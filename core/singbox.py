"""Build a sing-box JSON config from a profile and supervise the process.

We translate the user's YAML server definition into a sing-box outbound,
pick an inbound (local mixed proxy, or a system tun), and launch the
sing-box binary as a subprocess. sing-box does all the real networking and
crypto; this module is only glue + supervision.

sing-box config reference: https://sing-box.sagernet.org/configuration/
"""
from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .config import AppConfig, Server

log = logging.getLogger("netbypass.singbox")

OUTBOUND_TAG = "proxy"


def _dns_block(app: AppConfig) -> dict[str, Any]:
    # Resolve names through the tunnel (DoH by default) to avoid DNS leaks.
    return {
        "servers": [
            {"tag": "secure", "address": app.dns, "detour": OUTBOUND_TAG},
            {"tag": "local", "address": "local", "detour": "direct"},
        ],
        "rules": [{"outbound": "any", "server": "secure"}],
        "strategy": "prefer_ipv4",
    }


def _inbound(app: AppConfig) -> dict[str, Any]:
    if app.mode == "tun":
        # System-wide. Needs admin/root. Uses wintun on Windows automatically.
        return {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "nbx-tun",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
            "sniff": True,
        }
    # Default: userspace local proxy (SOCKS5 + HTTP on the same port).
    return {
        "type": "mixed",
        "tag": "mixed-in",
        "listen": app.local_host,
        "listen_port": app.local_port,
        "sniff": True,
        "set_system_proxy": False,
    }


def _tls_block(s: dict[str, Any]) -> dict[str, Any] | None:
    tls = s.get("tls")
    if not tls:
        return None
    out: dict[str, Any] = {"enabled": True}
    if "sni" in tls:
        out["server_name"] = tls["sni"]
    if tls.get("insecure"):
        out["insecure"] = True
    if "alpn" in tls:
        out["alpn"] = tls["alpn"]
    reality = tls.get("reality")
    if reality:
        out["reality"] = {
            "enabled": True,
            "public_key": reality["public_key"],
            "short_id": reality.get("short_id", ""),
        }
        # Reality requires uTLS fingerprint.
        out["utls"] = {"enabled": True, "fingerprint": tls.get("fingerprint", "chrome")}
    elif "fingerprint" in tls:
        out["utls"] = {"enabled": True, "fingerprint": tls["fingerprint"]}
    return out


def build_outbound(server: Server) -> dict[str, Any]:
    """Map a YAML server definition to a sing-box outbound dict."""
    s = server.raw
    base = {"tag": OUTBOUND_TAG, "server": s["server"], "server_port": int(s["server_port"])}

    if server.type == "shadowsocks":
        return {
            "type": "shadowsocks",
            **base,
            "method": s["method"],
            "password": s["password"],
        }

    if server.type == "trojan":
        out = {"type": "trojan", **base, "password": s["password"]}
        tls = _tls_block(s)
        if tls:
            out["tls"] = tls
        return out

    if server.type == "vmess":
        out = {
            "type": "vmess",
            **base,
            "uuid": s["uuid"],
            "security": s.get("security", "auto"),
            "alter_id": int(s.get("alter_id", 0)),
        }
        tls = _tls_block(s)
        if tls:
            out["tls"] = tls
        return out

    if server.type == "vless":
        out = {
            "type": "vless",
            **base,
            "uuid": s["uuid"],
            "flow": s.get("flow", ""),
        }
        tls = _tls_block(s)
        if tls:
            out["tls"] = tls
        return out

    if server.type == "hysteria2":
        out = {
            "type": "hysteria2",
            **base,
            "password": s["password"],
        }
        tls = _tls_block(s) or {"enabled": True}
        out["tls"] = tls
        return out

    if server.type == "wireguard":
        return {
            "type": "wireguard",
            **base,
            "private_key": s["private_key"],
            "peer_public_key": s["peer_public_key"],
            "local_address": s["local_address"],  # list, e.g. ["10.0.0.2/32"]
            "pre_shared_key": s.get("pre_shared_key", ""),
        }

    raise ValueError(f"unsupported server type: {server.type}")


def _route_block(app: AppConfig) -> dict[str, Any]:
    rules: list[dict[str, Any]] = [
        {"action": "sniff"},
        # Keep private/LAN traffic off the tunnel.
        {"ip_is_private": True, "outbound": "direct"},
    ]
    if app.route_only:
        domains = [x for x in app.route_only if any(c.isalpha() for c in x.split("/")[0])]
        cidrs = [x for x in app.route_only if x not in domains]
        matcher: dict[str, Any] = {}
        if domains:
            matcher["domain_suffix"] = domains
        if cidrs:
            matcher["ip_cidr"] = cidrs
        matcher["outbound"] = OUTBOUND_TAG
        rules.append(matcher)
        final = "direct"  # split-tunnel: everything else goes direct
    else:
        final = OUTBOUND_TAG  # full-tunnel: everything via proxy
    return {"rules": rules, "final": final, "auto_detect_interface": True}


def build_config(app: AppConfig, server: Server) -> dict[str, Any]:
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": _dns_block(app),
        "inbounds": [_inbound(app)],
        "outbounds": [
            build_outbound(server),
            {"type": "direct", "tag": "direct"},
        ],
        "route": _route_block(app),
    }


class SingBoxProcess:
    """Supervises one sing-box invocation for a given server."""

    def __init__(self, app: AppConfig, server: Server):
        self.app = app
        self.server = server
        self._proc: subprocess.Popen | None = None
        self._cfg_path: Path | None = None

    def start(self) -> None:
        binary = Path(self.app.singbox_path).expanduser()
        if not binary.exists():
            raise FileNotFoundError(
                f"sing-box binary not found at '{binary}'. "
                f"Download it from https://github.com/SagerNet/sing-box/releases "
                f"and set client.singbox_path in config.yaml."
            )

        config = build_config(self.app, self.server)
        fd = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="nbx-", delete=False, encoding="utf-8"
        )
        json.dump(config, fd, indent=2)
        fd.close()
        self._cfg_path = Path(fd.name)

        log.info("starting transport for server '%s'", self.server.name)
        self._proc = subprocess.Popen(
            [str(binary), "run", "-c", str(self._cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._cfg_path and self._cfg_path.exists():
            try:
                self._cfg_path.unlink()
            except OSError:
                pass
        self._cfg_path = None
