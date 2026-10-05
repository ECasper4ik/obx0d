"""Kill-switch: if the tunnel drops, don't let traffic fall back to the
open internet. This is a privacy-safety feature (leak prevention), identical
in spirit to the kill-switch in any commercial VPN client.

Windows: Windows Firewall (netsh advfirewall). We set the default outbound
action to Block and open explicit allow-holes for loopback, the LAN, the
sing-box process and the server endpoints. On teardown we remove the rules
and restore the previous default policy.

Linux: an nftables table that drops output except loopback / LAN / the
tunnel interface / the server endpoints.

Both require admin/root. Without it the kill-switch is skipped with a warning.
"""
from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger("netbypass.killswitch")

RULE_PREFIX = "netbypass-ks"
_LINUX_TABLE = "netbypass_ks"


@dataclass
class Endpoint:
    host: str
    port: int


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    log.debug("exec: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
def _win_get_outbound_policy() -> str:
    """Return current outbound default, e.g. 'AllowOutbound' (best effort)."""
    try:
        out = _run(["netsh", "advfirewall", "show", "allprofiles", "firewallpolicy"]).stdout
    except subprocess.CalledProcessError:
        return "AllowOutbound"
    for line in out.splitlines():
        if "," in line and "Outbound" in line:
            # line like: "BlockInbound,AllowOutbound"
            parts = line.strip().split(",")
            if len(parts) == 2:
                return parts[1].strip()
    return "AllowOutbound"


def _win_enable(endpoints: list[Endpoint], singbox_path: str) -> None:
    # Allow loopback + private LAN so you keep local/printer/router access.
    _run(["netsh", "advfirewall", "firewall", "add", "rule",
          f"name={RULE_PREFIX}-loopback", "dir=out", "action=allow",
          "remoteip=127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fe80::/10"])
    # Allow the sing-box process itself (it's what talks to the server).
    _run(["netsh", "advfirewall", "firewall", "add", "rule",
          f"name={RULE_PREFIX}-singbox", "dir=out", "action=allow",
          f"program={singbox_path}", "enable=yes"])
    # Allow each server endpoint explicitly (so the tunnel can be established).
    for i, ep in enumerate(endpoints):
        _run(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_PREFIX}-srv{i}", "dir=out", "action=allow",
              f"remoteip={ep.host}", f"remoteport={ep.port}", "protocol=TCP"])
        _run(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_PREFIX}-srvu{i}", "dir=out", "action=allow",
              f"remoteip={ep.host}", f"remoteport={ep.port}", "protocol=UDP"])
    # Flip default outbound to block: with default=block, only the allow
    # rules above get out. If the tunnel dies, everything else is dropped.
    _run(["netsh", "advfirewall", "set", "allprofiles",
          "firewallpolicy", "blockinbound,blockoutbound"])


def _win_disable(previous_outbound: str) -> None:
    for suffix in ("loopback", "singbox"):
        _run(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={RULE_PREFIX}-{suffix}"], check=False)
    # Delete numbered server rules (ignore misses).
    for i in range(64):
        for pfx in (f"{RULE_PREFIX}-srv{i}", f"{RULE_PREFIX}-srvu{i}"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={pfx}"],
                 check=False)
    restore = "allowoutbound" if "allow" in previous_outbound.lower() else "blockoutbound"
    _run(["netsh", "advfirewall", "set", "allprofiles",
          "firewallpolicy", f"blockinbound,{restore}"], check=False)


# --------------------------------------------------------------------------- #
# Linux
# --------------------------------------------------------------------------- #
def _linux_enable(endpoints: list[Endpoint]) -> None:
    rules = [
        f"add table inet {_LINUX_TABLE}",
        f"add chain inet {_LINUX_TABLE} out {{ type filter hook output priority 0 ; policy drop ; }}",
        f"add rule inet {_LINUX_TABLE} out oifname lo accept",
        f"add rule inet {_LINUX_TABLE} out meta oifname \"nbx-tun\" accept",
        f"add rule inet {_LINUX_TABLE} out ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept",
        f"add rule inet {_LINUX_TABLE} out ct state established,related accept",
    ]
    for ep in endpoints:
        rules.append(f"add rule inet {_LINUX_TABLE} out ip daddr {ep.host} tcp dport {ep.port} accept")
        rules.append(f"add rule inet {_LINUX_TABLE} out ip daddr {ep.host} udp dport {ep.port} accept")
    script = "\n".join(rules) + "\n"
    subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True,
                   capture_output=True)


def _linux_disable() -> None:
    _run(["nft", "delete", "table", "inet", _LINUX_TABLE], check=False)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
class KillSwitch:
    def __init__(self, endpoints: list[Endpoint], singbox_path: str):
        self.endpoints = endpoints
        self.singbox_path = singbox_path
        self.system = platform.system()
        self._active = False
        self._prev_win_policy = "AllowOutbound"

    def _has_tool(self) -> bool:
        if self.system == "Windows":
            return shutil.which("netsh") is not None
        if self.system == "Linux":
            return shutil.which("nft") is not None
        return False

    def enable(self) -> bool:
        if not self._has_tool():
            log.warning("kill-switch tool not available on %s; skipping", self.system)
            return False
        try:
            if self.system == "Windows":
                self._prev_win_policy = _win_get_outbound_policy()
                _win_enable(self.endpoints, self.singbox_path)
            elif self.system == "Linux":
                _linux_enable(self.endpoints)
            else:
                log.warning("kill-switch unsupported on %s", self.system)
                return False
        except subprocess.CalledProcessError as exc:
            log.error("kill-switch enable failed (need admin/root?): %s",
                      exc.stderr or exc)
            return False
        self._active = True
        log.info("kill-switch ON")
        return True

    def disable(self) -> None:
        if not self._active:
            return
        try:
            if self.system == "Windows":
                _win_disable(self._prev_win_policy)
            elif self.system == "Linux":
                _linux_disable()
        except subprocess.CalledProcessError as exc:
            log.error("kill-switch disable failed: %s", exc.stderr or exc)
        self._active = False
        log.info("kill-switch OFF")
