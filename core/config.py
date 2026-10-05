"""Load and validate the YAML profile.

The config describes WHICH servers you own and HOW the local client should
expose them (local proxy vs. system-wide tun). No servers are hard-coded;
everything lives in config.yaml.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_TYPES = {"shadowsocks", "vless", "vmess", "trojan", "hysteria2", "wireguard"}
SUPPORTED_MODES = {"proxy", "tun"}


class ConfigError(Exception):
    pass


@dataclass
class Server:
    name: str
    type: str
    raw: dict[str, Any]  # protocol-specific fields, passed to the transport builder

    @property
    def server_host(self) -> str:
        return str(self.raw.get("server", ""))

    @property
    def server_port(self) -> int:
        return int(self.raw.get("server_port", 0))


@dataclass
class AppConfig:
    mode: str                      # "proxy" | "tun"
    local_host: str
    local_port: int
    singbox_path: str
    dns: str                       # DoH/DoT/plain resolver used inside the tunnel
    servers: list[Server]
    killswitch: bool
    log_level: str
    log_file: str | None
    check_endpoints: dict[str, str]
    route_only: list[str] = field(default_factory=list)  # optional split: route only these

    @property
    def local_proxy_url(self) -> str:
        return f"socks5h://{self.local_host}:{self.local_port}"


def _require(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d:
        raise ConfigError(f"missing required key '{key}' in {where}")
    return d[key]


def load_config(path: str | Path) -> AppConfig:
    path = Path(path).expanduser()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    client = data.get("client", {})
    mode = str(client.get("mode", "proxy")).lower()
    if mode not in SUPPORTED_MODES:
        raise ConfigError(f"client.mode must be one of {SUPPORTED_MODES}, got '{mode}'")

    local = client.get("local", {})
    local_host = str(local.get("host", "127.0.0.1"))
    local_port = int(local.get("port", 2080))

    singbox_path = str(_require(client, "singbox_path", "client"))

    dns = str(client.get("dns", "https://1.1.1.1/dns-query"))

    servers_raw = data.get("servers") or []
    if not servers_raw:
        raise ConfigError("at least one server must be defined under 'servers'")

    servers: list[Server] = []
    for i, s in enumerate(servers_raw):
        where = f"servers[{i}]"
        name = str(_require(s, "name", where))
        stype = str(_require(s, "type", where)).lower()
        if stype not in SUPPORTED_TYPES:
            raise ConfigError(f"{where}: unsupported type '{stype}' (supported: {SUPPORTED_TYPES})")
        _require(s, "server", where)
        servers.append(Server(name=name, type=stype, raw=dict(s)))

    ks = bool(client.get("killswitch", False))

    logging_cfg = data.get("logging", {})
    log_level = str(logging_cfg.get("level", "INFO"))
    log_file = logging_cfg.get("file")
    log_file = str(log_file) if log_file else None

    check = data.get("check", {})
    check_endpoints = {
        "ip": str(check.get("ip_endpoint", "https://api.ipify.org?format=json")),
        "geo": str(check.get("geo_endpoint", "https://ipinfo.io/json")),
        "ipv6": str(check.get("ipv6_endpoint", "https://api6.ipify.org?format=json")),
        "dns_probe": str(check.get("dns_probe", "whoami.akamai.net")),
    }

    route_only = [str(x) for x in (data.get("route_only") or [])]
    # Validate any CIDc entries early so failures happen at load time.
    for item in route_only:
        if "/" in item and not _looks_like_domain(item):
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ConfigError(f"route_only entry '{item}' is not a valid CIDR: {exc}")

    return AppConfig(
        mode=mode,
        local_host=local_host,
        local_port=local_port,
        singbox_path=singbox_path,
        dns=dns,
        servers=servers,
        killswitch=ks,
        log_level=log_level,
        log_file=log_file,
        check_endpoints=check_endpoints,
        route_only=route_only,
    )


def _looks_like_domain(value: str) -> bool:
    head = value.split("/", 1)[0]
    return any(c.isalpha() for c in head)
