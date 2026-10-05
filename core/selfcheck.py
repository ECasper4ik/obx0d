"""Self-test (`--check`): verify the tunnel actually carries your traffic and
that nothing leaks around it.

Checks:
  * exit IP via the proxy vs. your real IP (direct). They MUST differ.
  * geolocation of the exit IP (sanity + RTT plausibility).
  * IPv6 leak: if an IPv6 request goes out directly and reveals your real
    address, that's a leak (many tunnels are v4-only).
  * DNS: whether lookups resolve through the tunnel or your ISP resolver.
  * RTT through the proxy.

WebRTC leaks are a BROWSER property (STUN reveals local/public IPs from JS),
not something a CLI can observe. We can't test it here; the README explains
how to disable it in the browser instead.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import requests

from .config import AppConfig
from .health import measure_rtt

log = logging.getLogger("netbypass.selfcheck")


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _get_json(url: str, proxy_url: str | None, timeout: float = 8.0) -> dict | None:
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    try:
        resp = requests.get(url, proxies=proxies, timeout=timeout)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return {"value": resp.text.strip()}
    except requests.RequestException as exc:
        log.debug("request to %s failed: %s", url, exc)
        return None


def _extract_ip(payload: dict | None) -> str | None:
    if not payload:
        return None
    for key in ("ip", "query", "value", "address"):
        if key in payload and payload[key]:
            return str(payload[key])
    return None


def run_checks(app: AppConfig) -> list[CheckResult]:
    results: list[CheckResult] = []
    proxy = app.local_proxy_url
    ep = app.check_endpoints

    # 1. Real IP (direct) vs exit IP (through tunnel)
    direct = _extract_ip(_get_json(ep["ip"], proxy_url=None))
    through = _extract_ip(_get_json(ep["ip"], proxy_url=proxy))

    if through is None:
        results.append(CheckResult("tunnel", False,
                                   "no response through proxy — is the tunnel up?"))
    elif direct and through == direct:
        results.append(CheckResult("tunnel", False,
                                   f"exit IP == real IP ({through}); traffic is NOT tunnelled"))
    else:
        results.append(CheckResult("tunnel", True,
                                   f"exit IP {through} differs from real IP — tunnelled"))

    # 2. Geolocation of exit
    geo = _get_json(ep["geo"], proxy_url=proxy)
    if geo:
        loc = f"{geo.get('country', '?')}/{geo.get('city', geo.get('region', '?'))}"
        org = geo.get("org", geo.get("asn", "?"))
        results.append(CheckResult("geo", True, f"exit geo: {loc}  org: {org}"))
    else:
        results.append(CheckResult("geo", False, "could not resolve exit geolocation"))

    # 3. IPv6 leak
    v6_direct = _extract_ip(_get_json(ep["ipv6"], proxy_url=None, timeout=5.0))
    if v6_direct and ":" in v6_direct:
        results.append(CheckResult("ipv6", False,
                                   f"IPv6 reachable directly ({v6_direct}); "
                                   f"disable IPv6 or route it through the tunnel"))
    else:
        results.append(CheckResult("ipv6", True, "no direct IPv6 exposure detected"))

    # 4. DNS path — resolve an echo domain through the tunnel.
    #    whoami.akamai.net returns the resolver's IP as its answer.
    try:
        import dns.resolver  # noqa: PLC0415

        answer = dns.resolver.resolve(ep["dns_probe"], "A", lifetime=6.0)
        resolver_ip = str(answer[0]) if len(answer) else "?"
        if direct and resolver_ip == direct:
            results.append(CheckResult("dns", False,
                                       f"DNS resolver {resolver_ip} == your real IP — DNS leak"))
        else:
            results.append(CheckResult("dns", True,
                                       f"DNS resolver seen as {resolver_ip}"))
    except Exception as exc:  # noqa: BLE001
        results.append(CheckResult("dns", False, f"DNS probe failed: {exc}"))

    # 5. RTT
    rtt = measure_rtt(proxy)
    if rtt is not None:
        ok = rtt < 1500
        note = "ok" if ok else "high latency for a nearby exit"
        results.append(CheckResult("rtt", ok, f"{rtt:.0f} ms ({note})"))
    else:
        results.append(CheckResult("rtt", False, "RTT measurement failed"))

    return results
