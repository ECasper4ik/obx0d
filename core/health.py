"""Health probing through the local proxy, used to drive failover."""
from __future__ import annotations

import logging
import time

import requests

log = logging.getLogger("netbypass.health")


def probe(proxy_url: str, test_url: str = "https://www.gstatic.com/generate_204",
          timeout: float = 6.0) -> bool:
    """Return True if a request succeeds through the proxy.

    gstatic's generate_204 returns an empty 204 and is a cheap reachability
    check. Any configured URL works.
    """
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        resp = requests.get(test_url, proxies=proxies, timeout=timeout)
        return resp.status_code in (200, 204)
    except requests.RequestException as exc:
        log.debug("probe failed: %s", exc)
        return False


def measure_rtt(proxy_url: str, test_url: str = "https://www.gstatic.com/generate_204",
                timeout: float = 6.0) -> float | None:
    """Return round-trip time in milliseconds through the proxy, or None."""
    proxies = {"http": proxy_url, "https": proxy_url}
    start = time.perf_counter()
    try:
        requests.get(test_url, proxies=proxies, timeout=timeout)
    except requests.RequestException:
        return None
    return (time.perf_counter() - start) * 1000.0
