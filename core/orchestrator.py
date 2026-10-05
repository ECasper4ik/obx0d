"""Ties everything together: start a server, watch it, fail over on death,
and tear down cleanly (including the kill-switch)."""
from __future__ import annotations

import logging
import time

from .config import AppConfig
from .health import probe
from .killswitch import Endpoint, KillSwitch
from .singbox import SingBoxProcess

log = logging.getLogger("netbypass.orchestrator")


class Orchestrator:
    def __init__(self, app: AppConfig):
        self.app = app
        self.current: SingBoxProcess | None = None
        self.killswitch: KillSwitch | None = None
        if app.killswitch:
            endpoints = [Endpoint(s.server_host, s.server_port) for s in app.servers]
            self.killswitch = KillSwitch(endpoints, app.singbox_path)

    def _start_server_index(self, idx: int) -> bool:
        server = self.app.servers[idx]
        proc = SingBoxProcess(self.app, server)
        proc.start()
        # Give sing-box a moment to bind, then verify reachability.
        for _ in range(10):
            time.sleep(0.6)
            if not proc.is_alive():
                log.error("transport for '%s' exited early", server.name)
                proc.stop()
                return False
            if probe(self.app.local_proxy_url):
                self.current = proc
                log.info("connected via '%s'", server.name)
                return True
        log.warning("server '%s' did not pass health check", server.name)
        proc.stop()
        return False

    def connect(self) -> bool:
        """Try each server in order until one works."""
        if self.killswitch:
            self.killswitch.enable()
        for idx in range(len(self.app.servers)):
            if self._start_server_index(idx):
                return True
        log.error("no server could be reached")
        return False

    def run_forever(self, poll_interval: float = 5.0) -> None:
        """Supervise: if the active server dies or stops answering, fail over."""
        try:
            if not self.connect():
                return
            while True:
                time.sleep(poll_interval)
                alive = self.current is not None and self.current.is_alive()
                healthy = alive and probe(self.app.local_proxy_url)
                if not healthy:
                    log.warning("tunnel unhealthy — failing over "
                                "(kill-switch keeps traffic blocked meanwhile)")
                    if self.current:
                        self.current.stop()
                        self.current = None
                    if not self.connect():
                        log.error("failover exhausted all servers; retrying in 15s")
                        time.sleep(15)
        except KeyboardInterrupt:
            log.info("shutting down (Ctrl-C)")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        if self.current:
            self.current.stop()
            self.current = None
        if self.killswitch:
            self.killswitch.disable()
