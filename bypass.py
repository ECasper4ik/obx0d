#!/usr/bin/env python3
"""netbypass — a small config-driven client-orchestrator around sing-box.

It does not implement any protocol or crypto itself; it launches and
supervises an external transport binary, protects against traffic leaks
(kill-switch), and can self-test the connection.

Usage:
    python bypass.py --profile config.yaml --mode proxy
    python bypass.py --profile config.yaml --check
    python bypass.py --profile config.yaml --mode tun       (needs admin)

See README.md for the full picture and legal note.
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table

from core.config import ConfigError, load_config
from core.logutil import setup_logging
from core.orchestrator import Orchestrator
from core.selfcheck import run_checks

console = Console()

DISCLAIMER = (
    "netbypass is a privacy / access tool. It connects only to servers YOU "
    "configure. Using it may be regulated by the laws of your jurisdiction; "
    "you are responsible for compliance. The authors accept no liability for "
    "misuse. Do not use it for unlawful activity."
)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="bypass", description="netbypass client-orchestrator")
    p.add_argument("--profile", "-p", help="path to config.yaml")
    p.add_argument("--mode", "-m", choices=["proxy", "tun"],
                   help="override client.mode from the config")
    p.add_argument("--check", action="store_true",
                   help="run the leak/latency self-test and exit")
    p.add_argument("--version", action="store_true", help="print version and exit")
    return p.parse_args(argv)


def _print_check(results) -> int:
    table = Table(title="netbypass self-test")
    table.add_column("check", style="bold")
    table.add_column("status")
    table.add_column("detail")
    worst = 0
    for r in results:
        status = "[green]PASS[/green]" if r.ok else "[red]FAIL[/red]"
        if not r.ok:
            worst = 1
        table.add_row(r.name, status, r.detail)
    console.print(table)
    return worst


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = _parse_args(argv)

    if args.version:
        from core import __version__
        console.print(f"netbypass {__version__}")
        return 0

    if not args.profile:
        console.print("[red]error:[/red] --profile/-p is required (path to config.yaml)")
        return 2

    console.print(f"[dim]{DISCLAIMER}[/dim]\n")

    try:
        app = load_config(args.profile)
    except ConfigError as exc:
        console.print(f"[red]config error:[/red] {exc}")
        return 2

    if args.mode:
        app.mode = args.mode

    setup_logging(app.log_level, app.log_file)

    if args.check:
        console.print("[dim]Running self-test — make sure the tunnel is already "
                      "running in another window.[/dim]")
        results = run_checks(app)
        return _print_check(results)

    orch = Orchestrator(app)
    orch.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
