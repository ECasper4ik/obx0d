"""netbypass core package.

A small, config-driven orchestrator around an external transport binary
(sing-box). It does NOT implement any crypto or protocol itself — it only
launches, supervises and health-checks the transport, and protects the
host against traffic leaks (kill-switch, self-test).
"""

__version__ = "0.1.0"
