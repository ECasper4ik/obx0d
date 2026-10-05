# netbypass

A small, config-driven **client-orchestrator** around the [sing-box](https://github.com/SagerNet/sing-box)
transport. It does **not** implement any protocol or cryptography itself — it
launches and supervises an external, well-reviewed transport binary, keeps the
connection healthy (auto-failover), prevents traffic leaks (kill-switch), and
can self-test the tunnel.

> **Legal note.** netbypass is a privacy / access tool. It connects only to
> servers **you** configure. Using it may be regulated by the laws of your
> jurisdiction; you are responsible for compliance. The authors accept no
> liability for misuse. Do not use it for unlawful activity.

---

## 1. What it is (and isn't)

- **Is:** a supervisor. You bring your own server(s); netbypass turns a simple
  `config.yaml` into a running tunnel, restarts/fails over when a server dies,
  blocks traffic if the tunnel drops, and checks for DNS/IPv6 leaks.
- **Isn't:** a VPN protocol, a crypto library, or a server. The actual
  encryption and transport are done by `sing-box` (a separate, audited binary).

Think of it as the control panel; sing-box is the engine.

---

## 2. Networking basics (so the config makes sense)

**IP address.** Every device on a network has an IP. IPv4 looks like
`203.0.113.10` (four bytes, 0–255 each). IPv6 looks like `2001:db8::7` (much
larger space). Your server has a public IP; your PC has a private one behind
your router.

**Subnet mask / CIDR.** A mask says which part of an IP is the *network* and
which is the *host*. `192.168.0.0/24` means "the first 24 bits are the network"
→ addresses `192.168.0.0`–`192.168.0.255`. `/32` is a single host. In the
config, `route_only` and the kill-switch use CIDR ranges like
`149.154.160.0/20` to mean "this whole block of Telegram addresses".

**Private ranges.** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` are
reserved for LANs. netbypass keeps these **off** the tunnel so your
printer/router/local devices keep working.

**NAT.** Your router rewrites your private IP to its single public IP for
outbound traffic (and back). This is why many homes share one public IP, and
why a server sees your router's address, not your PC's.

**Ports.** An IP gets you to a host; a port (0–65535) gets you to a *service*
on it. `443` = HTTPS, `53` = DNS, `51820` = typical WireGuard. The local proxy
listens on `127.0.0.1:2080` — that's where your apps send traffic.

**DNS.** Turns `discord.com` into an IP. If DNS goes out over the open network
while the rest is tunnelled, it *leaks* which sites you visit. netbypass tells
sing-box to resolve names **inside** the tunnel over DNS-over-HTTPS (DoH), and
`--check` verifies there's no leak.

**SNI / "подмена" (domain fronting-ish).** During a TLS handshake the client
normally announces the site it wants in cleartext (the *SNI* field). Transports
like **VLESS + Reality** present a handshake that looks like an ordinary visit
to a big, unblocked site (e.g. `www.microsoft.com`) — that's the `sni` /
`reality` block in the config. sing-box handles all of this; you just paste the
values your server gave you.

**SOCKS5 vs TUN.**
- *proxy mode* opens a local **SOCKS5/HTTP** proxy. You point an app (browser,
  Discord) at `127.0.0.1:2080`. Only apps you configure use it. **No admin
  needed** — recommended for Discord/Telegram.
- *tun mode* creates a virtual network interface and routes the **whole system**
  through it. Needs admin rights (and `wintun.dll` on Windows).

---

## 3. Project layout & how files connect

```
netbypass/
├─ bypass.py              # CLI entrypoint: parses args, prints disclaimer,
│                         #   runs either the self-test or the orchestrator.
├─ config.example.yaml    # Template. Copy to config.yaml and fill in servers.
├─ requirements.txt       # Python deps (PyYAML, requests, dnspython, rich, PySocks)
├─ build.ps1              # Builds a single bypass.exe with PyInstaller (Windows)
├─ README.md
└─ core/
   ├─ __init__.py         # package marker + version
   ├─ config.py           # load_config(): reads YAML -> validated AppConfig/Server
   ├─ singbox.py          # build_config(): AppConfig+Server -> sing-box JSON;
   │                      #   SingBoxProcess: launches/stops the sing-box binary
   ├─ health.py           # probe()/measure_rtt(): is the tunnel actually working?
   ├─ killswitch.py       # KillSwitch: Windows Firewall / nftables leak-blocker
   ├─ selfcheck.py        # run_checks(): DNS / IPv6 / exit-IP / geo / RTT tests
   ├─ orchestrator.py     # Orchestrator: ties it together, supervises, fails over
   └─ logutil.py          # logging setup (keeps server IPs out of INFO logs)
```

**Data flow when you run it:**

```
bypass.py
   └─ config.py        reads config.yaml  ──►  AppConfig + [Server, Server, ...]
   └─ orchestrator.py  picks a server
         └─ singbox.py   build_config(app, server)  ──►  temp sing-box JSON
         └─ singbox.py   SingBoxProcess.start()     ──►  runs sing-box.exe
         └─ health.py    probe(127.0.0.1:2080)      ──►  up? keep it : try next
         └─ killswitch.py enable()                   ──►  block leaks on drop
   (loop) orchestrator watches health; on failure → stop, fail over to next server
```

`--check` takes the same `AppConfig` and runs `selfcheck.run_checks()` instead
of starting a tunnel.

---

## 4. Install & run (Windows)

### A. Get sing-box (the engine)
1. Download `sing-box-*-windows-amd64.zip` from the
   [sing-box releases](https://github.com/SagerNet/sing-box/releases).
2. Unzip it, e.g. to `C:\Tools\sing-box\sing-box.exe`.

### B. Get netbypass running from Python
```powershell
cd netbypass
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy config.example.yaml config.yaml
notepad config.yaml        # set singbox_path and your server(s)
```

Run it (local proxy mode — no admin):
```powershell
python bypass.py --profile config.yaml --mode proxy
```
Then set your browser / Discord network proxy to **SOCKS5 `127.0.0.1:2080`**.

Self-test (run in a second window while the tunnel is up):
```powershell
python bypass.py --profile config.yaml --check
```

System-wide (all apps) — **run PowerShell as Administrator**:
```powershell
python bypass.py --profile config.yaml --mode tun
```

### C. Build a single .exe
```powershell
.\build.ps1
# → dist\bypass.exe
.\dist\bypass.exe --profile config.yaml --mode proxy
```
`sing-box.exe` stays a **separate** file (don't bundle it) — keep it where
`config.yaml`'s `singbox_path` points.

---

## 5. Linux / macOS

Same Python entrypoint works:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python bypass.py --profile config.yaml --mode proxy
```
Kill-switch uses `nftables` on Linux (needs root). macOS kill-switch is not
implemented (use proxy mode).

---

## 6. Pointing apps at the proxy

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5
  `127.0.0.1` port `2080`, check "Proxy DNS when using SOCKS v5".
- **Chrome/Discord (desktop):** they follow the **system** proxy. Either use
  `--mode tun`, or set Windows system proxy to `127.0.0.1:2080`, or launch with
  a `--proxy-server="socks5://127.0.0.1:2080"` flag.
- **Telegram:** Settings → Advanced → Connection type → Use custom proxy →
  SOCKS5 `127.0.0.1:2080`.

---

## 7. Troubleshooting

- `sing-box binary not found` → fix `client.singbox_path` in config.yaml.
- Self-test `tunnel: FAIL` → the tunnel isn't up or the port is wrong; start
  `--mode proxy` first, then run `--check` in another window.
- `kill-switch ... need admin/root?` → run the terminal as Administrator (Win)
  or with `sudo` (Linux), or set `killswitch: false`.
- Everything connects but a site is slow → try a different server in the list;
  `--check` shows the RTT so you can compare.

---

## 8. Releases (automated .exe build)

A GitHub Actions workflow (`.github/workflows/release.yml`) builds
`bypass.exe` on `windows-latest` with PyInstaller.

- **Tag push** → builds and publishes a **GitHub Release** with `bypass.exe`
  and a `bypass-windows-x64.zip` bundle (exe + example config + README):

  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

- **Manual run** (Actions tab → "Build and release bypass.exe" → Run workflow)
  → builds and uploads the `.exe` as a workflow **artifact** (no release).

`sing-box.exe` is never bundled — it stays a separate download.
