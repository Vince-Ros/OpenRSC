# OpenRSC

OpenRSC is an MIT-licensed, source-only Python remote control centre for Windows
desktops and servers. It provides a persistent command prompt and a responsive
file manager through a clean web panel. OpenRSC itself uses only the Python
standard library: there are no wheels, native extensions, Node packages, CDN
assets, or compiled OpenRSC components. The optional tunnel runtime is
Cloudflare's separately signed `cloudflared.exe`.

## Included

- Up to eight independent persistent `cmd.exe` tabs with streamed output,
  per-tab command history, rename/close controls, interrupt/reset actions, and
  keyboard switching (`Ctrl+Shift+T`, `Ctrl+Tab`, and `Ctrl+W`).
- A ChatGPT-inspired, distraction-free command workspace with a collapsible
  mobile sidebar, touch-friendly controls, safe-area support, and responsive
  layouts for phones, tablets, laptops, and ultrawide displays.
- Administrator status shown in the panel; commands inherit the Python
  process's Windows token.
- Proxy-friendly 8 MiB chunked uploads with progress, ranged downloads,
  directory ZIP downloads, text/image preview, drag-and-drop, rename, folders,
  recursive delete, and ZIP extraction with traversal protection.
- Responsive desktop/mobile interface with no external front-end dependencies.
- Salted PBKDF2 password authentication, signed/revocable sessions, CSRF and
  origin checks, login lockout, strict cookies, security headers, path
  confinement, and privacy-preserving audit events.
- A one-command launcher that installs prerequisites, requests UAC, downloads
  and verifies a project-local `cloudflared.exe`, authenticates Cloudflare in an
  isolated local profile, creates/reuses a named tunnel, provisions DNS, and
  starts both processes.

## Fast start on Windows

### Guided setup tool

For a first-time setup or a clean way to change hosting and recovery options,
double-click `setup-openrsc.cmd` or run:

```powershell
.\setup-openrsc.cmd
```

The dark setup window keeps the important choices in one place:

- host locally or through the existing Cloudflare named tunnel;
- choose the public hostname, tunnel name, loopback port, and file roots;
- add or remove OpenRSC from Windows sign-in startup;
- enable the supervisor that restarts the server after a crash and reconnects
  Cloudflare hosting after an internet outage;
- set terminal/session limits, change the panel password, save the setup, and
  start, stop, or health-check OpenRSC.

The same setup tool can be scripted without opening the window:

```powershell
.\setup-openrsc.cmd --status
.\setup-openrsc.cmd --apply --startup on --recovery on --tunnel on
.\setup-openrsc.cmd --configure-tunnel --hostname openrsc.example.com
.\setup-openrsc.cmd --start
.\setup-openrsc.cmd --stop
```

Run `setup-openrsc.cmd --help` for every field and toggle. Machine-specific
choices are stored in `config\setup.json`; authentication secrets remain in the
generated private OpenRSC and Cloudflare configuration files.

### Direct launcher

Open a terminal in this directory and run either entrypoint:

```bat
launch-openrsc.cmd
```

```powershell
python .\launcher.py
```

On the first run the launcher performs this sequence:

1. Detects Python 3.11+. The `.cmd` bootstrap installs Python 3.14 with `winget`
   if no suitable interpreter exists.
2. Requests Windows administrator elevation in a visible console so terminal
   commands inherit an administrator token and first-run prompts stay usable.
3. Detects the OpenRSC configuration. A fresh source copy prompts twice for a
   panel password without echoing or storing its plaintext, then writes the
   verifier only to the ignored private configuration directory.
4. Downloads `cloudflared.exe` from the latest official Cloudflare GitHub
   release into `cloudflare\bin`, verifies the SHA-256 published with that
   release, verifies its Cloudflare Authenticode signer, and records the release
   metadata.
5. Opens Cloudflare login in a browser. Select the Cloudflare domain/zone you
   want to use, then return to the launcher and choose the full public hostname
   (the default is `openrsc.<selected-domain>` when the zone lookup is
   available).
6. Creates or reuses `openrsc-<computer-name>`, creates the DNS route, writes a
   named-tunnel config, and launches OpenRSC on loopback with that tunnel.

Later launches detect the local `state.json`, tunnel credential, and generated
config, update the origin port when needed, and go directly to the already
connected domain without another Cloudflare login.

Stop the server-side process tree with:

```powershell
.\stop-openrsc.ps1
```

## Everything Cloudflare stays inside OpenRSC

The launcher never relies on or changes `%USERPROFILE%\.cloudflared`. Every
Cloudflare management process receives a `HOME` and `USERPROFILE` pointing at
the project-local isolated profile:

```text
cloudflare/
  bin/cloudflared.exe        verified external runtime
  bin/release.json           source URL, version, signer, SHA-256
  cert.pem                   Cloudflare account/zone authorization
  credentials/<UUID>.json    named-tunnel run credential
  config.yml                 generated ingress configuration
  state.json                 detected hostname/tunnel association
  profile/.cloudflared/      isolated browser-login home
```

Runtime files are ignored by Git. On Windows, `launcher.py` removes inherited
ACLs and grants access only to the current account, SYSTEM, and Administrators.
The certificate and credential JSON are secrets even though they live beside
the code.

## Launcher controls

Install or update only the local Cloudflare binary, without login or starting a
server:

```powershell
python .\launcher.py --install-only --no-elevate
python .\launcher.py --install-only --update-cloudflared --no-elevate
```

Preselect a hostname for an unattended setup (browser authorization is still
required the first time):

```powershell
python .\launcher.py --hostname openrsc.example.com
```

Select another Cloudflare zone and rebuild the local association:

```powershell
python .\launcher.py --reauth-cloudflare
```

Reconfigure the hostname while reusing the current project-local Cloudflare
authorization:

```powershell
python .\launcher.py --reconfigure-cloudflare --hostname panel.example.com
```

Other useful modes:

```powershell
python .\launcher.py --check-only
python .\launcher.py --no-tunnel --no-elevate
python .\launcher.py --port 9000
```

Use `--overwrite-dns` only when the selected hostname already has a DNS record
that should be replaced. Without the flag, an interactive run asks before
replacing it.

## Password and file roots

Rotate the panel password without placing it on the command line or in console
history:

```powershell
python .\scripts\configure_password.py
```

Changing it also rotates the session-signing secret and invalidates all browser
sessions. Configure narrower file roots when full-drive access is unnecessary:

```powershell
python .\scripts\configure_password.py --root 'C:\Users\Public' --root 'D:\Shared'
```

The private application configuration is `config\openrsc.json` and is ignored
by Git.

## Verify and test

```powershell
python .\scripts\verify_install.py
python -m unittest discover -s tests -v
```

The suite covers launcher validation and local-state detection, isolated
Cloudflare command environments, named-tunnel command construction, independent
multi-tab terminal lifecycle, password
verification, signed sessions, CSRF rejection, path escape rejection,
upload/download behavior, ZIP-slip rejection, the real system shell, and an
end-to-end HTTP login/files/terminal/logout flow.

## Project layout

```text
launcher.py              installer, Cloudflare setup, UAC, and main entrypoint
launch-openrsc.cmd       Python bootstrap for a machine without Python 3.11+
cloudflare/              generated, ignored tunnel runtime and secrets
openrsc/                 Python package
  auth.py                password, sessions, CSRF, login limiting
  files.py               confined filesystem and ZIP operations
  terminal.py            persistent system-shell engine
  server.py              hardened threaded HTTP API
  web/                    dependency-free responsive panel
scripts/                 configuration and verification tools
tests/                   standard-library unittest suite
start-openrsc.ps1        legacy quick/token tunnel launcher
stop-openrsc.ps1         verified PID-based process-tree stop
```

## Performance choices

The server uses a threaded HTTP core, 1 MiB transfer chunks, atomic upload
replacement, byte-range downloads, a bounded terminal ring buffer, lightweight
incremental polling, and locally cached static assets. It avoids framework and
front-end dependency startup costs.

## References and license

Cloudflare documents the locally managed sequence used here in
[Create a locally-managed tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/create-local-tunnel/)
and its certificate/credential roles in
[Tunnel permissions](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/tunnel-permissions/).

OpenRSC is MIT licensed. See `LICENSE`. `cloudflared.exe` remains a separate
Cloudflare distribution with its own licensing and release metadata.
