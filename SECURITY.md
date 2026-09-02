# OpenRSC security model

OpenRSC exposes powerful host functions after authentication. Its security
boundary is the web login, signed session, loopback listener, protected local
runtime files, and the Cloudflare tunnel layer in front of it.

## Application defaults

- The HTTP origin binds only to `127.0.0.1`.
- The local password is represented by a random 192-bit salt and a
  PBKDF2-HMAC-SHA256 verifier with 650,000 iterations.
- Session IDs and the signing key come from the operating-system CSPRNG.
- Sessions are signed, server-revocable, user-agent bound, and expire after
  eight hours.
- Browser state uses an HttpOnly, SameSite=Strict cookie. The cookie becomes
  `Secure` and receives the `__Host-` prefix when Cloudflare supplies a trusted
  HTTPS forwarding header from loopback.
- Every modifying API call requires both a session-bound CSRF value and a
  same-origin request.
- Authentication failures are rate limited and temporarily locked.
- Paths are canonicalized and confined to configured roots. ZIP extraction
  rejects traversal paths and symbolic links and enforces count/size limits.
- Large uploads use authenticated, session-owned, sequential chunks with
  unpredictable IDs, strict offsets, bounded pending state, and atomic finish.
- Security headers include CSP, frame denial, MIME sniffing denial, a strict
  referrer policy, and HSTS for HTTPS requests.
- Terminal audit events contain command length and SHA-256 only, not command
  text.

## Project-local Cloudflare boundary

- `cloudflared.exe` is downloaded only from the official Cloudflare GitHub
  release URL. The launcher checks the release-published SHA-256 and requires a
  valid Authenticode signature whose subject identifies Cloudflare.
- Cloudflare authentication receives an isolated project-local `HOME`,
  `USERPROFILE`, and `XDG_CONFIG_HOME`. The normal user `.cloudflared` directory
  is neither used nor modified.
- The zone certificate, tunnel credential, generated config, release metadata,
  and connection state all remain under `cloudflare\` in the OpenRSC directory.
- On Windows, private configuration, runtime data, and Cloudflare state have
  inheritance removed and are limited to the current account, SYSTEM, and the
  built-in Administrators group. Descendants inherit that protected ACL.
- The named tunnel points only to `http://127.0.0.1:<port>` and has a terminal
  `http_status:404` ingress rule.
- Once credentials and config exist, running the tunnel does not require
  Cloudflare's account certificate. That certificate remains available locally
  only so the launcher can inspect, reconfigure, or repair the named tunnel.

Do not commit or publish `config\openrsc.json`, `cloudflare\cert.pem`,
`cloudflare\credentials\*.json`, session cookies, or audit data. If any is
copied or exposed, rotate the panel password/signing key and replace the
affected Cloudflare authorization or tunnel.

## Operational notes

- Commands run with exactly the Windows token held by the Python process. The
  primary launcher asks Windows for administrator elevation by default.
- A configured drive root deliberately gives an authenticated user access to
  that drive. Narrow `files.roots` when full-drive access is unnecessary.
- File deletion is permanent and requires an explicit browser confirmation.
- Review `data\logs\audit.jsonl` and `data\logs\openrsc.log` regularly.
- Stop the process before replacing code, tunnel credentials, or configuration.
- A Cloudflare Access self-hosted application can be placed in front of the
  public hostname when an additional identity layer is wanted; the OpenRSC
  password screen remains active behind it.

## Reporting

Open an issue containing a minimal reproduction and affected version. Exclude
passwords, origin certificates, tunnel credentials/tokens, session cookies,
private hostnames, and private configuration contents.
