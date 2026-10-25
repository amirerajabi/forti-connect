# Status

Released: 0.3.0 (tag v0.3.0, 2026-10-25), at https://github.com/amirerajabi/forti-connect. Before it: 0.2.0, 0.1.1 and
0.1.0 (the first release), the same day. The release workflow builds the Windows installer, the macOS DMG / ZIP and the
Linux AppImage with their update metadata (for 0.1.0 and 0.1.1 the installer's SHA-512 matched `latest.yml`). The
update from 0.1.0 to 0.1.1 did install on the developer's machine, but for all users (see Known issues).

## In 0.3.0

- **SSL-VPN connected and worked for the user through the helper** (FortiConnect 0.2.0, their real gateway, a full
  login): the first real connection.
- **Traffic showed 0 B/s:** the Windows counter's PowerShell loop went to PowerShell on stdin, and PowerShell quits
  without running a multi-line script piped to it. Scripts now go as `-EncodedCommand` (Windows' IPsec setup scripts
  had the same problem and were likely silently failing). Checked against the live tunnel: samples every second.
  The tunnel also falls back to the adapter name FortiConnect chose when the system has not shown the VPN address yet.
- **OpenConnect ships inside the Windows installer** (`scripts/fetch-openconnect.mjs`, official v9.21 build, SHA-256
  pinned; checked in a local unpacked build: 18 files in `resources/core`, the engine picks that copy first).
- **Helper v2** copies that OpenConnect into `C:\Program Files\FortiConnect Helper\openconnect` (admin-only) and runs
  it first. Checked here: v1 → v2 update, the copy in place, a connection to the real gateway through it up to
  `Password:` (helper.log names the copy).
- **The first SSL-VPN connect installs (or updates) the helper itself**; a declined update falls back to the older helper.
- Windows' own tools are run by full path (`whoami` resolved to Git's and broke the helper install from a Git shell).
- Installing the helper from Settings is refused while connected (it restarts the helper and would end the tunnel; the
  developer's test update did end the user's connection once).

## In 0.2.0

- **The Windows VPN helper:** SSL-VPN on Windows no longer needs FortiConnect running as administrator. A small helper
  (`engine/src/core/backends/helper-script.ts`: PowerShell compiling C#, so nothing to install) runs as SYSTEM from
  `C:\Program Files\FortiConnect Helper` through a scheduled task started at boot, and starts OpenConnect when
  FortiConnect asks over a named pipe only the user's account can open. Installed and removed from Home or Settings →
  VPN programs with one UAC prompt. "Restart as administrator" stays as the alternative.
- Verified on the developer's machine: the helper installed through the app (UAC accepted), runs in session 0 as an
  account a normal user cannot see (SYSTEM), the folder is writable only by TrustedInstaller / SYSTEM / Administrators,
  `users.txt` holds the one account. FortiConnect, as a normal user, connected through it to the real gateway
  185.103.131.114:20443: the certificate question, then OpenConnect (run by the helper) connected directly and asked
  `Password:`; disconnecting there ended it cleanly. A full login through the helper has not been done.
- Tests run the real helper script in a test mode (this user, its own pipe, the fake OpenConnect) and connect through it.
- OpenConnect's "Server certificate verify failed" line, printed even when the pinned certificate is then accepted, is
  no longer shown as an error or kept as the reason for a later failure.
- Not done: uninstalling FortiConnect leaves the helper (remove it first from Settings → VPN programs); the client does
  not check that the pipe's server really is the helper (a process that took the pipe name first while the helper was
  not running could pose as it).

## In 0.1.1

- **SSL-VPN timed out after 60 s against a FortiGate with its own certificate** (reported with a real gateway that
  FortiClient connects to). OpenConnect asks "Enter 'yes' to accept" on stdout, which Windows buffers while stdout is a
  pipe, so the question never reached the engine. The engine now checks the certificate itself before starting
  OpenConnect, asks the user, and passes `--servercert`; a changed certificate is flagged. Checked with OpenConnect 9.21
  against that gateway up to its `Password:` prompt (not logged in), and with tests against a local self-signed server.
- OpenConnect now runs with `--no-proxy`: it was following `HTTPS_PROXY` (here RayConnect's local proxy on 10819), so
  the VPN would have broken whenever that app disconnected.

## Works (verified on Windows, 2026-10-25)

- `npm run typecheck`, `npm test` (30 engine tests), `npm run check:i18n` (237 strings) and `npm run build` pass.
- The engine against a fake OpenConnect (`engine/test/fixtures/fake-vpn.mjs`): saved password answered automatically,
  FortiToken code asked through the UI, password asked and remembered when not saved, an untrusted certificate put to
  the user and its pin saved, a refused password reported in words, disconnecting while a question waits, a dropped
  tunnel reconnecting (asking for the code again) and giving up after its attempts, secrets never in the API or the
  log, a VPN process left by a crash ended on the next start.
- Command lines and output reading for OpenConnect, charon-cmd and rasdial (unit tests); the TLS gateway check with
  certificate pin against a local self-signed server.
- The UI in the browser build: adding an SSL-VPN profile by pasting a portal address (fills port and realm), the Home
  page with the "OpenConnect not found" notice, Settings → VPN programs, the tray panel at `#tray`, Persian right to left.

## Known issues

- **An update installed while FortiConnect runs as administrator moves it to all users.** The NSIS installer, started
  elevated by the updater, installs per-machine (`C:\Program Files\FortiConnect`, shortcuts on the Public desktop) and
  removes the per-user copy; pins to the old path break. Seen on the developer's machine going from 0.1.0 to 0.1.1. A
  fix would be `perMachine: true` in `desktop/electron-builder.yml` (always all users; non-elevated updates then ask
  UAC). Left as is for now, at the user's choice. With the VPN helper (0.2.0) FortiConnect normally runs unelevated,
  so this only happens when someone still uses "Restart as administrator".

## Not verified yet

- **Any real FortiGate.** No gateway was available: SSL-VPN through a real OpenConnect, IPsec through Windows' VPN
  client (`Add-VpnConnection` + `rasdial`) and through charon-cmd have only been checked as command lines. Things to
  watch on the first real tests:
  - OpenConnect's exact prompt texts for FortiGate 2FA (the code question is matched by words like "token" / "code").
  - `rasdial` with IKEv2 + EAP credentials (works on most Windows builds; some need the credentials stored instead).
  - charon-cmd under `script` + `sudo` on macOS and Linux, and its prompts for the pre-shared key and XAuth password.
  - Traffic counters on each OS (Windows: .NET interface statistics; macOS: netstat; Linux: /sys). Linux IPsec has no
    adapter of its own, so it shows no traffic.
- The prompt dialog and the profile dialog's "Check gateway" against a live engine with a real backend (the engine side
  is tested; the dialogs were only typechecked and opened).
- The Electron app beyond a smoke run: the smoke run starts the engine, sets the tray to "Not connected" and captures
  the main window, but its tray-panel capture came out empty (not looked into). Restart as administrator, the
  safeStorage key, the installer and the updater were never run.
- macOS and Linux builds.

## Ideas

- Import FortiClient's exported configuration (`.conf` / XML) as profiles.
- SAML / single sign-on login for SSL-VPN (OpenConnect's `--external-browser`).
- Bundle a signed OpenConnect build for Windows in the release workflow.
