# Status

Released: 0.1.0 (tag v0.1.0, 2026-10-25), the first release, at https://github.com/amirerajabi/forti-connect. The release
workflow built the Windows installer, the macOS DMG / ZIP and the Linux AppImage with their update metadata; the
installer's SHA-512 matches `latest.yml`. No installed copy has updated from it yet (there is nothing older).

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
