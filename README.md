# FortiConnect

A simple desktop client for FortiGate VPNs: **SSL-VPN** and **IPsec**. Add your FortiGate's address and user name, press
the big button, and you are connected. Built like [RayConnect](https://github.com/amirerajabi/rayconnect) and
[Grabbit](https://github.com/amirerajabi/grabbit): Electron + React UI + a Node engine.

FortiConnect is not made by or affiliated with Fortinet. FortiGate and FortiClient are Fortinet's trademarks.

- **SSL-VPN** through [OpenConnect](https://www.infradead.org/openconnect/) 9 or newer (`--protocol=fortinet`) on
  Windows, macOS and Linux: realms, client certificates, FortiToken / e-mail / SMS codes, and gateways with their own
  certificate (FortiConnect shows its fingerprint and remembers it once you trust it).
- **IPsec:**
  - Windows: Windows' own VPN client, with IKEv2 + EAP or L2TP/IPsec + pre-shared key. Nothing to install.
  - macOS and Linux: strongSwan's `charon-cmd`, with IKEv1 + XAuth + pre-shared key (main or aggressive mode, with a
    peer ID: what a FortiGate dial-up tunnel for FortiClient uses) or IKEv2 + EAP.
- **Saved passwords stay on this computer**, encrypted with a key the OS keychain protects. Leave them unsaved and
  FortiConnect asks when connecting.
- **Reconnects** when the tunnel drops, and asks again if the gateway wants a new code.
- **Check gateway:** time to the FortiGate, its certificate and whether it looks like an SSL-VPN portal, before you connect.
- **forticonnect:// links** carry a profile (never its secrets) for colleagues: copy one, they press Ctrl+V.
- **Tray panel:** click the tray icon to connect or switch profiles without opening the window.
- **English or فارسی:** Persian turns the whole UI right to left (Settings → General → Language).
- Live traffic graph, the VPN program's log, light and dark themes, command palette (Ctrl+K).

## What it needs

| | SSL-VPN | IPsec |
| --- | --- | --- |
| Windows | `openconnect.exe` with `wintun.dll` (for example MSYS2: `pacman -S mingw-w64-ucrt-x86_64-openconnect`), and FortiConnect running **as administrator** (it offers to restart that way) | Nothing. The FortiGate tunnel must allow IKEv2 or L2TP (Windows has no IKEv1 + XAuth). |
| macOS | `brew install openconnect` | `brew install strongswan` |
| Linux | `sudo apt install openconnect` | `sudo apt install strongswan-charon` (or your distribution's `charon-cmd`) |

On macOS and Linux, creating the tunnel needs root: FortiConnect runs the VPN program through `sudo` and asks for your
computer password in its own window (kept in memory only, for reconnecting).

## Download

Get the latest version from [Releases](https://github.com/amirerajabi/forti-connect/releases/latest):
`FortiConnect-Setup-<version>.exe` for Windows, a DMG for macOS (Apple silicon) and an AppImage for Linux. FortiConnect
updates itself afterwards (Settings → Updates).

The builds are not code-signed yet. On Windows, SmartScreen may warn on first run: choose **More info → Run anyway**. On
macOS, right-click the app and choose **Open** the first time.

## Use

| | |
| --- | --- |
| Add a profile | **Add profile** (Ctrl+N). Paste the portal address (`https://vpn.example.com:10443/realm`) into Gateway to fill the port and realm. |
| Connect | The big power button, **Ctrl+Enter**, double-click a profile card, or the tray icon. |
| Codes and questions | A window asks for the FortiToken code, a password you did not save, or whether to trust a certificate. |
| Share a profile | ⋯ → **Copy link** on a profile card; the other person presses **Ctrl+V** in FortiConnect. |

## Development

```bash
npm run setup        # npm install in engine, ui, desktop
npm run dev          # engine on 7330 (token "dev", data in .dev-data/) + UI on http://localhost:5174
npm run dev:desktop  # Vite + Electron
npm run typecheck
npm test             # engine tests (a fake VPN program stands in for OpenConnect)
npm run check:i18n   # every UI string has a Persian translation
npm run build
npm run dist         # Windows installer into desktop/release/
```

To ship OpenConnect inside the Windows installer, put `openconnect.exe`, its DLLs, `wintun.dll` and
`vpnc-script-win.js` in `desktop/core/` before `npm run dist`.

See [AGENTS.md](AGENTS.md) for the layout and conventions, and [docs/STATUS.md](docs/STATUS.md) for what is verified.

## License

MIT. OpenConnect (LGPL-2.1) and strongSwan (GPL-2.0) are separate programs FortiConnect runs; they are not part of it.
