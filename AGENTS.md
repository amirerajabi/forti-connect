# FortiConnect — guide for coding agents

FortiConnect is a simple FortiGate VPN client (SSL-VPN and IPsec): Electron desktop app + React UI + a Node engine that
drives the VPN programs (OpenConnect, strongSwan's charon-cmd, Windows' own VPN client). Its structure, look and
conventions follow RayConnect (`C:\Users\AMIR\Desktop\v2ray`), which follows Grabbit and Rowlit.

Read [docs/STATUS.md](docs/STATUS.md) first: what works, what is unfinished.

## Layout

| Path | What |
| --- | --- |
| `engine/` | Node + TypeScript, only dependency `ws`. HTTP API under `/api` (bearer token), events on `/ws`. `src/core/Manager.ts` (profiles, connect/disconnect, questions to the user, reconnecting, crash repair, gateway checks, traffic, log), `profiles.ts` (validation, `forticonnect://` links), `secrets.ts` (AES-GCM store for passwords and pre-shared keys), `net.ts` (TLS gateway check, certificate pin), `traffic.ts` (adapter byte counters per OS), `system.ts` (elevation, finding programs, PowerShell). `src/core/backends/`: `process.ts` (a VPN program as a child process: prompts, progress, stop), `openconnect.ts` (SSL-VPN), `charon.ts` (IPsec on macOS / Linux), `ras.ts` (IPsec on Windows), `index.ts` (which backend, `createTunnel`). Tests: `engine/test/engine.test.ts` with `test/fixtures/fake-vpn.mjs` (asks what OpenConnect asks) and a self-signed `gateway.crt`. |
| `ui/` | React 18 + Vite + zustand + lucide. Layout: glass top bar, icon rail (`components/layout/Rail.tsx`) and one page at a time (`src/pages/`: Home, Profiles, Log, Settings). `components/Dialogs/ProfileDialog.tsx` adds and edits profiles; `PromptDialog.tsx` answers the backend's questions (code, password, certificate, computer password). The same app rendered with `#tray` is the tray panel (`components/Tray/TrayPanel.tsx`). `src/app/commands.ts` is the command registry (pages, palette, tray menu and shortcuts use it). Stores in `src/store/`. Theme tokens in `src/theme/tokens.css`. Text: `src/i18n.ts` + `src/i18n-fa.ts`. |
| `desktop/` | Electron main + preload. Starts the engine as a utility process (with the secrets key from `safeStorage`, `secret-key.ts`), the main window, the tray icon (follows the connection; left click opens the panel window from `tray-panel.ts`, right click the menu), restart as administrator (Windows), auto-updater. Packaging: `electron-builder.yml`; `desktop/core/` is shipped as `resources/core` when it holds an OpenConnect. Icons: `node build/make-icon.mjs`. |
| `shared/protocol.ts` | Wire types shared by engine, UI and desktop (types only). |
| `scripts/run.mjs` | Dev launchers (`browser`, `desktop-dev`, `desktop`). |
| `scripts/check-i18n.mjs` | `npm run check:i18n`: every UI string has a Persian translation (CI runs it). |
| `.github/workflows/` | `ci.yml` (typecheck, tests, i18n, UI build), `release.yml` (tag `v*` → installers → GitHub Release). |

Public repo (to be created): https://github.com/amirerajabi/forti-connect (MIT). Releases there are what installed
copies update from.

## Commands

```bash
npm run setup / dev / dev:desktop / typecheck / test / check:i18n / build / dist
```

A change is done when `npm run typecheck`, `npm test`, `npm run check:i18n` and `npm run build` pass. Check UI changes
in the running app (`npm run dev`, then http://localhost:5174; the tray panel at http://localhost:5174/#tray), in
English and in Persian, not only by typechecking.

Electron smoke run with a throwaway profile (PowerShell): set `FORTICONNECT_USER_DATA=<scratch>`,
`FORTICONNECT_SMOKE_SHOT=<main.png>` and optionally `FORTICONNECT_SMOKE_TRAY_SHOT=<tray.png>`, then run
`desktop\node_modules\electron\dist\electron.exe desktop`. It captures, prints `tray: …` / `smoke: …` lines and quits.

## Rules

- [.claude/rules/release.md](.claude/rules/release.md): versions, tags, release assets, the auto-updater contract. The
  step-by-step release guide is `.claude/skills/release/SKILL.md`.

- Grabbit's code rules apply: strict TypeScript, comments say why, no hex colours outside `tokens.css`, every user
  action is a command, wire types only in `shared/protocol.ts`, no new dependencies without asking.
- **The machine's network is not a test bench.** Tests run a fake VPN program and a local TLS server; never start a real
  tunnel, create a Windows VPN entry or change routes from a test or a dev run unless the user asked for it.
- **Secrets never leave the engine.** The API says `hasPassword` / `hasPsk`, never the value; the log is scrubbed of
  them (`ProcessTunnel.scrub`); Windows' VPN entry exists only while connected so the pre-shared key does not stay in
  Windows. Values for PowerShell go through environment variables, never into the script text.
- **A tunnel nobody controls must not survive.** The running VPN program (pid and names) or Windows VPN entry is kept
  in `runtime.json` and ended on the next start; the pid is only killed if its process name still matches.
- Disconnect also cancels a question that is waiting and a connect in progress (it stops the tunnel first, then queues
  the cleanup); keep that, or a waiting prompt deadlocks the connect / disconnect queue.
- Every engine behaviour change gets a test.
- **Two languages.** English is the default; Persian turns the UI right-to-left. Write UI text in English through
  `t('…')` (or `useT()` in components) and add its Persian to `ui/src/i18n-fa.ts`. In CSS use logical properties
  (`margin-inline-start`, `inset-inline-end`, `text-align: start`), never left/right, except where the OS dictates
  the side (the title bar). Numbers with units get `unicode-bidi: plaintext` (`.tabular`), or "3 ms" reads "ms 3".
  Engine messages and log lines stay English.
