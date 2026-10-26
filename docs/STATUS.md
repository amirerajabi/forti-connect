# Status

Released: 0.5.1 (tag v0.5.1, 2026-10-26), at https://github.com/amirerajabi/forti-connect. Before it: 0.5.0, 0.4.0, 0.3.2 and 0.3.1 (the same day), then 0.3.0, 0.2.0, 0.1.1 and
0.1.0 (the first release), all on 2026-10-25. The release workflow builds the Windows installer, the macOS DMG / ZIP and the
Linux AppImage with their update metadata (for 0.1.0 and 0.1.1 the installer's SHA-512 matched `latest.yml`). The
update from 0.1.0 to 0.1.1 did install on the developer's machine, but for all users (see Known issues).

## In 0.5.1: the IPsec adapter set up by the helper itself

The user's test of 0.5.0 (2026-10-26): it connected, but nothing behind the VPN was reachable, and reconnecting hung at
"Setting up the VPN adapter". Seen on their PC while connected: the adapter had only 169.254.x (netsh "set address"
failed with "The object already exists": the last connection's address and default route were still there), no route
into the tunnel (Ethernet and the tunnel both had metric 1; `Find-NetRoute 192.168.57.16` chose Ethernet), 0 bytes
received on the adapter. vpnc-script also took up to a minute on a reused adapter.

- **Helper v5** no longer uses vpnc-script for IPsec. It keeps its own adapter, "FortiConnect IPsec", for as long as it
  runs (no delete and re-create between connections), and sets it up with single netsh commands built from checked
  values: the address (`set address` replaces leftovers), MTU, interface metric 1, DNS, a /32 route to the gateway
  through the route Windows uses for it now (GetBestRoute), and the tunnel's networks as on-link routes; "all
  traffic" is 0.0.0.0/1 + 128.0.0.0/1, which beat any default route. Disconnect deletes exactly those.
- The engine asks for INTERNAL_IP4_SUBNET in mode config and routes only those networks when the FortiGate names them
  (FortiClient does the same); a /0 there means all traffic.
- 15 s after connecting the log says how many packets went out and came back, and warns when none came back.
- **Checked on the user's PC** with helper v5 installed and a harmless setup (10.255.255.0/24, gateway 192.0.2.1): up in
  ~3 s, address and MTU set, gateway route via Ethernet, 10.255.255.9 routed into the adapter and 8.8.8.8 not, and all
  of it removed again on disconnect. **Not checked:** traffic through the real gateway, and the all-traffic halves (that
  test would have cut the PC's own traffic).

## In 0.5.0: IPsec IKEv2 carries traffic (step 2 of 3)

- **The user's real login with 0.4.0 worked** (2026-10-26): PSK proof, EAP-MSCHAPv2, final AUTH; VPN address
  192.168.4.11, DNS 217.218.127.127 / 217.218.155.155, all traffic (TSr 0.0.0.0-255.255.255.255), ESP AES-256 SHA256.
- `ikev2/esp.ts`: ESP tunnel mode in UDP (AES-CBC + HMAC-SHA2, 64-packet replay window), on the IKE socket so it follows
  the same NAT mapping. The IKE session now answers the gateway's INFORMATIONAL requests (liveness, DELETE; a
  CREATE_CHILD_SA is refused with NO_ADDITIONAL_SAS until rekeying exists), sends NAT keepalives every 20 s, and checks
  the gateway itself after 30 s of silence.
- **Helper v4** has a `tun` operation: it opens or creates the "FortiConnect" Wintun adapter from its own copy of
  `wintun.dll`, runs OpenConnect's `vpnc-script-win.js` (connect / disconnect) with the address, DNS, gateway route,
  MTU 1400 and split networks, then passes IP packets over the pipe as length-prefixed frames. Every field is checked in
  C#. The C# is installed without comment lines (the install script travels in a command line, near Windows' 32767
  limit; a test checks the size).
- Windows IKEv2 profiles need the helper (installed or updated on connect, one UAC prompt).
- Tested: ESP round trips, replays, tampering; a whole connection against the fake gateway with a stand-in adapter
  (packets both ways, IPv6 held back, the gateway's liveness check answered, its DELETE noticed); the real helper script
  in `tun-echo` test mode (framing both ways, a bad address refused). **Not tested:** the real Wintun adapter and
  vpnc-script from the helper, and any traffic through the real gateway; rekeying (child SA after 43200 s) is step 3.

## In 0.4.0: IPsec IKEv2 on Windows with FortiConnect's own engine (step 1 of 3)

The user's second FortiGate (178.252.144.146, "PDN") is an IPsec dial-up tunnel set up for FortiClient: IKEv2, the
gateway proves itself with a pre-shared key, the user logs in with EAP (user name + password), mode config hands out
the address, local ID `dialup1`; phase 1 AES256 with SHA384/SHA256, DH 20/21; phase 2 AES256 SHA256/SHA384, PFS DH 20.
Windows' own client cannot do PSK + EAP (it wants a gateway certificate), and strongSwan's Windows port cannot take a
virtual IP (`kernel_iph_net.c`: `add_ip` returns NOT_SUPPORTED; `tun_device.c` has no Windows TUN). So FortiConnect
gets its own IKEv2 initiator (`engine/src/core/ikev2/`):

- **Step 1, login (done):** IKE_SA_INIT, IKE_AUTH with the gateway's PSK proof, EAP-MSCHAPv2 (MD4 and DES written out,
  since OpenSSL 3 dropped them; RFC 2759 / 3079 vectors pass), the final AUTH with the MSK, mode config, ESP keys. It
  always floats to UDP 4500 and claims a NAT (source hash of 0.0.0.0) so ESP will travel in UDP. Tests run it against a
  fake gateway written from the RFCs. Against the real gateway, with a dummy key and no password: it accepted AES256 /
  SHA384 / DH 20, answered on 4500, took `dialup1` as a key ID and sent its PSK proof (which our dummy key did not match,
  as expected). A full login with the real key and password has not been done.
- In the app, a Windows IPsec profile with IKEv2 now uses this engine (L2TP still uses Windows' client). It logs in,
  reports "the login worked (VPN address …)", signs out (DELETE) and stops, since there is no data path yet. The profile
  dialog now asks for the pre-shared key and local ID for IKEv2 too.
- **Step 2, traffic (next):** ESP (AES-256-CBC + HMAC) in UDP 4500 between the gateway and the VPN helper's Wintun
  adapter, the VPN address and routes (from TSr / INTERNAL_IP4_SUBNET) and DNS on the adapter.
- **Step 3:** dead peer detection, answering the gateway's INFORMATIONAL requests, rekeying (CREATE_CHILD_SA with PFS
  DH 20; IKE SA life 86400 s, child 43200 s), reconnecting.

## In 0.3.2

The user's drop test with 0.3.1 against their real FortiGate (2026-10-26, log in the conversation):

- **Worked:** the lost gateway was noticed at once ("OpenConnect lost the gateway … logging in again"), FortiConnect
  waited for the network ("Waiting for the network" → "answers again" 10 s later) and logged in by itself. A normal
  Disconnect now ends OpenConnect with Ctrl+C (helper.log: `exited 0`, "Logout successful") and the next connect works
  on the first try.
- **Still failed once:** when the drop happens while the network is down, OpenConnect's logout cannot reach the gateway,
  so the helper kills it after 8 s (helper.log: "did not end after Ctrl+C, killing it") and the next connect hits the
  half-removed adapter. Now: "Set up tun device failed" / "Could not open|create Wintun adapter" right after connecting
  is tried again after 1 s (at most twice per connect, also with reconnecting off), without using up a reconnect
  attempt. Tested with the fake VPN only.
- The engine test for that retry failed once in the first full run ("no prompt") and passed in 4 full runs and 8 runs of
  the reconnect tests after; not explained. The test now prints the engine log if it fails again.

## In 0.3.1

From the user's log of a network drop against their real FortiGate (2026-10-26):

- **The FortiGate does not let a session resume** ("Server reports that reconnect-after-drop is not allowed"), yet
  OpenConnect kept trying for up to 5 minutes after losing it, with the tunnel dead. When the gateway says so and
  OpenConnect then reports it lost the gateway ("Failed to reconnect to host" / "remaining timeout"), the engine now ends
  OpenConnect and logs in again itself. On a gateway that allows resuming, OpenConnect is left to resume (that keeps the
  adapter and so the connections through it).
- **Reconnecting waits for the network:** before each attempt the engine checks that the SSL-VPN gateway answers (TCP);
  while it does not, it looks again every 3 s without using up one of the 5 attempts, and Home says "Waiting for the
  network to come back…". IPsec is tried straight away as before (its gateway answers on UDP).
- **Every connect after a disconnect failed once** ("Could not open Wintun adapter 'FortiConnect': Element not found",
  then a second login 3 s later, sometimes with another VPN address). The helper killed OpenConnect, which left its
  Wintun adapter half-removed (and skipped the logout and the script's route cleanup). **Helper v3** ends OpenConnect
  with Ctrl+C (attaching to its console) and kills it only if it has not ended 8 s later; it also clears an inherited
  "ignore Ctrl+C" flag at start, without which OpenConnect never heard it. Checked with the helper test (the fake VPN
  logs out on Ctrl+C) — **not yet against the real OpenConnect / gateway**. OpenConnect run directly (FortiConnect
  elevated, or macOS / Linux) is still ended as before.
- Not solvable on this side: since the gateway refuses to resume, a real drop always means a new login, a new adapter,
  and so broken TCP connections through the old one (a browser session to a server behind the VPN has to be reopened).
  The gateway usually gives the same VPN address to a quick new login.

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

- `npm run typecheck`, `npm test` (43 engine tests), `npm run check:i18n` (256 strings) and `npm run build` pass.
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
