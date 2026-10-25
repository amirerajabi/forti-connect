// FortiConnect desktop: starts the engine sidecar, opens the window, and owns the native bits (tray with Connect /
// Disconnect, notifications, the file picker for the VPN programs, launch at login, restarting as administrator).
import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, nativeImage, nativeTheme, Notification, Tray } from 'electron';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { CH, type FilePurpose, type Preferences, type TrayState } from '../shared/channels';
import { startEngine, stopEngine, type EngineInfo } from './engine-process';
import { badgePath, dockIconPath, iconPath, trayIconPath, type BadgeState } from './paths';
import { TrayPanel } from './tray-panel';
import { Updater } from './updater';
import { createMainWindow, DARK, LIGHT, titleBarKind } from './window';

const devUrl = process.env.FORTICONNECT_DEV_URL;
// Separate profile (tests, portable use): settings, profiles and window state all live under it.
if (process.env.FORTICONNECT_USER_DATA) app.setPath('userData', process.env.FORTICONNECT_USER_DATA);
let win: BrowserWindow | null = null;
let tray: Tray | null = null;
let engine: EngineInfo | null = null;
let quitting = false;
let prefs: Preferences = { minimizeToTray: true, autoUpdate: true, launchAtLogin: false, language: 'en' };
let trayState: TrayState = { status: 'disconnected', profile: '' };
let updater: Updater | null = null;
let lastTrayTip = '';
let trayMenu: Menu | null = null;
let panel: TrayPanel | null = null;
let loginItemSynced = false;

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => showWindow());
  void app.whenReady().then(start);
}

async function start(): Promise<void> {
  // Windows keys notifications, the taskbar and the launch-at-login entry on this id (appId in electron-builder.yml).
  // A run with its own profile (tests, development) gets its own id, so Windows never merges its taskbar button,
  // badge and notifications into those of the FortiConnect the user has installed.
  app.setAppUserModelId(process.env.FORTICONNECT_USER_DATA ? 'com.forticonnect.app.test' : 'com.forticonnect.app');
  try {
    engine = await startEngine();
  } catch (e) {
    dialog.showErrorBox('FortiConnect', `Could not start the FortiConnect engine.\n\n${e instanceof Error ? e.message : String(e)}`);
    app.exit(1);
    return;
  }
  // A smoke test stays offline unless it points the updater at a test feed.
  updater = await Updater.create((m) => console.log(m), !!process.env.FORTICONNECT_SMOKE_SHOT && !process.env.FORTICONNECT_UPDATE_FEED);
  installIpc();
  installMenu();
  openWindow();
  panel = new TrayPanel(engine, path.join(__dirname, 'preload.js'), devUrl);
  createTray();
}

function openWindow(): void {
  if (!engine) return;
  win = createMainWindow(engine, path.join(__dirname, 'preload.js'), devUrl);
  win.webContents.once('did-finish-load', () => {
    const shot = process.env.FORTICONNECT_SMOKE_SHOT;
    if (shot) smokeShot(shot);
  });
  // A new window (or one reopened after closing) gets the badge for the current state; Windows drops it with the button.
  win.once('show', () => updateTray());
  win.on('close', (e) => {
    // Close = hide to the tray (the connection stays up); Quit from the tray disconnects and exits.
    if (!quitting && prefs.minimizeToTray && tray) {
      e.preventDefault();
      win?.hide();
    }
  });
  // Windows is logging off or shutting down: disconnect while we still can, so the FortiGate sees a clean logout.
  win.on('session-end', () => {
    quitting = true;
    void stopEngine();
  });
  win.on('closed', () => {
    win = null;
    // The hidden tray panel keeps a window alive, so 'window-all-closed' would never fire: quit here instead.
    if (!quitting && !(tray && prefs.minimizeToTray)) quit();
  });
}

function showWindow(): void {
  if (!win) openWindow();
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

function sendCommand(command: string, show = true): void {
  if (show) showWindow();
  win?.webContents.send(CH.command, command);
}

/** The tray menu's words in Persian; the menu follows the UI language. */
const TRAY_FA: Record<string, string> = {
  'Connected to {profile}': 'متصل به {profile}',
  Connected: 'متصل',
  'Connecting…': 'در حال اتصال…',
  'Not connected': 'وصل نیست',
  Connect: 'اتصال',
  Disconnect: 'قطع اتصال',
  'Show FortiConnect': 'نمایش FortiConnect',
  'Add profile…': 'افزودن پروفایل…',
  'Paste a link': 'چسباندن لینک',
  'Settings…': 'تنظیمات…',
  Quit: 'خروج',
};

function tr(text: string, profile = ''): string {
  return (prefs.language === 'fa' ? (TRAY_FA[text] ?? text) : text).replace('{profile}', profile);
}

function createTray(): void {
  const image = nativeImage.createFromPath(trayIconPath(false));
  if (image.isEmpty()) return;
  tray = new Tray(image.resize({ width: 16, height: 16 }));
  // Left click opens the panel, right click the menu. No setContextMenu: on macOS it would take the left click too.
  tray.on('click', () => {
    if (panel && tray) panel.toggle(tray.getBounds());
    else showWindow();
  });
  tray.on('right-click', () => {
    panel?.hide();
    if (trayMenu) tray?.popUpContextMenu(trayMenu);
  });
  updateTray();
}

let lastBadge = '';

/**
 * The connection on the app's own icon: Windows draws a small badge over the taskbar button (green with a tick when
 * connected, amber while connecting, grey when not); macOS has no overlay, so the Dock icon is swapped for one with the
 * badge drawn in. Linux taskbars have neither; the tray icon shows the state there.
 */
function updateAppBadge(label: string): void {
  const state: BadgeState = trayState.status === 'connected' ? 'on' : trayState.status === 'connecting' ? 'busy' : 'off';
  if (process.platform === 'win32' && win && !win.isDestroyed()) {
    const image = nativeImage.createFromPath(badgePath(state));
    if (!image.isEmpty()) win.setOverlayIcon(image, label);
  } else if (process.platform === 'darwin' && app.dock) {
    const image = nativeImage.createFromPath(dockIconPath(state));
    if (!image.isEmpty()) app.dock.setIcon(image);
  }
  if (state !== lastBadge) console.log(`badge: ${state}`);
  lastBadge = state;
}

function updateTray(): void {
  if (!tray) return;
  const { status, profile } = trayState;
  const on = status === 'connected';
  const image = nativeImage.createFromPath(trayIconPath(on));
  if (!image.isEmpty()) tray.setImage(image.resize({ width: 16, height: 16 }));
  const label = on ? (profile ? tr('Connected to {profile}', profile) : tr('Connected')) : status === 'connecting' ? tr('Connecting…') : tr('Not connected');
  const tip = `FortiConnect: ${label}`.slice(0, 127);
  // Logged so smoke tests (and bug reports) can see what the tray shows.
  if (tip !== lastTrayTip) console.log(`tray: ${tip}${on ? ' [green icon]' : ''}`);
  lastTrayTip = tip;
  tray.setToolTip(tip);
  updateAppBadge(label);
  trayMenu = Menu.buildFromTemplate([
    { label, enabled: false },
    { label: on || status === 'connecting' ? tr('Disconnect') : tr('Connect'), click: () => sendCommand('conn.toggle', false) },
    { type: 'separator' },
    { label: tr('Show FortiConnect'), click: showWindow },
    { label: tr('Add profile…'), click: () => sendCommand('profile.add') },
    { label: tr('Paste a link'), click: () => sendCommand('profile.paste') },
    { label: tr('Settings…'), click: () => sendCommand('nav.settings') },
    { type: 'separator' },
    { label: tr('Quit'), click: quit },
  ]);
}

function installMenu(): void {
  if (process.platform !== 'darwin') {
    // The in-app menu button replaces the menu bar on Windows and Linux.
    Menu.setApplicationMenu(null);
    return;
  }
  const cmd = (label: string, command: string, accelerator?: string): Electron.MenuItemConstructorOptions => ({ label, accelerator, click: () => sendCommand(command) });
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      { role: 'appMenu' },
      { label: 'Profiles', submenu: [cmd('Add profile…', 'profile.add', 'CmdOrCtrl+N'), cmd('Paste a link', 'profile.paste'), cmd('Go to Profiles', 'nav.profiles')] },
      { role: 'editMenu' },
      { label: 'Connection', submenu: [cmd('Connect / Disconnect', 'conn.toggle', 'CmdOrCtrl+Return'), cmd('Check gateways', 'profile.test', 'CmdOrCtrl+T')] },
      { role: 'viewMenu' },
      { role: 'windowMenu' },
    ]),
  );
}

function installIpc(): void {
  ipcMain.handle(CH.chooseFile, async (e, purpose: FilePurpose, defaultPath?: string) => {
    const owner = BrowserWindow.fromWebContents(e.sender) ?? undefined;
    const pick = FILE_PICKER[purpose] ?? FILE_PICKER.openconnect;
    const opts: Electron.OpenDialogOptions = {
      title: pick.title,
      properties: ['openFile'],
      defaultPath: typeof defaultPath === 'string' ? defaultPath : undefined,
      filters: pick.filters(),
    };
    const r = owner ? await dialog.showOpenDialog(owner, opts) : await dialog.showOpenDialog(opts);
    return r.canceled ? null : (r.filePaths[0] ?? null);
  });
  ipcMain.on(CH.notify, (_e, title: unknown, body: unknown) => {
    // A toast already shows it inside a focused window.
    if (win?.isFocused() || !Notification.isSupported()) return;
    const n = new Notification({ title: String(title).slice(0, 200), body: String(body).slice(0, 500), icon: iconPath() });
    n.on('click', showWindow);
    n.show();
  });
  ipcMain.on(CH.setTheme, (_e, theme: unknown, colors: { bg?: unknown; fg?: unknown }) => {
    nativeTheme.themeSource = theme === 'dark' ? 'dark' : 'light';
    if (titleBarKind() !== 'overlay' || !win) return;
    const fallback = theme === 'dark' ? DARK : LIGHT;
    const color = /^#[0-9a-f]{3,8}$/i.test(String(colors?.bg)) ? String(colors.bg) : fallback.bg;
    const symbolColor = /^#[0-9a-f]{3,8}$/i.test(String(colors?.fg)) ? String(colors.fg) : fallback.fg;
    win.setTitleBarOverlay({ color, symbolColor });
    win.setBackgroundColor(color);
  });
  ipcMain.on(CH.setPreferences, (_e, p: Preferences) => {
    const next: Preferences = { minimizeToTray: !!p?.minimizeToTray, autoUpdate: p?.autoUpdate !== false, launchAtLogin: !!p?.launchAtLogin, language: p?.language === 'fa' ? 'fa' : 'en' };
    // Once per start as well: the entry holds the executable's path, which an update can change (Raylit.exe became
    // FortiConnect.exe), and a stale entry would start nothing at sign-in.
    if (app.isPackaged && (next.launchAtLogin !== prefs.launchAtLogin || !loginItemSynced)) {
      app.setLoginItemSettings({ openAtLogin: next.launchAtLogin, args: ['--hidden'] });
      loginItemSynced = true;
    }
    const relabel = next.language !== prefs.language;
    prefs = next;
    updater?.configure(prefs.autoUpdate);
    if (relabel) updateTray();
  });
  ipcMain.on(CH.showMain, (_e, command: unknown) => {
    panel?.hide();
    if (typeof command === 'string' && /^[a-z]+\.[A-Za-z]+$/.test(command)) sendCommand(command);
    else showWindow();
  });
  ipcMain.on(CH.hidePanel, () => panel?.hide());
  ipcMain.on(CH.quitApp, quit);
  ipcMain.on(CH.setTrayState, (_e, s: TrayState) => {
    const status = s?.status === 'connected' || s?.status === 'connecting' ? s.status : 'disconnected';
    trayState = { status, profile: String(s?.profile ?? '').slice(0, 80) };
    updateTray();
  });
  ipcMain.on(CH.relaunchAdmin, relaunchAsAdmin);
  ipcMain.handle(CH.updateGet, () => updater?.current ?? null);
  ipcMain.handle(CH.updateCheck, () => updater?.check() ?? null);
  ipcMain.handle(CH.updateInstall, () => {
    if (!updater) return false;
    // quitAndInstall quits the app: let the close handler know it is a real quit, not "hide to tray".
    quitting = true;
    const ok = updater.quitAndInstall();
    if (!ok) quitting = false;
    return ok;
  });
  ipcMain.on(CH.appVersion, (e) => {
    e.returnValue = app.getVersion();
  });
  ipcMain.on(CH.readClipboard, (e) => {
    e.returnValue = clipboard.readText();
  });
  ipcMain.on(CH.writeClipboard, (_e, text: unknown) => {
    if (typeof text === 'string' && text.length < 1_000_000) clipboard.writeText(text);
  });
}

const FILE_PICKER: Record<FilePurpose, { title: string; filters: () => Electron.FileFilter[] }> = {
  openconnect: { title: 'Choose the OpenConnect program', filters: () => (process.platform === 'win32' ? [{ name: 'OpenConnect', extensions: ['exe'] }] : []) },
  charon: { title: "Choose strongSwan's charon-cmd", filters: () => [] },
  script: { title: 'Choose the vpnc-script', filters: () => (process.platform === 'win32' ? [{ name: 'Scripts', extensions: ['js', 'bat', 'cmd'] }] : []) },
  cert: { title: 'Choose the client certificate', filters: () => [{ name: 'Certificates', extensions: ['pem', 'crt', 'p12', 'pfx'] }, { name: 'All files', extensions: ['*'] }] },
};

/**
 * Windows: start FortiConnect again with administrator rights (SSL-VPN needs them to create its adapter), then quit
 * this copy. The single-instance lock is released before the elevated copy starts, or it would find this one and quit.
 */
function relaunchAsAdmin(): void {
  if (process.platform !== 'win32') return;
  const args = process.argv.slice(1).filter((a) => a !== '--hidden');
  const quoted = (v: string) => `'${v.replace(/'/g, "''")}'`;
  const list = args.length ? ` -ArgumentList ${args.map(quoted).join(',')}` : '';
  app.releaseSingleInstanceLock();
  const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Start-Process -FilePath ${quoted(process.execPath)}${list} -Verb RunAs`], { windowsHide: true, stdio: 'ignore' });
  ps.on('exit', (code) => {
    // Code 0: the user allowed it and the elevated copy is starting. Otherwise (UAC declined) keep running as before.
    if (code === 0) quit();
    else app.requestSingleInstanceLock();
  });
}

function quit(): void {
  quitting = true;
  app.quit();
}

/** Smoke test (FORTICONNECT_SMOKE_SHOT=<file.png>): let the UI connect to the engine, capture the window, quit. */
function smokeShot(file: string): void {
  const delay = Number(process.env.FORTICONNECT_SMOKE_DELAY_MS) || 3000;
  // FORTICONNECT_SMOKE_TRAY_SHOT=<file.png>: also open the tray panel and capture it.
  const trayShot = process.env.FORTICONNECT_SMOKE_TRAY_SHOT;
  if (trayShot) {
    setTimeout(() => {
      try {
        if (!tray || !panel) throw new Error('no tray icon');
        panel.toggle(tray.getBounds());
        console.log(`smoke: tray panel opened at ${JSON.stringify(tray.getBounds())}`);
      } catch (e) {
        console.error('smoke: tray panel failed', e);
      }
    }, Math.max(0, delay - 2500));
  }
  setTimeout(async () => {
    try {
      writeFileSync(file, (await win!.webContents.capturePage()).toPNG());
      console.log(`smoke: wrote ${file}`);
      const panelWin = BrowserWindow.getAllWindows().find((w) => w !== win);
      if (trayShot && !panelWin) console.error('smoke: no tray panel window to capture');
      if (trayShot && panelWin) {
        // The panel hides when it loses focus (the main window takes it during a smoke run), and a hidden window
        // never finishes a capture: show it without focus, and give up after a few seconds rather than hang.
        if (!panelWin.isVisible()) panelWin.showInactive();
        await new Promise((r) => setTimeout(r, 500));
        const image = await Promise.race([panelWin.webContents.capturePage(), new Promise<null>((r) => setTimeout(() => r(null), 5000))]);
        if (image) {
          writeFileSync(trayShot, image.toPNG());
          console.log(`smoke: wrote ${trayShot}`);
        } else console.error('smoke: tray panel capture timed out');
      }
    } catch (e) {
      console.error('smoke: capture failed', e);
      process.exitCode = 1;
    }
    quit();
  }, delay);
}

app.on('before-quit', (e) => {
  quitting = true;
  if (!engine) return;
  // Let the engine disconnect (logging out of the FortiGate) and save before the app exits.
  e.preventDefault();
  engine = null;
  panel?.destroy();
  void stopEngine().finally(() => app.quit());
});

app.on('window-all-closed', () => {
  if (!tray || !prefs.minimizeToTray) quit();
});

app.on('activate', showWindow);
