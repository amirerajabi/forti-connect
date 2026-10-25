import { app } from 'electron';
import * as path from 'node:path';

/** Repo layout in development, resources/ in a packaged build (electron-builder extraResources). */
const root = app.isPackaged ? process.resourcesPath : path.resolve(__dirname, '..', '..');
const buildDir = app.isPackaged ? root : path.join(root, 'desktop', 'build');

export function engineEntry(): string {
  return app.isPackaged ? path.join(root, 'engine', 'engine.cjs') : path.join(root, 'engine', 'dist', 'engine.cjs');
}

export function uiIndex(): string {
  return app.isPackaged ? path.join(root, 'ui', 'index.html') : path.join(root, 'ui', 'dist', 'index.html');
}

/** An OpenConnect copy shipped inside the installer (resources/core), when the build included one. */
export function bundledCoreDir(): string {
  return app.isPackaged ? path.join(root, 'core') : path.join(root, 'desktop', 'core');
}

export function iconPath(): string {
  return path.join(buildDir, process.platform === 'win32' ? 'icon.ico' : 'icon.png');
}

export function trayIconPath(connected: boolean): string {
  return path.join(buildDir, connected ? 'tray-on.png' : 'tray.png');
}

export type BadgeState = 'on' | 'busy' | 'off';

/** The connection badge Windows draws over the taskbar icon (badge-<state>.png, with a @2x copy beside it). */
export function badgePath(state: BadgeState): string {
  return path.join(buildDir, `badge-${state}.png`);
}

/** macOS has no overlay: the Dock icon itself carries the badge. */
export function dockIconPath(state: BadgeState): string {
  return path.join(buildDir, `dock-${state}.png`);
}

export function dataDir(): string {
  return path.join(app.getPath('userData'), 'data');
}

export function windowStateFile(): string {
  return path.join(app.getPath('userData'), 'window-state.json');
}
