/** IPC channel names shared by main and preload. */
export const CH = {
  chooseFile: 'forticonnect:choose-file',
  notify: 'forticonnect:notify',
  setTheme: 'forticonnect:set-theme',
  setPreferences: 'forticonnect:set-preferences',
  setTrayState: 'forticonnect:set-tray-state',
  readClipboard: 'forticonnect:read-clipboard',
  writeClipboard: 'forticonnect:write-clipboard',
  command: 'forticonnect:command',
  updateStatus: 'forticonnect:update-status',
  updateGet: 'forticonnect:update-get',
  updateCheck: 'forticonnect:update-check',
  updateInstall: 'forticonnect:update-install',
  appVersion: 'forticonnect:app-version',
  showMain: 'forticonnect:show-main',
  hidePanel: 'forticonnect:hide-panel',
  quitApp: 'forticonnect:quit-app',
  relaunchAdmin: 'forticonnect:relaunch-admin',
} as const;

/** additionalArguments passed to the renderer: --forticonnect-engine=<url> --forticonnect-token=<token> --forticonnect-titlebar=<kind> */
export const ARG = {
  engine: '--forticonnect-engine=',
  token: '--forticonnect-token=',
  titleBar: '--forticonnect-titlebar=',
} as const;

export interface Preferences {
  minimizeToTray: boolean;
  autoUpdate: boolean;
  launchAtLogin: boolean;
  /** The tray menu follows the UI language. */
  language: 'en' | 'fa';
}

export interface TrayState {
  status: 'disconnected' | 'connecting' | 'connected';
  /** The profile's name. */
  profile: string;
}

/** What the file picker is for: it sets the title and the file types. */
export type FilePurpose = 'openconnect' | 'charon' | 'script' | 'cert';
