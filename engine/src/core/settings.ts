import type { LogLevel, Settings } from '../../../shared/protocol';

const LOG_LEVELS: LogLevel[] = ['normal', 'verbose'];

export function defaultSettings(): Settings {
  return {
    openconnectPath: '',
    charonPath: '',
    vpncScript: '',
    reconnect: true,
    logLevel: 'normal',
    autoConnect: false,
    theme: 'system',
    language: 'en',
    minimizeToTray: true,
    launchAtLogin: false,
    autoUpdate: true,
  };
}

function filePath(v: unknown): string | null {
  return typeof v === 'string' ? v.trim().replace(/^"|"$/g, '').slice(0, 1000) : null;
}

/** Merge a partial update into the settings, coercing every field to a valid value. */
export function mergeSettings(base: Settings, patch: Partial<Settings>): Settings {
  const s: Settings = { ...base };
  const p = patch as Record<string, unknown>;
  for (const k of ['openconnectPath', 'charonPath', 'vpncScript'] as const) {
    const v = filePath(p[k]);
    if (v !== null) s[k] = v;
  }
  if (typeof p.reconnect === 'boolean') s.reconnect = p.reconnect;
  if (LOG_LEVELS.includes(p.logLevel as LogLevel)) s.logLevel = p.logLevel as LogLevel;
  if (typeof p.autoConnect === 'boolean') s.autoConnect = p.autoConnect;
  if (p.theme === 'system' || p.theme === 'light' || p.theme === 'dark') s.theme = p.theme;
  if (p.language === 'en' || p.language === 'fa') s.language = p.language;
  if (typeof p.minimizeToTray === 'boolean') s.minimizeToTray = p.minimizeToTray;
  if (typeof p.launchAtLogin === 'boolean') s.launchAtLogin = p.launchAtLogin;
  if (typeof p.autoUpdate === 'boolean') s.autoUpdate = p.autoUpdate;
  return s;
}

/** Settings that decide which programs connect: a change looks for them again. */
export const BACKEND_KEYS: (keyof Settings)[] = ['openconnectPath', 'charonPath', 'vpncScript'];
