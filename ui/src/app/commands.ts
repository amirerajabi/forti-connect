import {
  ArrowDownWideNarrow,
  ClipboardCopy,
  ClipboardPaste,
  Copy,
  Gauge,
  House,
  Keyboard,
  KeyRound,
  Languages,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
  SunMoon,
  Trash2,
  type LucideIcon,
} from 'lucide-react';
import { api } from '../api/client';
import { t } from '../i18n';
import { getPlatform, readClipboardText } from '../platform';
import { useConnection } from '../store/connection';
import { useEngine } from '../store/engine';
import { useProfiles, visibleProfiles } from '../store/profiles';
import { useUi, type Page } from '../store/ui';
import { useUpdates } from '../store/updates';
import { matches } from './keys';

export interface Command {
  id: string;
  /** English; shown through t(). */
  label: string;
  icon?: LucideIcon;
  shortcut?: string;
  /** Shown in the palette; false hides it there. */
  palette?: boolean;
  /** Why it is unavailable right now (English, shown through t()), or null when it can run. */
  disabled?: () => string | null;
  run: () => unknown;
}

/** Run an engine call and surface its error as a toast. */
export async function attempt<T>(fn: () => Promise<T>, failure = 'Action failed'): Promise<T | undefined> {
  try {
    return await fn();
  } catch (e) {
    useUi.getState().toast({ level: 'error', text: t(failure), detail: e instanceof Error ? e.message : String(e) });
    return undefined;
  }
}

const noProfiles = () => (useProfiles.getState().profiles.length === 0 ? 'Add a profile first' : null);
const noSelection = () => (useProfiles.getState().selectedId ? null : 'Choose a profile first');

export function isConnected(): boolean {
  return useConnection.getState().connection.status === 'connected';
}

/** Connecting can wait on a question (a FortiToken code): the prompt dialog shows it; failures come back as toasts. */
export async function connectTo(id?: string): Promise<void> {
  await attempt(() => api.connect(id), 'Could not connect');
}

export async function toggleConnection(): Promise<void> {
  const status = useConnection.getState().connection.status;
  if (status === 'connected' || status === 'connecting') await attempt(() => api.disconnect(), 'Could not disconnect');
  else await connectTo();
}

/** forticonnect:// links (one per line) become profiles. */
export async function importText(text: string): Promise<boolean> {
  const s = text.trim();
  if (!s) return false;
  try {
    const r = await api.importLinks(s);
    if (r.added === 0 && r.duplicates === 0) return false;
    const extra = [r.duplicates ? t('{n} already in the list', { n: r.duplicates }) : '', r.skipped ? t('{n} not understood', { n: r.skipped }) : '']
      .filter(Boolean)
      .join(' · ');
    useUi.getState().toast({ level: r.added ? 'success' : 'info', text: r.added ? t('Added {n} profiles', { n: r.added }) : t('Nothing new to add'), detail: extra || undefined });
    return true;
  } catch {
    return false;
  }
}

export async function pasteFromClipboard(): Promise<void> {
  const text = await readClipboardText();
  if (await importText(text)) return;
  useUi.getState().toast({ level: 'info', text: t('No forticonnect:// link on the clipboard'), detail: t('Copy a profile link first, or add a profile by hand.') });
}

export async function deleteProfile(id: string): Promise<void> {
  const p = useProfiles.getState().profiles.find((x) => x.id === id);
  if (!p) return;
  const r = await useUi.getState().askConfirm({
    title: t('Delete profile'),
    message: t('Delete "{name}"? Its saved password goes with it.', { name: p.name }),
    confirmLabel: t('Delete'),
    danger: true,
  });
  if (r.ok) await attempt(() => api.deleteProfiles([id]), 'Could not delete');
}

export async function duplicateProfile(id: string): Promise<void> {
  const p = await attempt(() => api.duplicateProfile(id), 'Could not duplicate');
  if (p) useUi.getState().set({ profileDialog: { id: p.id } });
}

export async function copyProfileLink(id: string): Promise<void> {
  const r = await attempt(() => api.profileLink(id), 'Could not copy the link');
  if (!r) return;
  getPlatform().writeClipboard(r.link);
  useUi.getState().toast({ level: 'info', text: t('Profile link copied'), detail: t('Passwords and keys are not part of it.') });
}

export function testProfiles(ids: string[]): Promise<unknown> {
  return attempt(() => api.test(ids), 'Could not start the check');
}

function toggleTheme(): void {
  const pref = useEngine.getState().settings?.theme ?? 'system';
  const next = pref === 'system' ? 'dark' : pref === 'dark' ? 'light' : 'system';
  void attempt(() => useEngine.getState().updateSettings({ theme: next }));
}

const nav = (page: Page) => () => useUi.getState().go(page);

/** Why the VPN helper cannot be changed right now, or null. */
function helperUnavailable(): string | null {
  const b = useEngine.getState().backends;
  if (b.platform !== 'win32' || !b.helper) return 'Only Windows needs the VPN helper';
  return b.helper.busy ? 'Waiting for the administrator prompt…' : null;
}

/** Windows asks for administrator rights once; afterwards SSL-VPN works with FortiConnect as a normal user. */
export async function installHelper(): Promise<void> {
  useUi.getState().toast({ level: 'info', text: t('Windows will ask for administrator rights to install the VPN helper.') });
  const b = await attempt(() => api.installHelper(), 'Could not install the VPN helper');
  if (b) useEngine.getState().setBackends(b);
}

export async function removeHelper(): Promise<void> {
  const r = await useUi.getState().askConfirm({
    title: t('Remove the VPN helper'),
    message: t('SSL-VPN will then need FortiConnect running as administrator. Windows asks for administrator rights to remove it.'),
    confirmLabel: t('Remove'),
    danger: true,
  });
  if (!r.ok) return;
  const b = await attempt(() => api.removeHelper(), 'Could not remove the VPN helper');
  if (b) useEngine.getState().setBackends(b);
}

export const COMMANDS: Command[] = [
  {
    id: 'conn.toggle',
    label: 'Connect / Disconnect',
    icon: Power,
    shortcut: 'Mod+Enter',
    // While connecting it stays enabled: it cancels the connect.
    disabled: () => (useConnection.getState().connection.status === 'disconnecting' ? 'Disconnecting…' : noProfiles()),
    run: toggleConnection,
  },
  { id: 'profile.add', label: 'Add profile…', icon: Plus, shortcut: 'Mod+N', run: () => useUi.getState().set({ profileDialog: { id: null } }) },
  { id: 'profile.paste', label: 'Paste profile link', icon: ClipboardPaste, shortcut: 'Mod+V', run: pasteFromClipboard },
  { id: 'profile.edit', label: 'Edit profile…', icon: Pencil, disabled: noSelection, run: () => useUi.getState().set({ profileDialog: { id: useProfiles.getState().selectedId } }) },
  { id: 'profile.duplicate', label: 'Duplicate profile', icon: Copy, disabled: noSelection, run: () => duplicateProfile(useProfiles.getState().selectedId!) },
  { id: 'profile.copyLink', label: 'Copy profile link', icon: ClipboardCopy, disabled: noSelection, run: () => copyProfileLink(useProfiles.getState().selectedId!) },
  { id: 'profile.delete', label: 'Delete profile', icon: Trash2, disabled: noSelection, run: () => deleteProfile(useProfiles.getState().selectedId!) },
  {
    id: 'profile.test',
    label: 'Check gateways',
    icon: Gauge,
    shortcut: 'Mod+T',
    disabled: () => (useConnection.getState().testing ? 'A check is running' : noProfiles()),
    run: () => testProfiles(visibleProfiles(useProfiles.getState()).map((p) => p.id)),
  },
  {
    id: 'profile.sortDelay',
    label: 'Sort by gateway time',
    icon: ArrowDownWideNarrow,
    disabled: noProfiles,
    run: () => useProfiles.getState().setSort(useProfiles.getState().sort === 'delay' ? 'list' : 'delay'),
  },
  { id: 'nav.home', label: 'Go to Connection', icon: House, shortcut: 'Mod+1', run: nav('home') },
  { id: 'nav.profiles', label: 'Go to Profiles', icon: KeyRound, shortcut: 'Mod+2', run: nav('profiles') },
  { id: 'nav.log', label: 'Go to Log', icon: ScrollText, shortcut: 'Mod+3', run: nav('log') },
  { id: 'nav.settings', label: 'Settings', icon: Settings, shortcut: 'Mod+,', run: nav('settings') },
  { id: 'nav.programs', label: 'VPN programs (OpenConnect, strongSwan)', icon: ShieldCheck, run: () => useUi.getState().go('settings', 'programs') },
  {
    id: 'view.focusFilter',
    label: 'Search profiles',
    icon: Search,
    shortcut: 'Mod+F',
    run: () => {
      useUi.getState().go('profiles');
      setTimeout(() => document.getElementById('profile-search')?.focus(), 0);
    },
  },
  { id: 'view.palette', label: 'Command palette', icon: Search, shortcut: 'Mod+K', palette: false, run: () => useUi.getState().set({ paletteOpen: true }) },
  { id: 'view.toggleTheme', label: 'Switch theme (system / dark / light)', icon: SunMoon, run: toggleTheme },
  {
    id: 'view.language',
    label: 'Switch language (English / فارسی)',
    icon: Languages,
    run: () => {
      const lang = useEngine.getState().settings?.language === 'fa' ? 'en' : 'fa';
      void attempt(() => useEngine.getState().updateSettings({ language: lang }));
    },
  },
  {
    id: 'app.relaunchAdmin',
    label: 'Restart as administrator',
    icon: ShieldCheck,
    disabled: () => {
      const p = getPlatform();
      if (p.kind !== 'electron' || p.os !== 'win32') return 'Only the Windows app needs this';
      return useEngine.getState().backends.elevated ? 'FortiConnect already runs as administrator' : null;
    },
    run: () => getPlatform().relaunchAsAdmin(),
  },
  {
    id: 'helper.install',
    label: 'Install the VPN helper',
    icon: ShieldCheck,
    disabled: helperUnavailable,
    run: installHelper,
  },
  {
    id: 'helper.remove',
    label: 'Remove the VPN helper',
    icon: Trash2,
    disabled: () => helperUnavailable() ?? (useEngine.getState().backends.helper?.state === 'missing' ? 'The VPN helper is not installed' : null),
    run: removeHelper,
  },
  {
    id: 'app.checkUpdates',
    label: 'Check for updates',
    icon: RefreshCw,
    disabled: () => (getPlatform().kind === 'electron' ? null : 'Updates are part of the desktop app'),
    run: () => {
      useUi.getState().go('settings', 'updates');
      return useUpdates.getState().check();
    },
  },
  { id: 'view.shortcuts', label: 'Keyboard shortcuts', icon: Keyboard, shortcut: 'Mod+/', run: () => useUi.getState().set({ shortcutsOpen: true }) },
];

const byId = new Map(COMMANDS.map((c) => [c.id, c]));

export function getCommand(id: string): Command | undefined {
  return byId.get(id);
}

export function runCommand(id: string): void {
  const c = byId.get(id);
  if (!c || c.disabled?.()) return;
  void c.run();
}

function modalOpen(): boolean {
  const u = useUi.getState();
  return !!(u.profileDialog || u.paletteOpen || u.shortcutsOpen || u.confirm || useConnection.getState().connection.prompt);
}

/** Keys a text field needs for itself (paste). */
const NOT_WHILE_TYPING = new Set(['profile.paste']);

export function installKeyboard(): () => void {
  const onKey = (e: KeyboardEvent) => {
    if (e.defaultPrevented) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement)?.tagName ?? '');
    for (const c of COMMANDS) {
      if (!c.shortcut || !matches(e, c.shortcut)) continue;
      if (NOT_WHILE_TYPING.has(c.id) && typing) continue;
      if (modalOpen() && c.id !== 'view.palette') continue;
      if (typing && !c.shortcut.includes('Mod')) continue;
      e.preventDefault();
      runCommand(c.id);
      return;
    }
  };
  window.addEventListener('keydown', onKey);
  const offMenu = getPlatform().onCommand((id) => runCommand(id));
  return () => {
    window.removeEventListener('keydown', onKey);
    offMenu();
  };
}
