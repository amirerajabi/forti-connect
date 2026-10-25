import { Cable, FolderOpen, Info, KeyRound, LoaderCircle, RefreshCw, RotateCw, Settings, ShieldCheck, SlidersHorizontal, Smartphone, Wrench } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import type { BackendInfo, HelperInfo, LogLevel, Settings as SettingsT } from '../../../shared/protocol';
import { api } from '../api/client';
import { attempt, runCommand } from '../app/commands';
import { Field } from '../components/common/Dialog';
import { BrandMark } from '../components/common/visuals';
import { useT } from '../i18n';
import { ikeLabel } from '../lib/format';
import { getPlatform, type FilePurpose } from '../platform';
import { useEngine } from '../store/engine';
import { useUi, type SettingsSection } from '../store/ui';
import { useUpdates } from '../store/updates';

const SECTIONS: { id: SettingsSection; label: string; Icon: typeof Settings }[] = [
  { id: 'general', label: 'General', Icon: SlidersHorizontal },
  { id: 'connection', label: 'Connection', Icon: Cable },
  { id: 'programs', label: 'VPN programs', Icon: Wrench },
  { id: 'updates', label: 'Updates', Icon: RefreshCw },
  { id: 'about', label: 'About', Icon: Info },
];

/** Settings as a page: section list beside the section, every change saved at once. */
export function SettingsPage() {
  const t = useT();
  const section = useUi((s) => s.settingsSection);
  const settings = useEngine((s) => s.settings);
  if (!settings) return null;
  return (
    <div className="page settings-page">
      <header className="page-head">
        <h1>{t('Settings')}</h1>
      </header>
      <div className="settings-layout">
        <nav className="settings-nav" aria-label={t('Sections')}>
          {SECTIONS.map((s) => (
            <button key={s.id} className={`nav-item${section === s.id ? ' active' : ''}`} aria-current={section === s.id ? 'page' : undefined} onClick={() => useUi.getState().go('settings', s.id)}>
              <s.Icon size={16} />
              {t(s.label)}
            </button>
          ))}
        </nav>
        <div className="settings-body card">
          <Section key={section} id={section} s={settings} />
        </div>
      </div>
    </div>
  );
}

function save(patch: Partial<SettingsT>): void {
  void attempt(() => useEngine.getState().updateSettings(patch), 'Could not save the setting');
}

function Toggle({ label, hint, checked, onChange }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="toggle-row">
      <input type="checkbox" className="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <span className="toggle-label">{label}</span>
        {hint && <span className="field-hint">{hint}</span>}
      </span>
    </label>
  );
}

/** A file path that saves on blur, with Browse in the desktop app. */
function PathField({ label, hint, value, purpose, placeholder, onSave }: { label: string; hint?: ReactNode; value: string; purpose: FilePurpose; placeholder: string; onSave: (v: string) => void }) {
  const t = useT();
  const [v, setV] = useState(value);
  const browse = async () => {
    const picked = await getPlatform().chooseFile(purpose, v || undefined);
    if (picked) {
      setV(picked);
      onSave(picked);
    }
  };
  return (
    <Field label={label} hint={hint}>
      <div className="input-with-btn">
        <input className="input mono-sm" dir="ltr" value={v} placeholder={placeholder} onChange={(e) => setV(e.target.value)} onBlur={() => v.trim() !== value && onSave(v.trim())} onKeyDown={(e) => e.key === 'Enter' && v.trim() !== value && onSave(v.trim())} spellCheck={false} />
        {getPlatform().kind === 'electron' && (
          <button className="btn" onClick={() => void browse()}>
            <FolderOpen size={16} /> {t('Browse')}
          </button>
        )}
      </div>
    </Field>
  );
}

const LOG_LEVELS: { id: LogLevel; label: string }[] = [
  { id: 'normal', label: 'Normal' },
  { id: 'verbose', label: 'Verbose' },
];

function Section({ id, s }: { id: SettingsSection; s: SettingsT }) {
  const t = useT();
  const electron = getPlatform().kind === 'electron';
  switch (id) {
    case 'general':
      return (
        <div className="settings-section">
          <h3>{t('General')}</h3>
          <Field label={t('Language')}>
            <div className="segmented">
              <button className={s.language === 'en' ? 'on' : ''} aria-pressed={s.language === 'en'} onClick={() => save({ language: 'en' })} lang="en">
                English
              </button>
              <button className={s.language === 'fa' ? 'on' : ''} aria-pressed={s.language === 'fa'} onClick={() => save({ language: 'fa' })} lang="fa">
                فارسی
              </button>
            </div>
          </Field>
          <Field label={t('Theme')}>
            <div className="segmented">
              {(['system', 'light', 'dark'] as const).map((th) => (
                <button key={th} className={s.theme === th ? 'on' : ''} aria-pressed={s.theme === th} onClick={() => save({ theme: th })}>
                  {t(th === 'system' ? 'System' : th === 'light' ? 'Light' : 'Dark')}
                </button>
              ))}
            </div>
          </Field>
          <Toggle label={t('Connect when FortiConnect starts')} hint={t('To the profile you used last.')} checked={s.autoConnect} onChange={(v) => save({ autoConnect: v })} />
          {electron && <Toggle label={t('Start FortiConnect when I sign in')} hint={t('It starts in the tray.')} checked={s.launchAtLogin} onChange={(v) => save({ launchAtLogin: v })} />}
          {electron && <Toggle label={t('Keep running in the tray when the window is closed')} hint={t('The connection stays up in the background.')} checked={s.minimizeToTray} onChange={(v) => save({ minimizeToTray: v })} />}
        </div>
      );
    case 'connection':
      return (
        <div className="settings-section">
          <h3>{t('Connection')}</h3>
          <Toggle label={t('Reconnect automatically')} hint={t('When the tunnel drops, try again up to 5 times. Skipped when a code or password would have to be asked.')} checked={s.reconnect} onChange={(v) => save({ reconnect: v })} />
          <Field label={t('Log detail')} hint={t('Verbose shows every step of the VPN program; useful when a connection fails.')}>
            <div className="segmented">
              {LOG_LEVELS.map((l) => (
                <button key={l.id} className={s.logLevel === l.id ? 'on' : ''} aria-pressed={s.logLevel === l.id} onClick={() => save({ logLevel: l.id })}>
                  {t(l.label)}
                </button>
              ))}
            </div>
          </Field>
          <p className="muted settings-note">{t('Passwords and pre-shared keys you save are encrypted on this computer and never appear in the log.')}</p>
        </div>
      );
    case 'programs':
      return <ProgramsSection s={s} />;
    case 'updates':
      return <UpdatesSection s={s} />;
    case 'about':
      return (
        <div className="settings-section about">
          <BrandMark size={48} />
          <h3>FortiConnect</h3>
          <p className="muted" dir="ltr">
            {electron ? `Version ${getPlatform().appVersion} · ` : 'Browser build · '}engine {useEngine.getState().version}
          </p>
          <p className="muted">{t('Not affiliated with Fortinet.')}</p>
          <ul className="about-list">
            <li>
              <ShieldCheck size={14} /> {t('One button to connect to a FortiGate over SSL-VPN (with OpenConnect) or IPsec (IKEv1 + XAuth, IKEv2 or L2TP).')}
            </li>
            <li>
              <Smartphone size={14} /> {t('FortiToken and other verification codes are asked in a dialog while connecting.')}
            </li>
            <li>
              <KeyRound size={14} /> {t('Saved passwords are encrypted; self-signed gateways can be pinned by their certificate.')}
            </li>
          </ul>
          <a href="https://github.com/amirerajabi/forti-connect" target="_blank" rel="noreferrer">
            github.com/amirerajabi/forti-connect
          </a>
        </div>
      );
  }
}

const KIND_NAME: Record<BackendInfo['kind'], string> = { openconnect: 'OpenConnect', charon: 'strongSwan charon-cmd', ras: 'Windows VPN client' };

function BackendCard({ title, info }: { title: string; info: BackendInfo }) {
  const t = useT();
  return (
    <div className="info-card">
      <Wrench size={18} className={info.available ? 'text-success' : 'text-warning'} />
      <div className="flex-1">
        <strong>
          {title}: {info.kind === 'ras' ? t(KIND_NAME.ras) : KIND_NAME[info.kind]} {info.version && <span className="muted">{info.version}</span>}
        </strong>
        <p className={info.available ? 'muted' : 'text-warning'}>{info.available ? t('Ready') : t('Not found')}</p>
        {info.path && (
          <p className="muted selectable mono-sm" dir="ltr">
            {info.path}
          </p>
        )}
        {info.modes && <p className="muted">{t('IKE modes: {modes}', { modes: info.modes.map(ikeLabel).join(', ') })}</p>}
        {info.note && (
          <p className="muted" dir="ltr">
            {info.note}
          </p>
        )}
      </div>
    </div>
  );
}

const INSTALL_HINT: Record<'win32' | 'darwin' | 'linux', string> = {
  win32: 'Windows: install OpenConnect for Windows (openconnect.exe with wintun.dll next to it), for example from MSYS2: pacman -S mingw-w64-ucrt-x86_64-openconnect. IPsec needs nothing: FortiConnect uses Windows’ own VPN client.',
  darwin: 'macOS: brew install openconnect strongswan',
  linux: 'Linux: sudo apt install openconnect strongswan-charon (or your distribution’s openconnect and charon-cmd packages).',
};

function ProgramsSection({ s }: { s: SettingsT }) {
  const t = useT();
  const backends = useEngine((e) => e.backends);
  const [busy, setBusy] = useState(false);
  const win = backends.platform === 'win32';
  const refresh = async () => {
    setBusy(true);
    const b = await attempt(() => api.refreshBackends(), 'Could not look for the VPN programs');
    if (b) useEngine.getState().setBackends(b);
    setBusy(false);
  };
  return (
    <div className="settings-section">
      <h3>{t('VPN programs')}</h3>
      <p className="muted settings-note">{t('FortiConnect does the VPN through programs on this computer: OpenConnect for SSL-VPN, and for IPsec Windows’ own client or strongSwan.')}</p>
      <BackendCard title={t('SSL-VPN')} info={backends.ssl} />
      <PathField label={t('OpenConnect program')} hint={t('Leave empty to find it automatically.')} value={s.openconnectPath} purpose="openconnect" placeholder={win ? 'C:\\…\\openconnect.exe' : '/usr/sbin/openconnect'} onSave={(v) => save({ openconnectPath: v })} />
      <PathField label={t('vpnc-script')} hint={t('Sets up addresses and routes for OpenConnect. Leave empty for the one next to it or its default.')} value={s.vpncScript} purpose="script" placeholder={win ? 'C:\\…\\vpnc-script-win.js' : '/etc/vpnc/vpnc-script'} onSave={(v) => save({ vpncScript: v })} />
      {win && backends.helper && <HelperCard info={backends.helper} elevated={backends.elevated} />}
      <BackendCard title={t('IPsec')} info={backends.ipsec} />
      {win ? (
        <p className="muted settings-note">{t('On Windows, IPsec uses Windows’ own VPN client: IKEv2 and L2TP/IPsec. IKEv1 with XAuth is not part of Windows.')}</p>
      ) : (
        <PathField label={t('charon-cmd program')} hint={t('Leave empty to find it automatically.')} value={s.charonPath} purpose="charon" placeholder="/usr/sbin/charon-cmd" onSave={(v) => save({ charonPath: v })} />
      )}
      <div className="input-with-btn">
        <button className="btn" disabled={busy} onClick={() => void refresh()}>
          {busy ? <LoaderCircle size={16} className="spin" /> : <RotateCw size={16} />} {t('Look again')}
        </button>
      </div>
      <p className="muted settings-note selectable">{t(INSTALL_HINT[backends.platform])}</p>
    </div>
  );
}

const HELPER_TEXT: Record<HelperInfo['state'], string> = {
  running: 'Running. SSL-VPN works with FortiConnect as a normal user.',
  outdated: 'Running, but older than this FortiConnect. Update it.',
  stopped: 'Installed but not running. It starts with Windows; install it again if it stays stopped.',
  'other-user': 'Installed for another Windows account. Install it again to add yours.',
  missing: 'Not installed. Without it, SSL-VPN needs FortiConnect running as administrator.',
};

/**
 * The Windows VPN helper: a small program that runs as SYSTEM and starts OpenConnect for FortiConnect, like FortiClient's
 * own service, so FortiConnect itself needs no administrator rights.
 */
function HelperCard({ info, elevated }: { info: HelperInfo; elevated: boolean }) {
  const t = useT();
  const ok = info.state === 'running';
  const installed = info.state !== 'missing';
  return (
    <>
      <div className="info-card">
        <ShieldCheck size={18} className={ok ? 'text-success' : 'text-warning'} />
        <div className="flex-1">
          <strong>
            {t('VPN helper')}
            {info.version ? <span className="muted tabular"> · v{info.version}</span> : null}
          </strong>
          <p className="muted">{t(HELPER_TEXT[info.state])}</p>
          <p className="muted field-hint">{t('It runs as SYSTEM from C:\\Program Files\\FortiConnect Helper, only for your Windows account, and only starts the OpenConnect installed under Program Files.')}</p>
        </div>
      </div>
      <div className="input-with-btn">
        {!ok && (
          <button className="btn btn-primary" disabled={!!info.busy} onClick={() => runCommand('helper.install')}>
            {info.busy ? <LoaderCircle size={16} className="spin" /> : <ShieldCheck size={16} />} {info.state === 'outdated' ? t('Update the VPN helper') : installed ? t('Install again') : t('Install the VPN helper')}
          </button>
        )}
        {installed && (
          <button className="btn" disabled={!!info.busy} onClick={() => runCommand('helper.remove')}>
            {t('Remove the VPN helper')}
          </button>
        )}
        {!ok && !elevated && getPlatform().kind === 'electron' && (
          <button className="btn" onClick={() => runCommand('app.relaunchAdmin')}>
            {t('Restart as administrator')}
          </button>
        )}
      </div>
    </>
  );
}

const UPDATE_TEXT: Record<string, string> = {
  idle: 'Not checked yet.',
  checking: 'Checking for updates…',
  'up-to-date': 'FortiConnect is up to date.',
  error: 'The last check failed.',
};

function UpdatesSection({ s }: { s: SettingsT }) {
  const t = useT();
  const status = useUpdates((u) => u.status);
  const manual = useUpdates((u) => u.manual);
  const busy = manual || status?.state === 'checking';
  const version = status?.version ?? '';
  let text = status ? t(UPDATE_TEXT[status.state] ?? '') : '';
  if (status?.state === 'downloading') text = t('Downloading FortiConnect {version}: {percent}%', { version, percent: status.percent ?? 0 });
  if (status?.state === 'ready') text = t('FortiConnect {version} is downloaded. Restart to install it, or it installs when you quit.', { version });
  if (status?.state === 'available') text = t('FortiConnect {version} is available. macOS only updates signed apps in place, so download it from the release page.', { version });
  if (status?.state === 'disabled') text = status.message ?? t('Updates are not available in this build.');
  return (
    <div className="settings-section">
      <h3>{t('Updates')}</h3>
      {!status ? (
        <p className="muted">{t('Updates are part of the desktop app.')}</p>
      ) : (
        <>
          <div className="info-card">
            <RefreshCw size={18} className="text-accent" />
            <div className="flex-1">
              <strong>FortiConnect {status.currentVersion}</strong>
              <p className={`muted${status.state === 'error' ? ' text-danger' : ''}`}>
                {text}
                {status.state === 'error' && status.message ? ` ${status.message}` : ''}
              </p>
            </div>
          </div>
          <div className="input-with-btn">
            {status.state === 'ready' || status.state === 'available' ? (
              <button className="btn btn-primary" onClick={() => void useUpdates.getState().install()}>
                {status.state === 'ready' ? t('Restart and update') : t('Open the release page')}
              </button>
            ) : (
              <button className="btn" disabled={busy || status.state === 'disabled' || status.state === 'downloading'} onClick={() => void useUpdates.getState().check()}>
                {busy ? <LoaderCircle size={16} className="spin" /> : <RefreshCw size={16} />} {t('Check for updates')}
              </button>
            )}
          </div>
          <Toggle label={t('Check for updates automatically')} hint={t('At start and every 6 hours.')} checked={s.autoUpdate} onChange={(v) => save({ autoUpdate: v })} />
        </>
      )}
    </div>
  );
}
