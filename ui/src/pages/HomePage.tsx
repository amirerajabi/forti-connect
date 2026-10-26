import { ArrowDown, ArrowUp, ChevronRight, Clock, LoaderCircle, MapPin, Power, ShieldAlert, ShieldCheck, Wrench } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { Profile } from '../../../shared/protocol';
import { attempt, runCommand, toggleConnection } from '../app/commands';
import { Sparkline } from '../components/common/Sparkline';
import { DelayBadge, TypeBadge, TypeTile } from '../components/common/visuals';
import { useT } from '../i18n';
import { formatBytes, formatDuration, formatSpeed, gatewayLabel } from '../lib/format';
import { getPlatform } from '../platform';
import { useConnection } from '../store/connection';
import { useEngine } from '../store/engine';
import { currentProfile, useProfiles } from '../store/profiles';
import { useUi } from '../store/ui';

const TITLE = { disconnected: 'Not connected', connecting: 'Connecting…', connected: 'Connected', disconnecting: 'Disconnecting…' };

/** Re-render every second while `on`, for the connection timer. */
function useTick(on: boolean): void {
  const [, setN] = useState(0);
  useEffect(() => {
    if (!on) return;
    const id = setInterval(() => setN((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [on]);
}

/** The page most people only ever need: one button, the profile it uses, and how the tunnel is doing. */
export function HomePage() {
  const t = useT();
  const connection = useConnection((s) => s.connection);
  const traffic = useConnection((s) => s.traffic);
  const history = useConnection((s) => s.history);
  const testing = useConnection((s) => s.testing);
  const profiles = useProfiles((s) => s.profiles);
  const selectedId = useProfiles((s) => s.selectedId);
  const settings = useEngine((s) => s.settings);
  const status = connection.status;
  const on = status === 'connected';
  const busy = status === 'connecting' || status === 'disconnecting';
  useTick(on);

  const profile = currentProfile(profiles, connection.profileId, selectedId);

  return (
    <div className={`page home conn-${status}`}>
      <section className="home-hero" aria-label={t('Connection')}>
        <button
          type="button"
          className="power"
          onClick={() => void toggleConnection()}
          disabled={status === 'disconnecting' || (!profile && !on)}
          aria-pressed={on}
          aria-label={on ? t('Disconnect') : t('Connect')}
          title={on ? t('Disconnect') : profile ? t('Connect to {name}', { name: profile.name }) : t('Add a profile first')}
        >
          {busy ? <LoaderCircle size={44} className="spin" /> : <Power size={44} data-stroke />}
        </button>
        <div className="home-status">
          <span className="conn-dot" aria-hidden="true" />
          <h1>{t(TITLE[status])}</h1>
          {on && connection.since && <span className="conn-time tabular">{formatDuration(Date.now() - connection.since)}</span>}
        </div>
        {connection.waitingForNetwork ? (
          <span className="muted">{t('Waiting for the network to come back…')}</span>
        ) : (
          status === 'connecting' && !!connection.retry && <span className="muted">{t('Reconnecting, attempt {n} of 5…', { n: connection.retry })}</span>
        )}

        {profile ? (
          <button type="button" className="profile-pick" onClick={() => useUi.getState().go('profiles')} title={t('Choose another profile')}>
            <TypeTile type={profile.type} />
            <span className="profile-pick-text">
              <span className="profile-pick-name ellipsis">{profile.name}</span>
              <span className="profile-pick-kind">
                <TypeBadge type={profile.type} /> <span className="ellipsis" dir="ltr">{gatewayLabel(profile)}</span>
              </span>
            </span>
            <DelayBadge profile={profile} testing={testing} />
            <ChevronRight size={16} className="muted flip-rtl" />
          </button>
        ) : (
          <div className="home-empty">
            <p className="muted">{t('Add the FortiGate you connect to: its address, your user name, and SSL-VPN or IPsec.')}</p>
            <div className="home-empty-actions">
              <button className="btn btn-primary" onClick={() => runCommand('profile.add')}>
                {t('Add a profile')}
              </button>
              <button className="btn" onClick={() => runCommand('profile.paste')}>
                {t('Paste a forticonnect:// link')}
              </button>
            </div>
          </div>
        )}

        {connection.error && status === 'disconnected' && <div className="conn-error">{connection.error}</div>}
        {profile && <BackendNotice profile={profile} />}
      </section>

      <section className="home-stats card" aria-label={t('Traffic')}>
        <Sparkline down={history.map((h) => h.down)} up={history.map((h) => h.up)} active={on} />
        <div className="figures">
          <Figure icon={ArrowDown} label={t('Download')} value={on ? formatSpeed(traffic.down) : '—'} sub={on ? formatBytes(traffic.totalDown) : ''} tone="down" />
          <Figure icon={ArrowUp} label={t('Upload')} value={on ? formatSpeed(traffic.up) : '—'} sub={on ? formatBytes(traffic.totalUp) : ''} tone="up" />
          <Figure icon={MapPin} label={t('VPN address')} value={on ? (connection.address ?? '—') : '—'} sub={on ? (connection.device ?? '') : ''} ltr />
          <Figure icon={Clock} label={t('Connected for')} value={on && connection.since ? formatDuration(Date.now() - connection.since) : '—'} />
        </div>
      </section>

      {settings && (
        <section className="home-switches" aria-label={t('Quick settings')}>
          <div className="switch-group">
            <label className="toggle-inline">
              <input type="checkbox" className="switch" checked={settings.reconnect} onChange={(e) => void attempt(() => useEngine.getState().updateSettings({ reconnect: e.target.checked }))} />
              <span className="switch-label">{t('Reconnect automatically')}</span>
            </label>
            <span className="muted switch-note">{t('When the tunnel drops, up to 5 times. A code the gateway wants is asked again.')}</span>
          </div>
          {profile?.type === 'ssl' && (
            <div className="switch-group">
              <span className="switch-label">{t('Certificate')}</span>
              <span className="muted switch-note">
                {profile.trustedCert ? t('Pinned: this profile only accepts the certificate you trusted.') : t('Checked against the certificates this computer trusts.')}
              </span>
              <button type="button" className="link-btn" onClick={() => useUi.getState().set({ profileDialog: { id: profile.id } })}>
                {t('Edit profile')}
              </button>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

/** What stands between this profile and a connection on this computer: a missing VPN program, or missing rights. */
function BackendNotice({ profile }: { profile: Profile }) {
  const t = useT();
  const backends = useEngine((s) => s.backends);
  const backend = profile.type === 'ssl' ? backends.ssl : backends.ipsec;
  if (!backend.available) {
    return (
      <div className="notice warning backend-notice">
        <Wrench size={16} />
        <span className="flex-1">
          {/* Found but not usable (too old, not OpenConnect): the engine's note says why. */}
          {backend.path && backend.note
            ? backend.note
            : profile.type === 'ssl'
              ? t('OpenConnect (which FortiConnect uses for SSL-VPN) was not found on this computer.')
              : t('No IPsec client was found on this computer.')}
        </span>
        <button className="btn btn-xs" onClick={() => useUi.getState().go('settings', 'programs')}>
          {t('VPN programs')}
        </button>
      </div>
    );
  }
  const helper = backends.helper;
  if (profile.type === 'ssl' && backends.platform === 'win32' && !backends.elevated && helper?.state !== 'running') {
    const outdated = helper?.state === 'outdated';
    return (
      <div className={`notice${outdated ? '' : ' warning'} backend-notice`}>
        <ShieldAlert size={16} />
        <span className="flex-1">
          {outdated
            ? t('A newer VPN helper comes with this FortiConnect. Update it (Windows asks for administrator rights once).')
            : helper?.state === 'stopped'
              ? t('The VPN helper is installed but not running. It starts with Windows; install it again if it stays stopped.')
              : t('SSL-VPN on Windows uses the FortiConnect VPN helper. It installs itself the first time you connect: Windows asks for administrator rights once.')}
        </span>
        <button className="btn btn-xs btn-primary" disabled={!!helper?.busy} onClick={() => runCommand('helper.install')}>
          {helper?.busy ? <LoaderCircle size={14} className="spin" /> : <ShieldCheck size={14} />} {outdated ? t('Update the VPN helper') : t('Install the VPN helper')}
        </button>
        {!outdated && getPlatform().kind === 'electron' && (
          <button className="btn btn-xs" onClick={() => runCommand('app.relaunchAdmin')}>
            {t('Restart as administrator')}
          </button>
        )}
      </div>
    );
  }
  if (profile.type === 'ipsec' && backend.modes && !backend.modes.includes(profile.ike ?? 'ikev1')) {
    return (
      <div className="notice warning backend-notice">
        <ShieldAlert size={16} />
        <span className="flex-1">{t('The IPsec client on this computer cannot do this profile’s IKE mode. Edit the profile to choose another.')}</span>
        <button className="btn btn-xs" onClick={() => useUi.getState().set({ profileDialog: { id: profile.id } })}>
          {t('Edit profile')}
        </button>
      </div>
    );
  }
  return null;
}

function Figure({ icon: Icon, label, value, sub, tone, ltr }: { icon: typeof Clock; label: string; value: string; sub?: string; tone?: string; ltr?: boolean }) {
  return (
    <div className={`figure${tone ? ` figure-${tone}` : ''}`}>
      <span className="figure-label">
        <Icon size={12} />
        {label}
      </span>
      <span className="figure-value tabular selectable" dir={ltr ? 'ltr' : undefined}>
        {value}
      </span>
      <span className="figure-sub tabular" dir={ltr ? 'ltr' : undefined}>
        {sub || ' '}
      </span>
    </div>
  );
}
