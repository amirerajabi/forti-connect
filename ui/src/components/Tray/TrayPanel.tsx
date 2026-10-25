import { ClipboardPaste, LoaderCircle, Power } from 'lucide-react';
import { useEffect } from 'react';
import { api } from '../../api/client';
import { attempt, connectTo, pasteFromClipboard, toggleConnection } from '../../app/commands';
import { useT } from '../../i18n';
import { formatSpeed, gatewayLabel } from '../../lib/format';
import { getPlatform } from '../../platform';
import { useConnection } from '../../store/connection';
import { currentProfile, useProfiles } from '../../store/profiles';
import { DelayBadge, TypeTile } from '../common/visuals';

/**
 * The panel that opens from the tray icon (its own small window, loaded with #tray): connect and pick a profile.
 * Everything else is one click away in the main window.
 */
export function TrayPanel() {
  const t = useT();
  const connection = useConnection((s) => s.connection);
  const traffic = useConnection((s) => s.traffic);
  const testing = useConnection((s) => s.testing);
  const profiles = useProfiles((s) => s.profiles);
  const selectedId = useProfiles((s) => s.selectedId);
  const status = connection.status;
  const on = status === 'connected';
  const busy = status === 'connecting' || status === 'disconnecting';
  const current = currentProfile(profiles, connection.profileId, selectedId);

  // Escape closes the panel, like any flyout (unless a question is open: Escape cancels that first).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && !useConnection.getState().connection.prompt && getPlatform().hideTrayPanel();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className={`tray conn-${status}`}>
      <div className="tray-head">
        <button type="button" className="power power-sm" onClick={() => void toggleConnection()} disabled={status === 'disconnecting' || (!current && !on)} aria-pressed={on} aria-label={on ? t('Disconnect') : t('Connect')}>
          {busy ? <LoaderCircle size={24} className="spin" /> : <Power size={24} data-stroke />}
        </button>
        <div className="tray-status">
          <strong>{on && current ? t('Connected to {name}', { name: current.name }) : status === 'connecting' ? t('Connecting…') : t('Not connected')}</strong>
          <span className="muted tabular">
            {on ? `↓ ${formatSpeed(traffic.down)} · ↑ ${formatSpeed(traffic.up)}${connection.address ? ` · ${connection.address}` : ''}` : current ? current.name : t('Add a profile first')}
          </span>
        </div>
      </div>

      <div className="tray-list" role="listbox" aria-label={t('Profiles')}>
        {profiles.map((p) => {
          const chosen = p.id === (connection.profileId ?? selectedId);
          return (
            <button
              key={p.id}
              type="button"
              role="option"
              aria-selected={chosen}
              className={`tray-row${chosen ? ' chosen' : ''}`}
              onClick={() => (on || busy ? void connectTo(p.id) : void attempt(() => api.select(p.id)))}
              title={`${gatewayLabel(p)} · ${on ? t('Switch to this profile') : t('Use this profile')}`}
            >
              <TypeTile type={p.type} size="sm" />
              <span className="tray-row-name ellipsis">{p.name}</span>
              <DelayBadge profile={p} testing={testing} />
            </button>
          );
        })}
        {profiles.length === 0 && <p className="muted tray-empty">{t('No profiles yet.')}</p>}
      </div>

      <div className="tray-foot">
        <button type="button" className="btn btn-xs" onClick={() => getPlatform().showMainWindow()}>
          {t('Open FortiConnect')}
        </button>
        <button type="button" className="icon-btn sm" title={t('Paste profile link')} aria-label={t('Paste profile link')} onClick={() => void pasteFromClipboard()}>
          <ClipboardPaste size={16} />
        </button>
        <div className="flex-1" />
        <button type="button" className="btn btn-xs btn-ghost" onClick={() => getPlatform().quitApp()}>
          {t('Quit')}
        </button>
      </div>
    </div>
  );
}
