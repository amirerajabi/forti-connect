import { ArrowDownWideNarrow, ClipboardCopy, ClipboardPaste, Copy, Gauge, LoaderCircle, MoreHorizontal, Pencil, Plus, Power, Search, Trash2, X } from 'lucide-react';
import { useMemo, type MouseEvent } from 'react';
import type { Profile } from '../../../shared/protocol';
import { api } from '../api/client';
import { attempt, connectTo, copyProfileLink, deleteProfile, duplicateProfile, runCommand, testProfiles } from '../app/commands';
import { showMenuBelow, useMenu, type MenuItem } from '../components/common/Menu';
import { DelayBadge, TypeBadge, TypeTile } from '../components/common/visuals';
import { useT } from '../i18n';
import { gatewayLabel } from '../lib/format';
import { useConnection } from '../store/connection';
import { useProfiles, visibleProfiles, type TypeFilter } from '../store/profiles';
import { useUi } from '../store/ui';

function profileMenu(p: Profile, t: (x: string) => string): MenuItem[] {
  return [
    { label: t('Connect'), icon: Power, run: () => connectTo(p.id) },
    { label: t('Check gateway'), icon: Gauge, run: () => testProfiles([p.id]) },
    'separator',
    { label: t('Edit profile…'), icon: Pencil, run: () => useUi.getState().set({ profileDialog: { id: p.id } }) },
    { label: t('Duplicate profile'), icon: Copy, run: () => duplicateProfile(p.id) },
    { label: t('Copy profile link'), icon: ClipboardCopy, run: () => copyProfileLink(p.id) },
    'separator',
    { label: t('Delete profile'), icon: Trash2, danger: true, run: () => deleteProfile(p.id) },
  ];
}

const FILTERS: { f: TypeFilter; label: string }[] = [
  { f: 'all', label: 'All' },
  { f: 'ssl', label: 'SSL-VPN' },
  { f: 'ipsec', label: 'IPsec' },
];

/** Every profile as a card: click chooses the one Connect uses, double-click connects, ⋯ has the rest. */
export function ProfilesPage() {
  const t = useT();
  const profiles = useProfiles((s) => s.profiles);
  const filter = useProfiles((s) => s.filter);
  const query = useProfiles((s) => s.query);
  const sort = useProfiles((s) => s.sort);
  const selectedId = useProfiles((s) => s.selectedId);
  const connection = useConnection((s) => s.connection);
  const testing = useConnection((s) => s.testing);
  const rows = useMemo(() => visibleProfiles({ profiles, filter, query, sort }), [profiles, filter, query, sort]);

  const pick = (p: Profile) => {
    if (useProfiles.getState().selectedId !== p.id) void attempt(() => api.select(p.id));
  };
  const menuAt = (e: MouseEvent, p: Profile) => {
    e.preventDefault();
    pick(p);
    useMenu.getState().show(e.clientX, e.clientY, profileMenu(p, t));
  };

  return (
    <div className="page profiles-page">
      <header className="page-head">
        <h1>{t('Profiles')}</h1>
        <div className="flex-1" />
        <button className="btn" onClick={() => runCommand('profile.paste')} title={t('Paste profile link')}>
          <ClipboardPaste size={16} /> {t('Paste')}
        </button>
        <button className="btn btn-primary" onClick={() => runCommand('profile.add')}>
          <Plus size={16} /> {t('Add profile')}
        </button>
      </header>

      {profiles.length === 0 ? (
        <EmptyProfiles />
      ) : (
        <>
          <div className="profiles-bar">
            <div className="chips" role="tablist" aria-label={t('Kinds')}>
              {FILTERS.map((g) => (
                <button key={g.f} role="tab" aria-selected={filter === g.f} className={`chip${filter === g.f ? ' on' : ''}`} onClick={() => useProfiles.getState().setFilter(g.f)}>
                  {t(g.label)} <span className="chip-count">{g.f === 'all' ? profiles.length : profiles.filter((p) => p.type === g.f).length}</span>
                </button>
              ))}
            </div>
            <div className="flex-1" />
            <label className="search-box">
              <Search size={14} />
              <span className="sr-only">{t('Search profiles')}</span>
              <input id="profile-search" className="input borderless" placeholder={t('Search profiles')} value={query} onChange={(e) => useProfiles.getState().setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Escape' && useProfiles.getState().setQuery('')} />
              {query && (
                <button type="button" className="icon-btn xs" aria-label={t('Clear search')} onClick={() => useProfiles.getState().setQuery('')}>
                  <X size={14} />
                </button>
              )}
            </label>
            <button className="btn" disabled={testing} onClick={() => runCommand('profile.test')} title={t('Check gateways')}>
              {testing ? <LoaderCircle size={16} className="spin" /> : <Gauge size={16} />} {t('Check')}
            </button>
            <button className={`btn${sort === 'delay' ? ' on' : ''}`} aria-pressed={sort === 'delay'} onClick={() => runCommand('profile.sortDelay')} title={t('Sort by gateway time')}>
              <ArrowDownWideNarrow size={16} /> {t('Fastest first')}
            </button>
          </div>

          <div className="cards">
            {rows.map((p) => {
              const live = connection.profileId === p.id && connection.status !== 'disconnected';
              const selected = p.id === selectedId;
              return (
                <div key={p.id} className={`card profile-card${selected ? ' selected' : ''}${live ? ` live live-${connection.status}` : ''}`} onContextMenu={(e) => menuAt(e, p)}>
                  <button type="button" className="profile-card-main" onClick={() => pick(p)} onDoubleClick={() => void connectTo(p.id)} aria-pressed={selected} title={p.username ? `${p.username} @ ${gatewayLabel(p)}` : gatewayLabel(p)}>
                    <TypeTile type={p.type} />
                    <span className="profile-card-text">
                      <span className="profile-card-name ellipsis">{p.name}</span>
                      <span className="profile-card-kind">
                        <TypeBadge type={p.type} />
                        <span className="ellipsis" dir="ltr">
                          {gatewayLabel(p)}
                        </span>
                      </span>
                    </span>
                    <DelayBadge profile={p} testing={testing} />
                  </button>
                  <div className="profile-card-actions">
                    {live ? (
                      <span className="live-tag">{connection.status === 'connected' ? t('Connected') : t('Connecting…')}</span>
                    ) : (
                      selected && (
                        <button type="button" className="btn btn-xs btn-primary" onClick={() => void connectTo(p.id)}>
                          <Power size={14} /> {t('Connect')}
                        </button>
                      )
                    )}
                    <button type="button" className="icon-btn sm" aria-label={t('More')} title={t('More')} onClick={(e) => (pick(p), showMenuBelow(e.currentTarget, profileMenu(p, t)))}>
                      <MoreHorizontal size={16} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
          {rows.length === 0 && <p className="muted list-note">{t('No profiles match “{query}”.', { query })}</p>}
        </>
      )}
    </div>
  );
}

function EmptyProfiles() {
  const t = useT();
  return (
    <div className="empty-state">
      <h2>{t('Add your first profile')}</h2>
      <p className="muted">{t('A profile is one FortiGate: its address, your user name, and whether it uses SSL-VPN or IPsec. Your administrator can tell you which.')}</p>
      <div className="empty-actions">
        <button className="btn btn-primary" onClick={() => runCommand('profile.add')}>
          <Plus size={16} /> {t('Add a profile')}
        </button>
        <button className="btn" onClick={() => runCommand('profile.paste')}>
          <ClipboardPaste size={16} /> {t('Paste a forticonnect:// link')}
        </button>
      </div>
      <p className="muted empty-tip">{t('Ctrl+V anywhere in the window imports a profile link you copied.')}</p>
    </div>
  );
}
