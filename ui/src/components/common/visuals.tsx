import type { Profile, VpnType } from '../../../../shared/protocol';
import { displayShortcut, shortcutParts } from '../../app/keys';
import { t } from '../../i18n';
import { delayText, delayTone, typeLabel } from '../../lib/format';

/** The FortiConnect mark: a navy tile, a shield and a lit keyhole (same artwork as the app icon). */
export function BrandMark({ size = 18 }: { size?: number }) {
  return (
    <svg className="brand-mark-svg" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="bm-tile" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="var(--brand-mark-tile-top)" />
          <stop offset="1" stopColor="var(--brand-mark-tile-bottom)" />
        </linearGradient>
        <linearGradient id="bm-lit" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--brand-mark-lit-start)" />
          <stop offset="1" stopColor="var(--brand-mark-lit-end)" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="7" fill="url(#bm-tile)" />
      <path d="M16 6 L24 9 V15.5 C24 20.5 20.6 24.2 16 26 C11.4 24.2 8 20.5 8 15.5 V9 Z" fill="none" stroke="var(--brand-mark-row)" strokeWidth="2" strokeLinejoin="round" />
      <circle cx="16" cy="14.5" r="2.6" fill="url(#bm-lit)" />
      <rect x="14.9" y="15.5" width="2.2" height="5" rx="1" fill="url(#bm-lit)" />
    </svg>
  );
}

export function Kbd({ shortcut }: { shortcut?: string }) {
  if (!shortcut) return null;
  return (
    // Key combinations read left to right in every language ("Ctrl K", not "K Ctrl").
    <span className="kbd-group" dir="ltr" aria-label={displayShortcut(shortcut)}>
      {shortcutParts(shortcut).map((k, i) => (
        <kbd key={i}>{k}</kbd>
      ))}
    </span>
  );
}

/** Gateway check time in ms, coloured: green fast, amber slower, red no answer. */
export function DelayBadge({ profile, testing }: { profile: Pick<Profile, 'delay' | 'type'>; testing?: boolean }) {
  if (testing && profile.delay === null) return <span className="delay delay-none">…</span>;
  const tone = delayTone(profile.delay);
  const title = profile.delay === null ? 'Not checked yet' : profile.type === 'ssl' ? 'Time to reach the gateway (TLS handshake)' : 'Time to look up the gateway';
  return (
    <span className={`delay delay-${tone}`} title={t(title)}>
      {delayText(profile.delay, t)}
    </span>
  );
}

/** "SSL-VPN" / "IPsec" outlined badge. */
export function TypeBadge({ type }: { type: VpnType }) {
  return <span className={`proto proto-${type}`}>{typeLabel(type)}</span>;
}

/** A small tile with the profile's kind ("SSL" / "IPs"), the first thing the eye finds on a card. */
export function TypeTile({ type, size = 'md' }: { type: VpnType; size?: 'sm' | 'md' }) {
  return (
    <span className={`country country-${size} tile-${type}`} aria-hidden="true">
      {type === 'ssl' ? 'SSL' : 'IPs'}
    </span>
  );
}
