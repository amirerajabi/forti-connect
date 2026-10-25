import type { IkeMode, Profile, VpnType } from '../../../shared/protocol';
import { language, t } from '../i18n';

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

export function formatBytes(n: number | null | undefined, digits = 1): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  if (n < 1024) return `${Math.round(n)} B`;
  let i = 0;
  let v = n;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : digits)} ${UNITS[i]}`;
}

export function formatSpeed(bps: number): string {
  if (!bps || bps < 1) return '0 B/s';
  return `${formatBytes(bps)}/s`;
}

/** "1:02:03" or "02:03" */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = String(m).padStart(2, '0');
  const ss = String(s).padStart(2, '0');
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

/** "today 10:39", "12 Oct 10:39"; in Persian with the Persian calendar and digits, as people there read dates. */
export function formatDate(ms: number | null | undefined): string {
  if (!ms) return t('never');
  const locale = language() === 'fa' ? 'fa-IR' : undefined;
  const d = new Date(ms);
  const sameDay = d.toDateString() === new Date().toDateString();
  const time = d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  return sameDay ? t('today {time}', { time }) : `${d.toLocaleDateString(locale, { day: 'numeric', month: 'short' })} ${time}`;
}

/** Product words: the same in every language. */
const TYPE_LABEL: Record<VpnType, string> = { ssl: 'SSL-VPN', ipsec: 'IPsec' };

export function typeLabel(type: VpnType): string {
  return TYPE_LABEL[type];
}

const IKE_LABEL: Record<IkeMode, string> = { ikev1: 'IKEv1', ikev2: 'IKEv2', l2tp: 'L2TP' };

export function ikeLabel(mode: IkeMode): string {
  return IKE_LABEL[mode];
}

/** "vpn.example.com:10443", "gw.example.com · IKEv1" */
export function gatewayLabel(p: Pick<Profile, 'type' | 'gateway' | 'port' | 'ike'>): string {
  if (p.type === 'ssl') return p.port && p.port !== 443 ? `${p.gateway}:${p.port}` : p.gateway;
  return `${p.gateway} · ${ikeLabel(p.ike ?? 'ikev1')}`;
}

export type DelayTone = 'good' | 'ok' | 'slow' | 'fail' | 'none';

export function delayTone(delay: number | null | undefined): DelayTone {
  if (delay === null || delay === undefined) return 'none';
  if (delay < 0) return 'fail';
  if (delay < 300) return 'good';
  if (delay < 800) return 'ok';
  return 'slow';
}

export function delayText(delay: number | null | undefined, tr: (s: string) => string = (s) => s): string {
  if (delay === null || delay === undefined) return '—';
  if (delay < 0) return tr('No answer');
  return `${delay} ms`;
}
