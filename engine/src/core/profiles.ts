// Profiles from the UI (or a hand-edited file, or a link) made valid, and forticonnect:// links in and out. A link
// carries everything about a profile except its secrets, so it can be sent to colleagues:
//   forticonnect://vpn.example.com:10443?type=ssl&user=amir&realm=staff#Office
//   forticonnect://gw.example.com?type=ipsec&ike=ikev1&user=amir&am=1&id=dialup#Branch
import type { IkeMode, ProfileConfig, ProfileInput, VpnType } from '../../../shared/protocol';
import { clamp } from './util';

const IKE: IkeMode[] = ['ikev1', 'ikev2', 'l2tp'];
const PIN = /^pin-sha256:[A-Za-z0-9+/]{43}=$/;

/** "vpn.example.com", "10.1.2.3", "[2001:db8::1]" (also pasted as https://vpn.example.com:10443/realm). */
function host(v: unknown): string {
  const s = typeof v === 'string' ? v.trim() : '';
  return /^[A-Za-z0-9.-]{1,253}$/.test(s) || /^\[?[0-9A-Fa-f:.]+\]?$/.test(s) ? s.replace(/^\[|\]$/g, '') : '';
}

function text(v: unknown, max: number): string {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

/** "10.0.0.0/8", "192.168.1.0/24" or a single address. */
export function validRoute(r: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(r);
  return !!m && m.slice(1, 5).every((x) => Number(x) <= 255) && (m[5] === undefined || Number(m[5]) <= 32);
}

/**
 * The connection details of a profile, each field checked. A gateway pasted as a portal address
 * ("https://vpn.example.com:10443/staff") fills the port and realm too. Throws with a message for the user.
 */
export function normalizeConfig(p: Partial<ProfileConfig>, base?: ProfileConfig): ProfileConfig {
  const type: VpnType = p.type === 'ipsec' || p.type === 'ssl' ? p.type : (base?.type ?? 'ssl');
  let gatewayIn = p.gateway ?? base?.gateway ?? '';
  let port = typeof p.port === 'number' ? p.port : (base?.port ?? 443);
  let realm = p.realm ?? base?.realm;
  const typed = String(gatewayIn).trim();
  // "https://host:port/realm", or the same without the scheme ("host:10443", "host/realm"); a bare IPv6 address is not.
  const portal = /^https?:\/\//i.test(typed) || /^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?\/|^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):\d{1,5}$/.test(typed);
  if (portal) {
    const u = new URL(/^https?:\/\//i.test(typed) ? typed : `https://${typed}`);
    gatewayIn = u.hostname;
    if (u.port) port = Number(u.port);
    const path = u.pathname.replace(/^\/+|\/+$/g, '');
    if (path && !path.startsWith('remote')) realm = path;
  }
  const gateway = host(gatewayIn);
  if (!gateway) throw new Error('Enter the address of the FortiGate (a host name or IP address)');
  const c: ProfileConfig = {
    type,
    gateway,
    port: Number.isFinite(port) ? clamp(Math.round(port), 1, 65535) : 443,
    username: text(p.username ?? base?.username, 200),
  };
  if (type === 'ssl') {
    const r = text(realm, 100).replace(/^\/+/, '');
    if (r) c.realm = r;
    const pin = text(p.trustedCert ?? base?.trustedCert, 100);
    if (pin && !PIN.test(pin)) throw new Error('The trusted certificate must look like pin-sha256:… (44 characters after the colon)');
    if (pin) c.trustedCert = pin;
    const cert = text(p.clientCert ?? base?.clientCert, 1000);
    if (cert) c.clientCert = cert;
  } else {
    c.ike = IKE.includes(p.ike as IkeMode) ? (p.ike as IkeMode) : (base?.ike ?? 'ikev1');
    if (c.ike === 'ikev1') c.aggressive = typeof p.aggressive === 'boolean' ? p.aggressive : (base?.aggressive ?? true);
    // The FortiGate picks the dial-up tunnel by this ID (IKEv1 peer ID, IKEv2 IDi; FortiClient's "Local ID").
    if (c.ike !== 'l2tp') {
      const id = text(p.localId ?? base?.localId, 200);
      if (id) c.localId = id;
    }
    const routes = (Array.isArray(p.routes) ? p.routes : (base?.routes ?? [])).map((r) => String(r).trim()).filter(Boolean);
    const bad = routes.find((r) => !validRoute(r));
    if (bad) throw new Error(`"${bad}" is not a network (write it like 10.0.0.0/8)`);
    if (routes.length) c.routes = [...new Set(routes)].slice(0, 100);
  }
  return c;
}

export function normalizeInput(p: Partial<ProfileInput>, base?: ProfileConfig): ProfileConfig & { name: string } {
  const config = normalizeConfig(p, base);
  return { ...config, name: text(p.name, 100) || config.gateway };
}

/** Identity of a profile's connection details: the same profile pasted twice is not added twice. */
export function profileKey(c: ProfileConfig): string {
  return [c.type, c.gateway.toLowerCase(), c.type === 'ssl' ? c.port : '', c.username.toLowerCase(), c.realm ?? '', c.ike ?? ''].join('|');
}

export function buildLink(name: string, c: ProfileConfig): string {
  const q = new URLSearchParams({ type: c.type });
  if (c.username) q.set('user', c.username);
  if (c.type === 'ssl') {
    if (c.realm) q.set('realm', c.realm);
    if (c.trustedCert) q.set('cert', c.trustedCert);
  } else {
    q.set('ike', c.ike ?? 'ikev1');
    if (c.ike === 'ikev1') q.set('am', c.aggressive ? '1' : '0');
    if (c.localId) q.set('id', c.localId);
    if (c.routes?.length) q.set('routes', c.routes.join(','));
  }
  const h = c.gateway.includes(':') ? `[${c.gateway}]` : c.gateway;
  const port = c.type === 'ssl' && c.port !== 443 ? `:${c.port}` : '';
  return `forticonnect://${h}${port}?${q.toString()}#${encodeURIComponent(name)}`;
}

export interface ParsedLink {
  name: string;
  config: ProfileConfig;
}

export function parseLink(raw: string): ParsedLink | null {
  const s = raw.trim();
  if (!/^forticonnect:\/\//i.test(s)) return null;
  try {
    // Parsed as https so the URL class reads host, port and IPv6 brackets the standard way.
    const u = new URL(`https://${s.slice('forticonnect://'.length)}`);
    const q = u.searchParams;
    const type = q.get('type') === 'ipsec' ? 'ipsec' : 'ssl';
    const config = normalizeConfig({
      type,
      gateway: u.hostname.replace(/^\[|\]$/g, ''),
      port: u.port ? Number(u.port) : 443,
      username: q.get('user') ?? '',
      realm: q.get('realm') ?? undefined,
      trustedCert: q.get('cert') ?? undefined,
      ike: (q.get('ike') as IkeMode | null) ?? undefined,
      aggressive: q.has('am') ? q.get('am') === '1' : undefined,
      localId: q.get('id') ?? undefined,
      routes: q.get('routes')?.split(',') ?? undefined,
    });
    const name = decodeURIComponent(u.hash.replace(/^#/, '')).trim() || config.gateway;
    return { name: name.slice(0, 100), config };
  } catch {
    return null;
  }
}

/** Every forticonnect:// link in `text`, one per line (or separated by spaces). */
export function parseLinks(text: string): { links: ParsedLink[]; skipped: number } {
  const links: ParsedLink[] = [];
  let skipped = 0;
  for (const part of text.split(/\s+/)) {
    if (!part) continue;
    const l = parseLink(part);
    if (l) links.push(l);
    else skipped++;
  }
  return { links, skipped };
}
