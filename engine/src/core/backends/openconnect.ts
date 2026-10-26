// SSL-VPN through OpenConnect (9.0 or newer has --protocol=fortinet): finding it, its command line, and reading what
// it prints. It needs administrator / root rights to create the tunnel adapter: on Windows FortiConnect itself must
// run elevated; on macOS and Linux it runs under sudo, which asks for the computer password through the UI.
import * as path from 'node:path';
import type { BackendInfo, ProfileConfig } from '../../../../shared/protocol';
import { commandOutput, findProgram, firstFile, type Platform } from '../system';
import type { Dialect, PromptClass } from './process';

export const ADMIN_PROMPT = 'FORTICONNECT_ADMIN:';
/** The adapter OpenConnect creates on Windows (wintun) and Linux (tun), so traffic counters can find it. */
export const ADAPTER = { win32: 'FortiConnect', linux: 'fcvpn0' } as const;

function exe(platform: Platform): string {
  return platform === 'win32' ? 'openconnect.exe' : 'openconnect';
}

/** Where OpenConnect is usually installed, after the user's own choice and a copy shipped with FortiConnect. */
export function openconnectCandidates(configured: string, dataDir: string, platform: Platform): string[] {
  const bundled = process.env.FORTICONNECT_BUNDLED_CORE;
  const own = [configured, path.join(dataDir, 'core', exe(platform)), bundled ? path.join(bundled, exe(platform)) : ''];
  if (platform === 'win32') {
    const pf = process.env.ProgramFiles ?? 'C:\\Program Files';
    return [...own, `${pf}\\OpenConnect\\openconnect.exe`, `${pf}\\OpenConnect-GUI\\openconnect.exe`, 'C:\\msys64\\ucrt64\\bin\\openconnect.exe', 'C:\\msys64\\mingw64\\bin\\openconnect.exe'];
  }
  if (platform === 'darwin') return [...own, '/opt/homebrew/bin/openconnect', '/usr/local/bin/openconnect', '/opt/homebrew/sbin/openconnect', '/usr/local/sbin/openconnect'];
  return [...own, '/usr/sbin/openconnect', '/usr/bin/openconnect', '/usr/local/sbin/openconnect', '/usr/local/bin/openconnect'];
}

/** Read `openconnect --version`: its version and whether it speaks Fortinet's protocol. */
export function parseVersion(out: string): { version: string | null; fortinet: boolean } {
  return {
    version: /OpenConnect version v?([\w.+-]+)/i.exec(out)?.[1] ?? null,
    fortinet: /Supported protocols:.*\bfortinet\b/i.test(out),
  };
}

export async function detectOpenconnect(configured: string, dataDir: string, platform: Platform, elevated: boolean): Promise<BackendInfo> {
  const p = findProgram('openconnect', openconnectCandidates(configured, dataDir, platform));
  if (!p) return { available: false, kind: 'openconnect', path: null, version: null, note: 'OpenConnect is not installed' };
  const { version, fortinet } = parseVersion(await commandOutput(p, ['--version']));
  if (!version) return { available: false, kind: 'openconnect', path: p, version: null, note: 'This file does not look like OpenConnect' };
  if (!fortinet) return { available: false, kind: 'openconnect', path: p, version, note: 'This OpenConnect is too old for FortiGate SSL-VPN (it needs 9.0 or newer)' };
  // On Windows the note depends on the VPN helper too: detectBackends adds it.
  const note = platform !== 'win32' && !elevated ? 'Asks for your computer password when connecting (sudo)' : undefined;
  return { available: true, kind: 'openconnect', path: p, version, note };
}

/** The vpnc-script to pass: the chosen one, else (Windows) the one shipped next to openconnect.exe. */
export function findVpncScript(configured: string, openconnectPath: string, platform: Platform): string | null {
  if (configured) return configured;
  if (platform !== 'win32') return null;
  const dir = path.dirname(openconnectPath);
  return firstFile([path.join(dir, 'vpnc-script-win.js'), path.join(dir, 'vpnc-script.js'), path.join(dir, '..', 'etc', 'vpnc', 'vpnc-script.js')]);
}

export interface OpenconnectOptions {
  profile: ProfileConfig;
  platform: Platform;
  verbose: boolean;
  vpncScript: string | null;
}

export function openconnectArgs(o: OpenconnectOptions): string[] {
  const p = o.profile;
  // Straight to the gateway like FortiClient: OpenConnect would otherwise follow HTTPS_PROXY, often another app's local
  // proxy (RayConnect, v2rayN), and the VPN would break as soon as that app disconnects.
  const args = ['--protocol=fortinet', '--no-proxy'];
  if (p.username) args.push('--user', p.username);
  if (p.trustedCert) args.push('--servercert', p.trustedCert);
  if (p.clientCert) args.push('--certificate', p.clientCert);
  if (o.platform === 'win32' || o.platform === 'linux') args.push('--interface', ADAPTER[o.platform]);
  if (o.vpncScript) args.push('--script', o.vpncScript);
  if (o.verbose) args.push('--verbose');
  // OpenConnect reads the realm from the URL path, like the portal address https://vpn.example.com/realm.
  const host = p.gateway.includes(':') ? `[${p.gateway}]` : p.gateway;
  args.push(`https://${host}:${p.port}${p.realm ? `/${encodeURI(p.realm)}` : ''}`);
  return args;
}

/** macOS and Linux without root: through sudo, which reads the computer password from stdin after our marker. */
export function withSudo(file: string, args: string[], platform: Platform, elevated: boolean): { file: string; args: string[] } {
  if (platform === 'win32' || elevated) return { file, args };
  return { file: 'sudo', args: ['-S', '-p', ADMIN_PROMPT, '--', file, ...args] };
}

export const openconnectDialect: Dialect = {
  name: 'OpenConnect',
  classify(text: string): PromptClass | null {
    const t = text.trim();
    if (t.includes(ADMIN_PROMPT)) return 'admin';
    if (/Enter 'yes' to accept/i.test(t)) return 'cert';
    if (!/[:?]$/.test(t)) return null;
    if (/^user ?name:?$/i.test(t) || /^login:?$/i.test(t)) return 'username';
    if (/password/i.test(t) && !/\b(new|confirm|again|repeat)\b/i.test(t)) return 'password';
    if (/token|code|otp|passcode|verification|one.time|challenge|\bpin\b/i.test(t)) return 'otp';
    return 'text';
  },
  progress(line: string) {
    // "Connected tun0 as 10.212.134.200, using SSL" (older) or "Configured as 10.212.134.200, with SSL connected" (9.x).
    const m = /(?:Connected (?:(\S+) )?as|Configured as) ([0-9A-Fa-f.:]+[0-9A-Fa-f])/.exec(line);
    if (m) return { up: true, address: m[2], device: m[1] };
    return null;
  },
  isError(line: string): boolean {
    // OpenConnect prints the verify failure even when the certificate is pinned with --servercert and then accepted.
    return /fail|error|unable|refused|denied|invalid|cannot|could not/i.test(line) && !/DTLS|Server certificate verify failed/i.test(line);
  },
  level: (line) => (/Server certificate verify failed/i.test(line) ? 'info' : undefined),
  adminRefused: (line) => /Sorry, try again/i.test(line),
  // FortiGate without "tunnel-connect-without-reauth": OpenConnect says so when it connects.
  noResume: (line) => /reconnect-after-drop is not allowed/i.test(line),
  // OpenConnect's own reconnect loop, once the gateway did not answer: "Failed to reconnect to host …" then
  // "sleep 10s, remaining timeout 300s".
  lost: (line) => /Failed to reconnect to host|remaining timeout \d+s/i.test(line),
  failure(last: string | undefined, code: number | null): string {
    const l = last ?? '';
    if (/incorrect password attempt|sudo:.*password/i.test(l)) return 'The computer password was not accepted, so the VPN adapter could not be set up';
    if (/login failed|authentication failed|ret=0 redir=\/remote\/login|Failed to complete authentication|HTTP 401|HTTP 403/i.test(l)) return 'The FortiGate refused the user name, password or code';
    if (/certificate/i.test(l) && /verif|trust|failed/i.test(l)) return "The gateway's certificate is not trusted";
    if (/tun|wintun|adapter|interface/i.test(l)) return 'Could not create the VPN adapter. It needs administrator rights (and wintun.dll next to openconnect.exe on Windows).';
    if (/getaddrinfo|resolve|Name or service not known|No such host/i.test(l)) return "The gateway's address could not be found";
    if (/refused|timed out|unreachable/i.test(l)) return 'The gateway did not answer. Check its address and port.';
    return l ? `OpenConnect: ${l}` : `OpenConnect exited (code ${code})`;
  },
};
