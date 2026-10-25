// IPsec on macOS and Linux through strongSwan's charon-cmd: IKEv1 with a pre-shared key and XAuth (what a FortiGate's
// dial-up tunnel for FortiClient expects, main or aggressive mode) or IKEv2 with EAP. charon-cmd reads its secrets with
// getpass(), which talks to a terminal and not to stdin, so it runs inside `script`, which gives it one.
import type { BackendInfo, ProfileConfig } from '../../../../shared/protocol';
import { commandOutput, findProgram, type Platform } from '../system';
import { ADMIN_PROMPT } from './openconnect';
import type { Dialect, PromptClass } from './process';

export function charonCandidates(configured: string, platform: Platform): string[] {
  if (platform === 'darwin') return [configured, '/opt/homebrew/sbin/charon-cmd', '/opt/homebrew/bin/charon-cmd', '/usr/local/sbin/charon-cmd', '/usr/local/bin/charon-cmd'];
  return [configured, '/usr/sbin/charon-cmd', '/usr/bin/charon-cmd', '/usr/local/sbin/charon-cmd', '/usr/lib/ipsec/charon-cmd', '/usr/libexec/ipsec/charon-cmd'];
}

export async function detectCharon(configured: string, platform: Platform, elevated: boolean): Promise<BackendInfo> {
  const p = findProgram('charon-cmd', charonCandidates(configured, platform));
  if (!p) return { available: false, kind: 'charon', path: null, version: null, note: "strongSwan's charon-cmd is not installed", modes: ['ikev1', 'ikev2'] };
  const out = await commandOutput(p, ['--version']);
  const version = /strongSwan\s+v?([\d.]+\w*)/i.exec(out)?.[1] ?? /([\d]+\.[\d]+\.[\d]+)/.exec(out)?.[1] ?? null;
  return { available: true, kind: 'charon', path: p, version, note: elevated ? undefined : 'Asks for your computer password when connecting (sudo)', modes: ['ikev1', 'ikev2'] };
}

export function charonArgs(p: ProfileConfig, verbose: boolean): string[] {
  const args = ['--host', p.gateway];
  if (p.ike === 'ikev2') {
    args.push('--identity', p.username, '--eap-identity', p.username, '--profile', 'ikev2-eap');
  } else {
    // The FortiGate matches a dial-up tunnel on the peer ID ("local ID" in FortiClient); without one, the user name.
    args.push('--identity', p.localId || p.username, '--profile', p.aggressive ? 'ikev1-xauth-psk-am' : 'ikev1-xauth-psk', '--xauth-username', p.username);
  }
  for (const r of p.routes ?? []) args.push('--remote-ts', r);
  if (verbose) args.push('--debug', '2');
  return args;
}

/** One shell word, for `script -c` on Linux. */
export function shellQuote(s: string): string {
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** charon-cmd under a terminal (`script`), and under sudo unless already root. */
export function charonCommand(charon: string, args: string[], platform: Platform, elevated: boolean): { file: string; args: string[] } {
  const cmd = elevated ? [charon, ...args] : ['sudo', '-S', '-p', ADMIN_PROMPT, '--', charon, ...args];
  if (platform === 'darwin') return { file: '/usr/bin/script', args: ['-q', '/dev/null', ...cmd] };
  return { file: 'script', args: ['-qfec', cmd.map(shellQuote).join(' '), '/dev/null'] };
}

export const charonDialect: Dialect = {
  name: 'strongSwan',
  classify(text: string): PromptClass | null {
    const t = text.trim();
    if (t.includes(ADMIN_PROMPT)) return 'admin';
    if (!/[:?]$/.test(t)) return null;
    if (/pre-?shared key|PSK/i.test(t)) return 'psk';
    if (/password/i.test(t)) return 'password';
    if (/token|code|passcode|challenge/i.test(t)) return 'otp';
    return 'text';
  },
  progress(line: string) {
    const ip = /installing new virtual IP ([0-9A-Fa-f.:]+[0-9A-Fa-f])/.exec(line);
    if (ip) return { address: ip[1] };
    if (/CHILD_SA \S+ established/.test(line)) return { up: true };
    return null;
  },
  isError(line: string): boolean {
    return /failed|no proposal|NO_PROPOSAL_CHOSEN|AUTHENTICATION_FAILED|TS_UNACCEPTABLE|giving up|unable|not found|incorrect password/i.test(line);
  },
  adminRefused: (line) => /Sorry, try again/i.test(line),
  failure(last: string | undefined, code: number | null): string {
    const l = last ?? '';
    if (/incorrect password attempt|sudo:.*password/i.test(l)) return 'The computer password was not accepted, so the VPN could not be set up';
    if (/AUTHENTICATION_FAILED|XAuth.*failed|EAP.*failed/i.test(l)) return 'The FortiGate refused the user name or password';
    if (/decrypt|MAC mismatch|HASH.*invalid|invalid HASH|pre-shared key/i.test(l)) return 'The pre-shared key does not match the FortiGate';
    if (/NO_PROPOSAL_CHOSEN|no proposal/i.test(l)) return 'The FortiGate refused the encryption proposals (phase 1 / phase 2 settings differ)';
    if (/giving up/i.test(l)) return 'The gateway did not answer (UDP ports 500 and 4500 may be blocked, or the address is wrong)';
    return l ? `strongSwan: ${l}` : `charon-cmd exited (code ${code})`;
  },
};
