// Which program connects a profile on this computer, and the tunnel for it.
//   SSL-VPN: OpenConnect everywhere; on Windows without administrator rights, through the FortiConnect VPN helper.
//   IPsec:   Windows' own client (IKEv2, L2TP/IPsec) on Windows; strongSwan's charon-cmd (IKEv1 + XAuth, IKEv2) elsewhere.
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Backends, Profile, Settings } from '../../../../shared/protocol';
import type { ProfileSecrets } from '../secrets';
import type { Platform } from '../system';
import { charonArgs, charonCommand, charonDialect, detectCharon } from './charon';
import { detectHelper, helperProcess } from './helper';
import { HELPER_PIPE } from './helper-script';
import { detectOpenconnect, findVpncScript, openconnectArgs, openconnectDialect, withSudo } from './openconnect';
import { ProcessTunnel } from './process';
import { detectRas, RasTunnel } from './ras';
import type { Tunnel, TunnelHooks } from './types';

/** The helper only runs an OpenConnect administrators control: one under Program Files. */
export function inProgramFiles(p: string | null): boolean {
  if (!p) return false;
  const dirs = [process.env.ProgramFiles, process.env.ProgramW6432, process.env['ProgramFiles(x86)']].filter((d): d is string => !!d);
  return dirs.some((d) => path.resolve(p).toLowerCase().startsWith(path.resolve(d).toLowerCase() + path.sep));
}

export async function detectBackends(settings: Settings, dataDir: string, platform: Platform, elevated: boolean, helperPipe = HELPER_PIPE): Promise<Backends> {
  const [ssl, ipsec, helper] = await Promise.all([
    detectOpenconnect(settings.openconnectPath, dataDir, platform, elevated),
    platform === 'win32' ? detectRas() : detectCharon(settings.charonPath, platform, elevated),
    platform === 'win32' ? detectHelper(helperPipe) : Promise.resolve(undefined),
  ]);
  if (platform === 'win32' && ssl.available && !elevated) {
    if (helper?.state !== 'running') ssl.note = 'Needs the FortiConnect VPN helper, or FortiConnect running as administrator';
    else if (!inProgramFiles(ssl.path)) ssl.note = 'The VPN helper only runs an OpenConnect installed under Program Files';
    else ssl.note = 'Runs through the FortiConnect VPN helper';
  }
  return { ssl, ipsec, elevated, platform, helper };
}

export interface TunnelContext {
  profile: Profile;
  secrets: ProfileSecrets;
  settings: Settings;
  backends: Backends;
  hooks: TunnelHooks;
  platform: Platform;
  elevated: boolean;
  /** The helper's pipe (tests use their own). */
  helperPipe?: string;
}

export type TunnelFactory = (ctx: TunnelContext) => Tunnel;

/** The tunnel for a profile, or an error saying what is missing on this computer. */
export const createTunnel: TunnelFactory = (ctx) => {
  const { profile: p, backends, platform, elevated, settings } = ctx;
  const verbose = settings.logLevel === 'verbose';
  if (p.type === 'ssl') {
    const b = backends.ssl;
    if (!b.available || !b.path) throw new Error(`${b.note ?? 'OpenConnect is not installed'}. See Settings → VPN programs.`);
    if (platform === 'win32' && !elevated) {
      const h = backends.helper;
      if (h?.state !== 'running' && h?.state !== 'outdated') {
        throw new Error('SSL-VPN on Windows needs the FortiConnect VPN helper (Settings → VPN programs → Install, once, with administrator rights), or FortiConnect running as administrator.');
      }
      // The helper (SYSTEM) must not read a file at a path the user chose: it gets the certificate's bytes instead.
      const cert = p.clientCert ? fs.readFileSync(p.clientCert).toString('base64') : undefined;
      const start = { gateway: p.gateway, port: p.port, realm: p.realm ? encodeURI(p.realm) : '', user: p.username, servercert: p.trustedCert ?? '', verbose, cert };
      const pipe = ctx.helperPipe ?? HELPER_PIPE;
      return new ProcessTunnel({ file: 'openconnect', args: [], launch: () => helperProcess(start, pipe), username: p.username, secrets: ctx.secrets, dialect: openconnectDialect, hooks: ctx.hooks, names: [] });
    }
    const args = openconnectArgs({ profile: p, platform, verbose, vpncScript: findVpncScript(settings.vpncScript, b.path, platform) });
    const cmd = withSudo(b.path, args, platform, elevated);
    return new ProcessTunnel({ ...cmd, username: p.username, secrets: ctx.secrets, dialect: openconnectDialect, hooks: ctx.hooks, names: ['openconnect', 'sudo'], stopSignal: 'SIGINT' });
  }
  if (platform === 'win32') {
    if (p.ike === 'ikev1') throw new Error("Windows' own VPN client has no IKEv1 + XAuth. Use IKEv2 or L2TP/IPsec for this profile (and enable it on the FortiGate), or connect with SSL-VPN.");
    return new RasTunnel({ profile: p, secrets: ctx.secrets, hooks: ctx.hooks });
  }
  if (p.ike === 'l2tp') throw new Error('L2TP/IPsec is only available on Windows. Use IKEv1 or IKEv2 for this profile.');
  const b = backends.ipsec;
  if (!b.available || !b.path) throw new Error(`${b.note ?? "strongSwan's charon-cmd is not installed"}. See Settings → VPN programs.`);
  const cmd = charonCommand(b.path, charonArgs(p, verbose), platform, elevated);
  return new ProcessTunnel({ ...cmd, username: p.username, secrets: ctx.secrets, dialect: charonDialect, hooks: ctx.hooks, names: ['script', 'sudo', 'charon'], stopSignal: 'SIGINT' });
};
