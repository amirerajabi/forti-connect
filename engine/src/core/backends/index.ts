// Which program connects a profile on this computer, and the tunnel for it.
//   SSL-VPN: OpenConnect everywhere.
//   IPsec:   Windows' own client (IKEv2, L2TP/IPsec) on Windows; strongSwan's charon-cmd (IKEv1 + XAuth, IKEv2) elsewhere.
import type { Backends, Profile, Settings } from '../../../../shared/protocol';
import type { ProfileSecrets } from '../secrets';
import type { Platform } from '../system';
import { charonArgs, charonCommand, charonDialect, detectCharon } from './charon';
import { detectOpenconnect, findVpncScript, openconnectArgs, openconnectDialect, withSudo } from './openconnect';
import { ProcessTunnel } from './process';
import { detectRas, RasTunnel } from './ras';
import type { Tunnel, TunnelHooks } from './types';

export async function detectBackends(settings: Settings, dataDir: string, platform: Platform, elevated: boolean): Promise<Backends> {
  const [ssl, ipsec] = await Promise.all([
    detectOpenconnect(settings.openconnectPath, dataDir, platform, elevated),
    platform === 'win32' ? detectRas() : detectCharon(settings.charonPath, platform, elevated),
  ]);
  return { ssl, ipsec, elevated, platform };
}

export interface TunnelContext {
  profile: Profile;
  secrets: ProfileSecrets;
  settings: Settings;
  backends: Backends;
  hooks: TunnelHooks;
  platform: Platform;
  elevated: boolean;
}

export type TunnelFactory = (ctx: TunnelContext) => Tunnel;

/** The tunnel for a profile, or an error saying what is missing on this computer. */
export const createTunnel: TunnelFactory = (ctx) => {
  const { profile: p, backends, platform, elevated, settings } = ctx;
  const verbose = settings.logLevel === 'verbose';
  if (p.type === 'ssl') {
    const b = backends.ssl;
    if (!b.available || !b.path) throw new Error(`${b.note ?? 'OpenConnect is not installed'}. See Settings → VPN programs.`);
    if (platform === 'win32' && !elevated) throw new Error('SSL-VPN on Windows needs administrator rights to create the VPN adapter. Restart FortiConnect as administrator.');
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
