// IPsec on Windows through its own VPN client (RAS): IKEv2 with EAP-MSCHAPv2, or L2TP over IPsec with a pre-shared
// key. Windows has no IKEv1 + XAuth, which is why a FortiGate dial-up tunnel needs IKEv2 or L2TP enabled for it.
// The connection is a per-user phonebook entry (no administrator rights needed) that exists only while connected, so
// the pre-shared key does not stay behind in Windows' settings.
import type { BackendInfo, ProfileConfig } from '../../../../shared/protocol';
import type { ProfileSecrets } from '../secrets';
import { powershell, run, sys32 } from '../system';
import type { Leftover, PromptRequest, Tunnel, TunnelHooks, TunnelUp } from './types';

export function detectRas(): BackendInfo {
  return { available: true, kind: 'ras', path: null, version: null, modes: ['ikev2', 'l2tp'], note: "Windows' own VPN client: IKEv2 or L2TP/IPsec (no IKEv1 + XAuth)" };
}

/** The phonebook entry's name: recognisable in Windows' VPN settings, and only characters rasdial takes. */
export function entryName(profileName: string): string {
  return `FortiConnect ${profileName.replace(/[^\w .()-]/g, '').trim().slice(0, 60) || 'VPN'}`;
}

/** Creates (or recreates) the entry. Every value comes from the environment: nothing from a profile is code. */
export const CREATE_SCRIPT = `
$ErrorActionPreference = 'Stop'
$n = $env:FC_NAME
if (Get-VpnConnection -Name $n -ErrorAction SilentlyContinue) {
  rasdial $n /disconnect | Out-Null
  Remove-VpnConnection -Name $n -Force
}
$p = @{ Name = $n; ServerAddress = $env:FC_GATEWAY; Force = $true; RememberCredential = $false; EncryptionLevel = 'Required' }
if ($env:FC_MODE -eq 'l2tp') { $p.TunnelType = 'L2tp'; $p.L2tpPsk = $env:FC_PSK; $p.AuthenticationMethod = 'MSChapv2' }
else { $p.TunnelType = 'Ikev2'; $p.AuthenticationMethod = 'Eap' }
$routes = @($env:FC_ROUTES -split ',' | Where-Object { $_ })
if ($routes.Count -gt 0) { $p.SplitTunneling = $true }
Add-VpnConnection @p | Out-Null
foreach ($r in $routes) { Add-VpnConnectionRoute -ConnectionName $n -DestinationPrefix $r | Out-Null }
`;

export const REMOVE_SCRIPT = `
$n = $env:FC_NAME
if (Get-VpnConnection -Name $n -ErrorAction SilentlyContinue) { Remove-VpnConnection -Name $n -Force }
`;

const ADDRESS_SCRIPT = `
(Get-NetIPAddress -InterfaceAlias $env:FC_NAME -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
`;

export function createEnv(name: string, p: ProfileConfig, psk: string | undefined): Record<string, string> {
  return { FC_NAME: name, FC_GATEWAY: p.gateway, FC_MODE: p.ike === 'l2tp' ? 'l2tp' : 'ikev2', FC_PSK: psk ?? '', FC_ROUTES: (p.routes ?? []).join(',') };
}

/** rasdial's "Remote Access error 691" and friends, in words. */
export function rasError(out: string, code: number | null): string {
  const n = Number(/error (\d+)/i.exec(out)?.[1] ?? code);
  const known: Record<number, string> = {
    691: 'The FortiGate refused the user name or password',
    789: 'The L2TP connection failed in the security layer: check the pre-shared key (behind NAT, Windows also needs AssumeUDPEncapsulationContextOnSendRule)',
    809: 'The gateway did not answer (UDP ports 500 and 4500 may be blocked on the way)',
    812: 'The FortiGate refused the sign-in method (EAP / MS-CHAPv2) or this user is not allowed',
    868: "The gateway's address could not be found",
    13801: "The gateway's certificate is not trusted by Windows (IKEv2 needs a certificate Windows trusts)",
    13806: 'IKEv2 could not find a valid machine certificate',
    13868: 'The FortiGate refused the IKEv2 policy (phase 1 / phase 2 settings differ)',
  };
  const line = out.split(/\r?\n/).map((l) => l.trim()).find((l) => /error/i.test(l));
  return known[n] ?? (line ? `Windows VPN: ${line}` : `rasdial exited (code ${code})`);
}

export interface RasOptions {
  profile: ProfileConfig & { name: string };
  secrets: ProfileSecrets;
  hooks: TunnelHooks;
}

export class RasTunnel implements Tunnel {
  private readonly name: string;
  private dialed = false;
  private stopping = false;
  private monitor: NodeJS.Timeout | null = null;

  constructor(private readonly o: RasOptions) {
    this.name = entryName(o.profile.name);
  }

  get running(): boolean {
    return this.dialed;
  }

  get leftover(): Leftover | null {
    return this.dialed ? { kind: 'ras', name: this.name } : null;
  }

  private log(text: string, level: 'info' | 'warning' | 'error' = 'info'): void {
    this.o.hooks.log({ t: Date.now(), level, text });
  }

  private async secret(kind: 'password' | 'psk', message: string): Promise<string> {
    const saved = this.o.secrets[kind];
    if (saved) return saved;
    const v = await this.o.hooks.ask({ kind, message } satisfies PromptRequest);
    if (v === null) throw new Error('Cancelled');
    return v;
  }

  async start(): Promise<TunnelUp> {
    const p = this.o.profile;
    const psk = p.ike === 'l2tp' ? await this.secret('psk', 'Pre-shared key:') : undefined;
    const password = await this.secret('password', `Password for ${p.username}:`);
    this.log(`Creating the Windows VPN connection "${this.name}" (${p.ike === 'l2tp' ? 'L2TP/IPsec' : 'IKEv2'})`);
    const made = await powershell(CREATE_SCRIPT, createEnv(this.name, p, psk));
    if (made.code !== 0) throw new Error(`Could not create the Windows VPN connection: ${made.err.trim().split(/\r?\n/)[0] || `code ${made.code}`}`);
    this.log(`Dialing ${p.gateway}`);
    // rasdial takes the password on its command line; it is only visible to this user's own processes for a moment.
    this.dialed = true;
    const r = await run(sys32('rasdial.exe'), [this.name, p.username, password], 90_000);
    if (r.code !== 0) {
      this.dialed = false;
      await powershell(REMOVE_SCRIPT, { FC_NAME: this.name });
      throw new Error(this.stopping ? 'Cancelled' : rasError(r.out, r.code));
    }
    const addr = await powershell(ADDRESS_SCRIPT, { FC_NAME: this.name });
    const address = addr.out.trim().split(/\r?\n/)[0] || null;
    this.watch();
    return { device: this.name, address };
  }

  /** rasdial with no arguments lists what is connected; the entry missing from it means the tunnel dropped. */
  private watch(): void {
    this.monitor = setInterval(async () => {
      if (this.stopping) return;
      const r = await run(sys32('rasdial.exe'), [], 10_000);
      if (this.stopping || r.code !== 0) return;
      if (!r.out.split(/\r?\n/).some((l) => l.trim() === this.name)) {
        this.stopWatching();
        this.dialed = false;
        await powershell(REMOVE_SCRIPT, { FC_NAME: this.name });
        this.o.hooks.dropped('The Windows VPN connection dropped');
      }
    }, 5000);
  }

  private stopWatching(): void {
    if (this.monitor) clearInterval(this.monitor);
    this.monitor = null;
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.stopWatching();
    if (!this.dialed) return;
    await disconnectRas(this.name);
    this.dialed = false;
  }
}

/** Hang up and remove an entry (also one a crash left behind). */
export async function disconnectRas(name: string): Promise<void> {
  await run(sys32('rasdial.exe'), [name, '/disconnect'], 30_000);
  await powershell(REMOVE_SCRIPT, { FC_NAME: name });
}
