// IPsec IKEv2 on Windows with FortiConnect's own engine (ikev2/), for FortiGate dial-up tunnels set up for FortiClient:
// the gateway proves itself with a pre-shared key and the user logs in with EAP (Windows' own client cannot do that, it
// wants a gateway certificate). The engine logs in and does ESP; the VPN helper (SYSTEM) owns the Wintun adapter, sets
// the address, routes and DNS with OpenConnect's vpnc-script, and passes IP packets over its pipe.
import type { LogLine, ProfileConfig } from '../../../../shared/protocol';
import { Esp } from '../ikev2/esp';
import type { TrafficSelector } from '../ikev2/payloads';
import { IkeSession } from '../ikev2/session';
import type { ProfileSecrets } from '../secrets';
import { errorMessage } from '../util';
import { helperTun, type HelperTun, type TunSetup } from './helper';
import type { Leftover, PromptRequest, Tunnel, TunnelHooks, TunnelUp } from './types';

/** The adapter's name: the helper always opens "FortiConnect", as OpenConnect does for SSL-VPN. */
export const IKEV2_ADAPTER = 'FortiConnect';
/** ESP in UDP costs up to ~90 bytes per packet; 1400 keeps packets whole on any 1500-byte path. */
const MTU = 1400;

function ipNum(s: string): number {
  return s.split('.').reduce((n, p) => n * 256 + Number(p), 0);
}

function ipStr(n: number): string {
  return [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');
}

/** Traffic selector ranges as networks ("a.b.c.d/len"); one covering everything means "all traffic" (empty list). */
export function rangesToNetworks(ranges: TrafficSelector[]): string[] {
  const out: string[] = [];
  for (const r of ranges) {
    let start = ipNum(r.start);
    const end = ipNum(r.end);
    if (start === 0 && end === 0xffffffff) return [];
    while (start <= end) {
      let len = 32;
      // The largest block that starts here and stays inside the range.
      while (len > 0) {
        const size = 2 ** (32 - (len - 1));
        if (start % size !== 0 || start + size - 1 > end) break;
        len--;
      }
      out.push(`${ipStr(start)}/${len}`);
      start += 2 ** (32 - len);
      if (out.length > 100) return out;
    }
  }
  return out;
}

export interface Ikev2Options {
  profile: ProfileConfig & { name: string };
  secrets: ProfileSecrets;
  hooks: TunnelHooks;
  /** Where the gateway listens, for tests (500 and 4500 otherwise). */
  session?: { port: number; natPort: number };
  helperPipe?: string;
  /** Tests use their own adapter instead of the helper's. */
  tun?: (setup: TunSetup) => HelperTun;
}

export class Ikev2Tunnel implements Tunnel {
  private session: IkeSession | null = null;
  private tun: HelperTun | null = null;
  private stopping = false;
  private up = false;
  /** Packets dropped on the way in (failed integrity, replays), for the log. */
  private dropped = 0;

  constructor(private readonly o: Ikev2Options) {}

  get running(): boolean {
    return !!this.session;
  }

  get leftover(): Leftover | null {
    // The helper undoes the adapter setup itself when the engine's pipe closes, even after a crash.
    return null;
  }

  private log(text: string, level: LogLine['level'] = 'info'): void {
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
    const psk = await this.secret('psk', 'Pre-shared key:');
    const password = await this.secret('password', `Password for ${p.username}:`);
    if (this.stopping) throw new Error('Cancelled');
    const session = new IkeSession({ gateway: p.gateway, psk, localId: p.localId ?? '', userName: p.username, password, log: (t) => this.log(t), ...this.o.session });
    this.session = session;
    try {
      const r = await session.connect();
      if (this.stopping) throw new Error('Cancelled');
      // The profile's own networks win over what the gateway offered (FortiClient's split tunnel lives on the gateway).
      const split = p.routes?.length ? p.routes.map((n) => (n.includes('/') ? n : `${n}/32`)) : rangesToNetworks(r.networks);
      const setup: TunSetup = { address: r.address, netmask: r.netmask, dns: r.dns.slice(0, 4), gateway: r.remote.address, split, mtu: MTU };
      this.log(`Setting up the VPN adapter: ${r.address}${split.length ? `, networks ${split.join(', ')}` : ', all traffic'}${r.dns.length ? `, DNS ${r.dns.join(', ')}` : ''}`);
      const tun = this.o.tun ? this.o.tun(setup) : helperTun(setup, this.o.helperPipe);
      this.tun = tun;
      await tun.ready;
      const esp = new Esp(r.child);
      session.keepAlive(
        (data) => {
          if (!esp.isOurs(data)) return;
          try {
            const packet = esp.decapsulate(data);
            if (packet.length) tun.send(packet);
          } catch (e) {
            if (++this.dropped <= 5 || this.dropped % 1000 === 0) this.log(`Dropped an incoming packet: ${errorMessage(e)} (${this.dropped} so far)`, 'warning');
          }
        },
        (reason) => this.lost(reason),
      );
      tun.onPacket((packet) => {
        // IPv4 only: the tunnel carries what the gateway agreed to, and Windows also sends IPv6 to every adapter.
        if (packet.length < 20 || packet[0] >> 4 !== 4) return;
        session.sendEsp(esp.encapsulate(packet));
      });
      tun.onClosed((reason) => reason && this.lost(reason));
      this.up = true;
      return { device: IKEV2_ADAPTER, address: r.address };
    } catch (e) {
      this.tun?.close();
      this.tun = null;
      if (!this.stopping) await session.delete().catch(() => undefined);
      session.close();
      this.session = null;
      throw new Error(this.stopping ? 'Cancelled' : errorMessage(e));
    }
  }

  /** The gateway ended the tunnel, stopped answering, or the helper closed the adapter. */
  private lost(reason: string): void {
    if (this.stopping || !this.up) return;
    this.up = false;
    this.tun?.close();
    this.tun = null;
    void this.session?.delete().catch(() => undefined);
    this.session = null;
    this.o.hooks.dropped(reason);
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.up = false;
    // The helper first: it undoes the routes and DNS, so the computer has its own network back before the tunnel goes.
    this.tun?.close();
    this.tun = null;
    await this.session?.delete().catch(() => undefined);
    this.session?.close();
    this.session = null;
  }
}
