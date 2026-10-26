// IPsec IKEv2 on Windows with FortiConnect's own engine (ikev2/), for FortiGate dial-up tunnels set up for FortiClient:
// the gateway proves itself with a pre-shared key and the user logs in with EAP (Windows' own client cannot do that, it
// wants a gateway certificate). The engine logs in and does ESP; the VPN helper (SYSTEM) owns the Wintun adapter, sets
// the address, routes and DNS with OpenConnect's vpnc-script, and passes IP packets over its pipe.
import type { LogLine, ProfileConfig } from '../../../../shared/protocol';
import { Esp } from '../ikev2/esp';
import type { TrafficSelector } from '../ikev2/payloads';
import { IkeSession, type KeepAliveTimers } from '../ikev2/session';
import type { ProfileSecrets } from '../secrets';
import { errorMessage } from '../util';
import { helperTun, type HelperTun, type TunSetup } from './helper';
import type { Leftover, PromptRequest, Tunnel, TunnelHooks, TunnelUp } from './types';

/** The helper's own adapter for IPsec, kept between connections (OpenConnect's for SSL-VPN is "FortiConnect"). */
export const IKEV2_ADAPTER = 'FortiConnect IPsec';
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
  /** Tests: short lifetimes (seconds) so keys are renewed quickly, and fast timers. */
  lifetimes?: { ike?: number; child?: number };
  timers?: KeepAliveTimers;
}

export class Ikev2Tunnel implements Tunnel {
  private session: IkeSession | null = null;
  private tun: HelperTun | null = null;
  private stopping = false;
  private up = false;
  /** Packets dropped on the way in (failed integrity, replays), for the log. */
  private dropped = 0;
  private report: NodeJS.Timeout | null = null;

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
    const session = new IkeSession({ gateway: p.gateway, psk, localId: p.localId ?? '', userName: p.username, password, log: (t) => this.log(t), lifetimes: this.o.lifetimes, ...this.o.session });
    this.session = session;
    try {
      const r = await session.connect();
      if (this.stopping) throw new Error('Cancelled');
      // The profile's own networks win over what the gateway offered (FortiClient's split tunnel lives on the gateway).
      // The profile's own networks first, then the ones the FortiGate names (its split tunnel), then what TSr allows.
      if (r.subnets.length) this.log(`The FortiGate names these networks: ${r.subnets.join(', ')}`);
      const split = p.routes?.length ? p.routes.map((n) => (n.includes('/') ? n : `${n}/32`)) : r.subnets.length ? (r.subnets.some((n) => n.endsWith('/0')) ? [] : r.subnets) : rangesToNetworks(r.networks);
      const setup: TunSetup = { address: r.address, netmask: r.netmask, dns: r.dns.slice(0, 4), gateway: r.remote.address, split, mtu: MTU };
      this.log(`Setting up the VPN adapter: ${r.address}${split.length ? `, networks ${split.join(', ')}` : ', all traffic'}${r.dns.length ? `, DNS ${r.dns.join(', ')}` : ''}`);
      const tun = this.o.tun ? this.o.tun(setup) : helperTun(setup, this.o.helperPipe);
      this.tun = tun;
      await tun.ready;
      // During a rekey the old and new ESP SAs both carry packets in for a moment: inbound by SPI, outbound the newest.
      let out = new Esp(r.child);
      const inbound = new Map<string, Esp>([[r.child.spiIn.toString('hex'), out]]);
      const counted = { packetsOut: 0, packetsIn: 0 };
      const total = (k: 'packetsOut' | 'packetsIn') => counted[k] + [...inbound.values()].reduce((n, e) => n + e[k], 0);
      session.keepAlive(
        {
          esp: (data) => {
            const esp = data.length >= 4 ? inbound.get(data.subarray(0, 4).toString('hex')) : undefined;
            if (!esp?.isOurs(data)) return;
            try {
              const packet = esp.decapsulate(data);
              if (packet.length) tun.send(packet);
            } catch (e) {
              if (++this.dropped <= 5 || this.dropped % 1000 === 0) this.log(`Dropped an incoming packet: ${errorMessage(e)} (${this.dropped} so far)`, 'warning');
            }
          },
          gone: (reason) => this.lost(reason),
          child: (child) => {
            out = new Esp(child);
            inbound.set(child.spiIn.toString('hex'), out);
          },
          childGone: (spiIn) => {
            const key = spiIn.toString('hex');
            const esp = inbound.get(key);
            if (!esp || esp === out) return;
            counted.packetsOut += esp.packetsOut;
            counted.packetsIn += esp.packetsIn;
            inbound.delete(key);
          },
        },
        this.o.timers,
      );
      tun.onPacket((packet) => {
        // IPv4 only: the tunnel carries what the gateway agreed to, and Windows also sends IPv6 to every adapter.
        if (packet.length < 20 || packet[0] >> 4 !== 4) return;
        session.sendEsp(out.encapsulate(packet));
      });
      tun.onClosed((reason) => reason && this.lost(reason));
      this.up = true;
      // Whether the gateway answers at all shows quickly: say so in the log, where it helps most when pages do not load.
      this.report = setTimeout(() => {
        if (!this.up) return;
        const [sent, received] = [total('packetsOut'), total('packetsIn')];
        const line = `Traffic after 15 s: ${sent} packets sent, ${received} received from the FortiGate${this.dropped ? `, ${this.dropped} dropped` : ''}`;
        this.log(sent > 0 && received === 0 ? `${line}. The FortiGate has not answered any traffic yet.` : line, sent > 0 && received === 0 ? 'warning' : 'info');
      }, 15_000);
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
    if (this.report) clearTimeout(this.report);
    this.up = false;
    // The helper first: it undoes the routes and DNS, so the computer has its own network back before the tunnel goes.
    this.tun?.close();
    this.tun = null;
    await this.session?.delete().catch(() => undefined);
    this.session?.close();
    this.session = null;
  }
}
