// IPsec IKEv2 on Windows with FortiConnect's own engine (ikev2/), for FortiGate dial-up tunnels set up for FortiClient:
// the gateway proves itself with a pre-shared key and the user logs in with EAP (Windows' own client cannot do that, it
// wants a gateway certificate). Step 1 of 3: the whole login runs here and its result is reported; carrying traffic
// (ESP through the VPN helper's adapter) is not built yet, so the session signs out again and says so.
import type { LogLine, ProfileConfig } from '../../../../shared/protocol';
import { IkeSession } from '../ikev2/session';
import type { ProfileSecrets } from '../secrets';
import { errorMessage } from '../util';
import type { Leftover, PromptRequest, Tunnel, TunnelHooks, TunnelUp } from './types';

export const IKEV2_NOT_READY = 'IPsec traffic is not built yet';

export class Ikev2Tunnel implements Tunnel {
  private session: IkeSession | null = null;
  private stopping = false;

  /** `session`: where the gateway listens, for tests (500 and 4500 otherwise). */
  constructor(private readonly o: { profile: ProfileConfig & { name: string }; secrets: ProfileSecrets; hooks: TunnelHooks; session?: { port: number; natPort: number } }) {}

  get running(): boolean {
    return !!this.session;
  }

  get leftover(): Leftover | null {
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
    const session = new IkeSession({
      gateway: p.gateway,
      psk,
      localId: p.localId ?? '',
      userName: p.username,
      password,
      log: (t) => this.log(t),
      ...this.o.session,
    });
    this.session = session;
    try {
      const r = await session.connect();
      this.log(`Logged in to the FortiGate with IPsec (IKEv2). VPN address ${r.address}${r.dns.length ? `, DNS ${r.dns.join(', ')}` : ''}.`, 'app');
      this.log('Carrying traffic over this IPsec tunnel is the next step and not built yet: signing out of the FortiGate again.', 'warning');
      await session.delete();
      throw new Error(`${IKEV2_NOT_READY}: the login worked (VPN address ${r.address}), but FortiConnect cannot carry traffic over IPsec yet. Use SSL-VPN on this FortiGate for now.`);
    } catch (e) {
      session.close();
      throw new Error(this.stopping ? 'Cancelled' : errorMessage(e));
    } finally {
      this.session = null;
    }
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.session?.close();
    this.session = null;
  }
}
