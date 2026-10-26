// An IKEv2 initiator for a FortiGate dial-up tunnel as FortiClient sets one up: IKE_SA_INIT, then IKE_AUTH where the
// gateway proves itself with the pre-shared key and the user logs in with EAP-MSCHAPv2, asking for a VPN address (mode
// config). The result is the ESP keys and addresses the data path (the VPN helper) needs. After the login the session
// keeps the tunnel going: it answers the gateway's requests (liveness checks, DELETEs, rekeys), checks the gateway when
// it goes quiet, and renews the ESP and IKE keys before their lifetimes run out (RFC 7296 §1.3.2, §1.3.3, §2.8, §2.18).
import * as dgram from 'node:dgram';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { authValue, decryptSk, deriveChildKeys, deriveIkeKeys, deriveRekeyedIkeKeys, DH_GROUP, DiffieHellman, encryptSk, icv, INTEG, PRF, randomBytes, type IkeKeys, type Suite } from './crypto';
import { decodeEap, EAP_CODE, MschapV2Peer } from './mschapv2';
import {
  AUTH_HMAC_SHA2_256_128,
  AUTH_HMAC_SHA2_384_192,
  AUTH_SHARED_KEY,
  CFG_REPLY,
  CFG_REQUEST,
  CP_ATTR,
  decodeAuth,
  decodeCp,
  decodeHeader,
  decodeKe,
  decodeNotify,
  decodePayloads,
  decodeSa,
  decodeTs,
  encodeAuth,
  encodeCp,
  encodeHeader,
  encodeId,
  encodeKe,
  encodeMessage,
  encodeNotify,
  encodePayloads,
  encodeSa,
  encodeTs,
  ENCR_AES_CBC,
  ESN_NONE,
  EXCHANGE,
  FLAG,
  HEADER_LENGTH,
  ID_TYPE,
  ip4,
  ip4s,
  NOTIFY,
  notifyName,
  PAYLOAD,
  PRF_HMAC_SHA2_256,
  PRF_HMAC_SHA2_384,
  PROTOCOL,
  TRANSFORM,
  type Payload,
  type Proposal,
  type TrafficSelector,
  type Transform,
} from './payloads';

export type Integ = 'sha256' | 'sha384';

export interface IkeOptions {
  gateway: string;
  /** IKE port on the gateway (FortiClient's "IKE UDP Port", 500). */
  port?: number;
  psk: string;
  /** FortiClient's "Local ID", which the FortiGate matches the dial-up tunnel on; empty sends the user name. */
  localId: string;
  userName: string;
  password: string;
  /** Phase 1: integrity / PRF choices in order of preference (AES-256-CBC encryption), and DH groups. */
  ike?: { integ: Integ[]; dh: number[] };
  /** Phase 2 (ESP) integrity choices (AES-256-CBC encryption). */
  esp?: { integ: Integ[] };
  /** Phase 2 PFS group for the ESP keys FortiConnect renews itself; null: no PFS. Default: the IKE SA's group. */
  pfsGroup?: number | null;
  /**
   * Lifetimes in seconds (FortiClient's phase 1 and phase 2 "Key Life": 86400 and 43200). FortiConnect renews a little
   * before; whichever side is first does it.
   */
  lifetimes?: { ike?: number; child?: number };
  /** Move to UDP 4500 when a NAT is in the way (RFC 3948). */
  natTraversal?: boolean;
  /** The gateway's NAT-T port (4500; tests use their own). */
  natPort?: number;
  log: (text: string) => void;
  /** Per try; requests are sent up to 5 times. */
  timeoutMs?: number;
}

export interface ChildSa {
  /** ESP SPI the gateway expects on packets from us, and ours for packets to us. */
  spiOut: Buffer;
  spiIn: Buffer;
  suite: Suite;
  encrOut: Buffer;
  integOut: Buffer;
  encrIn: Buffer;
  integIn: Buffer;
}

export interface IkeResult {
  address: string;
  netmask: string | null;
  dns: string[];
  /** Networks the gateway sends through the tunnel (its TSr); 0.0.0.0-255.255.255.255 means everything. */
  networks: TrafficSelector[];
  /** The company networks a FortiGate names in mode config (INTERNAL_IP4_SUBNET, its split tunnel), as "a.b.c.d/len". */
  subnets: string[];
  child: ChildSa;
  /** Where ESP goes: the gateway's address and port, and whether it travels inside UDP (NAT traversal). */
  remote: { address: string; port: number };
  udpEncapsulation: boolean;
  localPort: number;
}

/** What the data path hears about while the tunnel is up. */
export interface TunnelEvents {
  /** An ESP packet from the gateway. */
  esp: (data: Buffer) => void;
  /** The tunnel is over (the gateway ended it, or stopped answering). */
  gone: (reason: string) => void;
  /** New ESP keys (a rekey): send with these from now on, and accept packets for them. */
  child?: (child: ChildSa) => void;
  /** An ESP SA is gone (the old one after a rekey): stop accepting packets for this inbound SPI. */
  childGone?: (spiIn: Buffer) => void;
}

/** Timers for keeping the tunnel up; tests make them short. */
export interface KeepAliveTimers {
  keepaliveMs?: number;
  idleMs?: number;
  /** How often lifetimes are checked (10 s). */
  rekeyCheckMs?: number;
}

const INTEG_ID: Record<Integ, number> = { sha256: AUTH_HMAC_SHA2_256_128, sha384: AUTH_HMAC_SHA2_384_192 };
const PRF_ID: Record<Integ, number> = { sha256: PRF_HMAC_SHA2_256, sha384: PRF_HMAC_SHA2_384 };
const NON_ESP_MARKER = Buffer.alloc(4);
const ALL: TrafficSelector[] = [{ start: '0.0.0.0', end: '255.255.255.255' }];

/** Readable words for a gateway's error notify. */
function notifyError(type: number): string {
  switch (type) {
    case NOTIFY.NO_PROPOSAL_CHOSEN:
      return 'The FortiGate did not accept the encryption settings (phase 1 or phase 2 proposals differ)';
    case NOTIFY.AUTHENTICATION_FAILED:
      return 'The FortiGate refused the login (pre-shared key, local ID, user name or password)';
    case NOTIFY.TS_UNACCEPTABLE:
      return 'The FortiGate did not accept the networks requested for the tunnel';
    case NOTIFY.INTERNAL_ADDRESS_FAILURE:
    case NOTIFY.FAILED_CP_REQUIRED:
      return 'The FortiGate could not give this computer a VPN address';
    default:
      return `The FortiGate refused the connection (${notifyName(type)})`;
  }
}

export class IkeError extends Error {
  /** The gateway's error notify, when there was one, and its data (INVALID_KE_PAYLOAD names the group it wants). */
  constructor(message: string, readonly notify?: number, readonly data?: Buffer) {
    super(message);
  }
}

/**
 * One IKE SA: its SPIs, keys and message counters. A rekey replaces it, and whoever started the rekey is the new SA's
 * initiator (§2.18): so which keys protect our messages, and whether they carry the I flag, follow `weInitiator`.
 */
interface SaState {
  spiI: Buffer;
  spiR: Buffer;
  weInitiator: boolean;
  suite: Suite;
  keys: IkeKeys;
  /** Our next request's message ID; the last of the peer's we answered, and that answer (for retransmissions). */
  nextId: number;
  peerId: number;
  lastPeerResponse: Buffer | null;
  since: number;
}

interface ChildState {
  sa: ChildSa;
  since: number;
}

/** A proposal's transforms of one type. */
const ofType = (p: Proposal, t: number) => p.transforms.filter((x) => x.type === t);

/** One IKEv2 tunnel with a FortiGate: the login, then everything that keeps it up. */
export class IkeSession {
  private socket: dgram.Socket | null = null;
  private remoteAddress = '';
  private remotePort = 500;
  private natT = false;
  private spiI = randomBytes(8);
  private ni = randomBytes(32);
  private nr = Buffer.alloc(0);
  private initRequest = Buffer.alloc(0);
  private initResponse = Buffer.alloc(0);
  private idiBody = Buffer.alloc(0);
  private pending: { resolve: (b: Buffer) => void; match: (b: Buffer) => boolean } | null = null;
  private closed = false;
  private sa: SaState | null = null;
  /** The IKE SA a rekey replaced, until the gateway (or we) delete it. */
  private oldSa: SaState | null = null;
  private children: ChildState[] = [];
  // ---- after the login
  private lastHeard = Date.now();
  private timers: NodeJS.Timeout[] = [];
  private events: TunnelEvents | null = null;
  /** Our own requests go one at a time (each IKE SA allows one outstanding request here). */
  private own: Promise<unknown> = Promise.resolve();
  private checking = false;
  private rekeying = false;
  private rekeyJitter = Math.random();

  constructor(private readonly o: IkeOptions) {}

  private get timeout(): number {
    return this.o.timeoutMs ?? 2000;
  }

  async connect(): Promise<IkeResult> {
    this.remoteAddress = isIP(this.o.gateway) ? this.o.gateway : (await lookup(this.o.gateway, { family: 4 })).address;
    this.remotePort = this.o.port ?? 500;
    await this.open();
    try {
      await this.saInit();
      return await this.auth();
    } catch (e) {
      this.close();
      throw e;
    }
  }

  private open(): Promise<void> {
    return new Promise((resolve, reject) => {
      const s = dgram.createSocket('udp4');
      s.on('message', (msg, rinfo) => this.onMessage(msg, rinfo));
      s.on('error', (e) => (this.socket ? this.o.log(`IKE socket error: ${e.message}`) : reject(e)));
      // An ephemeral port: Windows' own IKE service holds 500 and 4500.
      s.bind(0, () => {
        this.socket = s;
        resolve();
      });
    });
  }

  close(): void {
    this.closed = true;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    this.socket?.close();
    this.socket = null;
  }

  /**
   * Keep the established tunnel going: ESP packets from the gateway go to `events.esp`; the gateway's requests are
   * answered (liveness, DELETEs, rekeys); a NAT keepalive goes out every 20 s; when nothing has come from the gateway
   * for 30 s FortiConnect asks it itself; the ESP and IKE keys are renewed before their lifetimes end.
   */
  keepAlive(events: TunnelEvents, t: KeepAliveTimers = {}): void {
    this.events = events;
    this.lastHeard = Date.now();
    if (this.natT) this.timers.push(setInterval(() => this.socket?.send(Buffer.from([0xff]), this.remotePort, this.remoteAddress), t.keepaliveMs ?? 20_000));
    const idle = t.idleMs ?? 30_000;
    this.timers.push(
      setInterval(() => {
        if (this.checking || this.closed || Date.now() - this.lastHeard < idle) return;
        this.checking = true;
        this.ownRequest(() => this.informational([]))
          .then(() => (this.lastHeard = Date.now()))
          .catch((e: Error) => {
            if (!this.closed && e.message !== 'Cancelled') this.gone('The FortiGate stopped answering (dead peer detection)');
          })
          .finally(() => (this.checking = false));
      }, Math.min(10_000, idle)),
    );
    this.timers.push(setInterval(() => this.checkLifetimes(), t.rekeyCheckMs ?? 10_000));
  }

  /** An ESP packet to the gateway, on the IKE socket so it follows the same NAT mapping. */
  sendEsp(data: Buffer): void {
    this.socket?.send(data, this.remotePort, this.remoteAddress);
  }

  private gone(reason: string): void {
    const e = this.events;
    this.events = null;
    this.o.log(reason);
    e?.gone(reason);
  }

  private onMessage(msg: Buffer, rinfo: dgram.RemoteInfo): void {
    if (rinfo.address !== this.remoteAddress) return;
    let ike = msg;
    if (rinfo.port === (this.o.natPort ?? 4500) && this.natT) {
      // NAT-T: IKE behind a zero marker; a single 0xFF byte is a keepalive; anything else on 4500 is ESP.
      if (msg.length === 1 && msg[0] === 0xff) return;
      if (msg.length < 4 || !msg.subarray(0, 4).equals(NON_ESP_MARKER)) {
        this.lastHeard = Date.now();
        this.events?.esp(msg);
        return;
      }
      ike = msg.subarray(4);
    }
    if (ike.length < HEADER_LENGTH) return;
    const spi = ike.subarray(0, 8);
    const sa = this.sa?.spiI.equals(spi) ? this.sa : this.oldSa?.spiI.equals(spi) ? this.oldSa : null;
    if (!sa && !spi.equals(this.spiI)) return;
    this.lastHeard = Date.now();
    if ((ike[19] & FLAG.RESPONSE) === 0) {
      if (sa && this.events) this.answer(sa, ike);
      return;
    }
    if (this.pending?.match(ike)) {
      const p = this.pending;
      this.pending = null;
      p.resolve(ike);
    }
  }

  private send(packet: Buffer): void {
    const data = this.natT ? Buffer.concat([NON_ESP_MARKER, packet]) : packet;
    this.socket?.send(data, this.remotePort, this.remoteAddress);
  }

  /** Send a request and wait for its response, sending it again on silence (RFC 7296 §2.1). */
  private request(spiI: Buffer, packet: Buffer, exchange: number, messageId: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let tries = 0;
      let timer: NodeJS.Timeout;
      const attempt = () => {
        if (this.closed) return reject(new IkeError('Cancelled'));
        if (tries++ >= 5) {
          this.pending = null;
          return reject(new IkeError(`The gateway did not answer (UDP port ${this.remotePort}${this.natT ? '' : ' may be blocked, or the address is wrong'})`));
        }
        this.send(packet);
        timer = setTimeout(attempt, this.timeout * Math.min(tries, 3));
      };
      this.pending = {
        match: (b) => {
          const h = decodeHeader(b);
          return h.spiI.equals(spiI) && h.exchange === exchange && h.messageId === messageId && (h.flags & FLAG.RESPONSE) !== 0;
        },
        resolve: (b) => {
          clearTimeout(timer);
          resolve(b);
        },
      };
      attempt();
    });
  }

  /** Run one of our own requests after the ones before it. */
  private ownRequest<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.own.then(fn, fn);
    this.own = run.catch(() => undefined);
    return run;
  }

  // ---------------------------------------------------------------- protection

  private encrypted(sa: SaState, exchange: number, payloads: Payload[], response: boolean, messageId: number): Buffer {
    const s = sa.suite;
    const [encKey, integKey] = sa.weInitiator ? [sa.keys.skEi, sa.keys.skAi] : [sa.keys.skEr, sa.keys.skAr];
    const inner = encodePayloads(payloads);
    const body = encryptSk(s, encKey, inner);
    const icvLen = INTEG[s.integ].icvLength;
    const total = HEADER_LENGTH + 4 + body.length + icvLen;
    const flags = (sa.weInitiator ? FLAG.INITIATOR : 0) | (response ? FLAG.RESPONSE : 0);
    const header = encodeHeader({ spiI: sa.spiI, spiR: sa.spiR, next: PAYLOAD.SK, exchange, flags, messageId }, total);
    const sk = Buffer.from([payloads[0]?.type ?? PAYLOAD.NONE, 0, 0, 0]);
    sk.writeUInt16BE(4 + body.length + icvLen, 2);
    const unsigned = Buffer.concat([header, sk, body]);
    return Buffer.concat([unsigned, icv(s, integKey, unsigned)]);
  }

  /** Decrypt a message from the gateway: its payloads, in order. */
  private open_(sa: SaState, msg: Buffer): Payload[] {
    const h = decodeHeader(msg);
    const m = msg.subarray(0, h.length);
    if (h.next !== PAYLOAD.SK) {
      // Only an unprotected error may come back unencrypted (e.g. INVALID_SYNTAX before keys).
      const ps = decodePayloads(h.next, m.subarray(HEADER_LENGTH));
      const n = ps.find((p) => p.type === PAYLOAD.NOTIFY);
      throw new IkeError(n ? notifyError(decodeNotify(n.body).type) : 'The gateway answered without encryption', n ? decodeNotify(n.body).type : undefined);
    }
    const first = m[HEADER_LENGTH];
    const skLen = m.readUInt16BE(HEADER_LENGTH + 2);
    const body = m.subarray(HEADER_LENGTH + 4, HEADER_LENGTH + skLen);
    const [encKey, integKey] = sa.weInitiator ? [sa.keys.skEr, sa.keys.skAr] : [sa.keys.skEi, sa.keys.skAi];
    const inner = decryptSk(sa.suite, encKey, integKey, m, body);
    return decodePayloads(first, inner);
  }

  /** One of our requests on the current IKE SA; an error notify in the answer throws (with the notify type). */
  private async call(exchange: number, payloads: Payload[], sa = this.sa!): Promise<Payload[]> {
    const id = sa.nextId++;
    const res = await this.request(sa.spiI, this.encrypted(sa, exchange, payloads, false, id), exchange, id);
    const ps = this.open_(sa, res);
    const err = ps.filter((p) => p.type === PAYLOAD.NOTIFY).map((p) => decodeNotify(p.body)).find((n) => n.type < 16384);
    if (err) throw new IkeError(notifyError(err.type), err.type, Buffer.from(err.data));
    return ps;
  }

  private informational(payloads: Payload[], sa = this.sa!): Promise<Payload[]> {
    return this.call(EXCHANGE.INFORMATIONAL, payloads, sa);
  }

  // ---------------------------------------------------------------- IKE_SA_INIT

  private natHash(spiR: Buffer, address: string, port: number): Buffer {
    const p = Buffer.alloc(2);
    p.writeUInt16BE(port);
    return createHash('sha1').update(Buffer.concat([this.spiI, spiR, ip4(address), p])).digest();
  }

  private ikeProposal(dh: number[], spi = Buffer.alloc(0)): Proposal {
    const integ = this.o.ike?.integ ?? ['sha384', 'sha256'];
    return {
      number: 1,
      protocol: PROTOCOL.IKE,
      spi,
      transforms: [
        { type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 },
        ...integ.map((i) => ({ type: TRANSFORM.PRF, id: PRF_ID[i] })),
        ...integ.map((i) => ({ type: TRANSFORM.INTEG, id: INTEG_ID[i] })),
        ...dh.map((g) => ({ type: TRANSFORM.DH, id: g })),
      ],
    };
  }

  private async saInit(): Promise<void> {
    let groups = this.o.ike?.dh ?? [20, 21];
    let cookie: Buffer | null = null;
    for (let round = 0; round < 4; round++) {
      const dh = new DiffieHellman(groups[0]);
      const local = this.socket!.address();
      const payloads: Payload[] = [
        ...(cookie ? [{ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.COOKIE, data: cookie }) }] : []),
        { type: PAYLOAD.SA, critical: false, body: encodeSa([this.ikeProposal(groups)]) },
        { type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) },
        { type: PAYLOAD.NONCE, critical: false, body: this.ni },
        // The source we would claim if there were no NAT: the gateway compares it with what it sees.
        { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NAT_DETECTION_SOURCE_IP, data: this.natHash(Buffer.alloc(8), '0.0.0.0', local.port) }) },
        { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NAT_DETECTION_DESTINATION_IP, data: this.natHash(Buffer.alloc(8), this.remoteAddress, this.remotePort) }) },
      ];
      this.initRequest = encodeMessage({ spiI: this.spiI, spiR: Buffer.alloc(8), exchange: EXCHANGE.IKE_SA_INIT, flags: FLAG.INITIATOR, messageId: 0 }, payloads);
      this.o.log(`IKE_SA_INIT to ${this.remoteAddress}:${this.remotePort} (AES-256, ${(this.o.ike?.integ ?? ['sha384', 'sha256']).map((i) => i.toUpperCase()).join('/')}, DH ${groups.join('/')})`);
      const res = await this.request(this.spiI, this.initRequest, EXCHANGE.IKE_SA_INIT, 0);
      const h = decodeHeader(res);
      const ps = decodePayloads(h.next, res.subarray(HEADER_LENGTH, h.length));
      const notifies = ps.filter((p) => p.type === PAYLOAD.NOTIFY).map((p) => decodeNotify(p.body));
      const c = notifies.find((n) => n.type === NOTIFY.COOKIE);
      if (c) {
        cookie = Buffer.from(c.data);
        this.o.log('The gateway asked for a cookie; asking again');
        continue;
      }
      const invalidKe = notifies.find((n) => n.type === NOTIFY.INVALID_KE_PAYLOAD);
      if (invalidKe && invalidKe.data.length >= 2) {
        const want = invalidKe.data.readUInt16BE(0);
        if (!groups.includes(want) || want === groups[0]) throw new IkeError(`The gateway wants Diffie-Hellman group ${want}, which this profile does not offer`);
        this.o.log(`The gateway prefers DH group ${want}; asking again`);
        groups = [want, ...groups.filter((g) => g !== want)];
        continue;
      }
      const err = notifies.find((n) => n.type < 16384);
      if (err) throw new IkeError(notifyError(err.type), err.type);

      const sa = ps.find((p) => p.type === PAYLOAD.SA);
      const ke = ps.find((p) => p.type === PAYLOAD.KE);
      const nonce = ps.find((p) => p.type === PAYLOAD.NONCE);
      if (!sa || !ke || !nonce) throw new IkeError('The gateway answered IKE_SA_INIT without SA, KE or nonce');
      const chosen = decodeSa(sa.body)[0];
      const suite = chosen && this.ikeSuite(chosen);
      if (!suite || suite.dh !== dh.group) throw new IkeError('The gateway chose IKE algorithms this profile did not offer');
      this.nr = Buffer.from(nonce.body);
      this.initResponse = Buffer.from(res.subarray(0, h.length));
      const secret = dh.computeSecret(decodeKe(ke.body).data);
      const spiR = Buffer.from(h.spiR);
      const keys = deriveIkeKeys(suite, secret, this.ni, this.nr, this.spiI, spiR);
      this.sa = { spiI: this.spiI, spiR, weInitiator: true, suite, keys, nextId: 1, peerId: -1, lastPeerResponse: null, since: Date.now() };
      this.o.log(`IKE_SA_INIT done: ${suite.encr.keyLength}-bit AES, ${suite.integ === AUTH_HMAC_SHA2_384_192 ? 'SHA384' : 'SHA256'}, DH group ${suite.dh}`);

      // ESP inside UDP on 4500 (RFC 3948). FortiConnect's data path sends ESP from a normal UDP socket, so it always
      // wants UDP encapsulation: the source hash above names 0.0.0.0, which never matches, so the gateway treats this
      // computer as being behind a NAT (strongSwan's "encap" does the same). It needs the gateway to allow NAT-T.
      const natSupported = notifies.some((n) => n.type === NOTIFY.NAT_DETECTION_DESTINATION_IP);
      if (natSupported && this.o.natTraversal !== false) {
        this.natT = true;
        this.remotePort = this.o.natPort ?? 4500;
        this.o.log('Continuing on UDP 4500 (ESP inside UDP)');
      } else {
        this.o.log('The gateway does not offer NAT traversal: staying on UDP 500');
      }
      return;
    }
    throw new IkeError('The gateway kept asking IKE_SA_INIT again');
  }

  /** The IKE suite a (chosen or offered) proposal names, if it is one FortiConnect can do. */
  private ikeSuite(p: Proposal): Suite | null {
    const encr = ofType(p, TRANSFORM.ENCR).find((t) => t.id === ENCR_AES_CBC && (t.keyLength ?? 256) === 256);
    const integ = ofType(p, TRANSFORM.INTEG).find((t) => INTEG[t.id])?.id;
    const prfId = ofType(p, TRANSFORM.PRF).find((t) => PRF[t.id])?.id;
    const dh = ofType(p, TRANSFORM.DH).find((t) => DH_GROUP[t.id])?.id;
    if (!encr || !integ || !prfId || !dh) return null;
    return { encr: { id: ENCR_AES_CBC, keyLength: 256 }, integ, prf: prfId, dh };
  }

  // ---------------------------------------------------------------- IKE_AUTH

  private espProposal(spi: Buffer, pfsGroup: number | null = null): Proposal {
    const integ = this.o.esp?.integ ?? ['sha256', 'sha384'];
    return {
      number: 1,
      protocol: PROTOCOL.ESP,
      spi,
      transforms: [
        { type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 },
        ...integ.map((i) => ({ type: TRANSFORM.INTEG, id: INTEG_ID[i] })),
        ...(pfsGroup ? [{ type: TRANSFORM.DH, id: pfsGroup }] : []),
        { type: TRANSFORM.ESN, id: ESN_NONE },
      ],
    };
  }

  /** The ESP suite of a chosen proposal; throws when FortiConnect cannot do it. */
  private espSuite(p: Proposal | undefined): Suite {
    const encr = p && ofType(p, TRANSFORM.ENCR).find((t) => t.id === ENCR_AES_CBC);
    const integ = p && ofType(p, TRANSFORM.INTEG).find((t) => INTEG[t.id])?.id;
    if (!p || p.protocol !== PROTOCOL.ESP || p.spi.length !== 4 || !encr || !integ) throw new IkeError('The gateway chose ESP algorithms this profile did not offer');
    return { encr: { id: ENCR_AES_CBC, keyLength: (encr.keyLength ?? 256) as 256 }, integ };
  }

  private verifyAuth(ps: Payload[], secret: Buffer, idrBody: Buffer, what: string): void {
    const auth = ps.find((p) => p.type === PAYLOAD.AUTH);
    if (!auth) throw new IkeError(`The gateway did not prove itself (${what})`);
    const a = decodeAuth(auth.body);
    if (a.method !== AUTH_SHARED_KEY) throw new IkeError(`The gateway proved itself with method ${a.method}; FortiConnect expects a pre-shared key`);
    const want = authValue(this.sa!.suite.prf!, secret, this.initResponse, this.ni, this.sa!.keys.skPr, idrBody);
    if (!want.equals(a.data)) throw new IkeError(what === 'pre-shared key' ? 'The pre-shared key does not match the FortiGate' : 'The gateway could not prove the login (EAP keys differ)');
  }

  private async auth(): Promise<IkeResult> {
    const id = this.o.localId || this.o.userName;
    // FortiClient sends its local ID as a key ID unless it looks like an FQDN or e-mail address.
    const idType = /@/.test(id) ? ID_TYPE.RFC822_ADDR : ID_TYPE.KEY_ID;
    this.idiBody = encodeId(idType, Buffer.from(id, 'utf8'));
    const spiIn = randomBytes(4);
    this.o.log(`IKE_AUTH as "${id}", user ${this.o.userName} (EAP)`);
    let ps = await this.call(EXCHANGE.IKE_AUTH, [
      { type: PAYLOAD.IDi, critical: false, body: this.idiBody },
      { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.INITIAL_CONTACT }) },
      { type: PAYLOAD.CP, critical: false, body: encodeCp(CFG_REQUEST, [CP_ATTR.INTERNAL_IP4_ADDRESS, CP_ATTR.INTERNAL_IP4_NETMASK, CP_ATTR.INTERNAL_IP4_DNS, CP_ATTR.INTERNAL_IP4_SUBNET].map((type) => ({ type, value: Buffer.alloc(0) }))) },
      { type: PAYLOAD.SA, critical: false, body: encodeSa([this.espProposal(spiIn)]) },
      { type: PAYLOAD.TSi, critical: false, body: encodeTs(ALL) },
      { type: PAYLOAD.TSr, critical: false, body: encodeTs(ALL) },
    ]);
    const idr = ps.find((p) => p.type === PAYLOAD.IDr);
    if (!idr) throw new IkeError('The gateway did not say who it is (no IDr)');
    const idrBody = Buffer.from(idr.body);
    this.verifyAuth(ps, Buffer.from(this.o.psk, 'utf8'), idrBody, 'pre-shared key');
    this.o.log('The gateway proved the pre-shared key');

    const peer = new MschapV2Peer(this.o.userName, this.o.password);
    for (let rounds = 0; rounds < 10; rounds++) {
      const eapPayload = ps.find((p) => p.type === PAYLOAD.EAP);
      if (!eapPayload) throw new IkeError('The gateway did not start EAP (it may not expect a user name and password)');
      const eap = decodeEap(eapPayload.body);
      if (eap.code === EAP_CODE.FAILURE) throw new IkeError('The FortiGate refused the user name or password');
      if (eap.code === EAP_CODE.SUCCESS) break;
      const answer = peer.respond(eap);
      ps = await this.call(EXCHANGE.IKE_AUTH, [{ type: PAYLOAD.EAP, critical: false, body: answer }]);
    }
    if (!peer.msk) throw new IkeError('EAP ended without keys');
    this.o.log('EAP-MSCHAPv2 accepted');

    // The final AUTH: signed with the MSK the password produced (RFC 7296 §2.16).
    const sa = this.sa!;
    const auth = authValue(sa.suite.prf!, peer.msk, this.initRequest, this.nr, sa.keys.skPi, this.idiBody);
    ps = await this.call(EXCHANGE.IKE_AUTH, [{ type: PAYLOAD.AUTH, critical: false, body: encodeAuth(AUTH_SHARED_KEY, auth) }]);
    this.verifyAuth(ps, peer.msk, idrBody, 'EAP');

    const cp = ps.find((p) => p.type === PAYLOAD.CP);
    const cfg = cp ? decodeCp(cp.body) : null;
    const attr = (t: number) => (cfg?.cfgType === CFG_REPLY ? cfg.attrs.filter((a) => a.type === t && a.value.length >= 4).map((a) => ip4s(a.value.subarray(0, 4))) : []);
    // INTERNAL_IP4_SUBNET: address then netmask (RFC 7296 §3.15.1); FortiClient routes these, as a split tunnel.
    const subnets =
      cfg?.cfgType === CFG_REPLY
        ? cfg.attrs
            .filter((a) => a.type === CP_ATTR.INTERNAL_IP4_SUBNET && a.value.length >= 8)
            .map((a) => `${ip4s(a.value.subarray(0, 4))}/${[...a.value.subarray(4, 8)].reduce((n, b) => n + ((b >>> 0).toString(2).match(/1/g)?.length ?? 0), 0)}`)
        : [];
    const address = attr(CP_ATTR.INTERNAL_IP4_ADDRESS)[0];
    if (!address) throw new IkeError('The FortiGate did not give this computer a VPN address');
    const saPayload = ps.find((p) => p.type === PAYLOAD.SA);
    const chosen = saPayload ? decodeSa(saPayload.body)[0] : undefined;
    if (!chosen) throw new IkeError('The gateway did not agree on the ESP settings (phase 2)');
    const espSuite = this.espSuite(chosen);
    const k = deriveChildKeys(sa.suite.prf!, sa.keys.skD, this.ni, this.nr, espSuite);
    const child: ChildSa = { spiOut: Buffer.from(chosen.spi), spiIn, suite: espSuite, ...k };
    this.children = [{ sa: child, since: Date.now() }];
    const tsr = ps.find((p) => p.type === PAYLOAD.TSr);
    const networks = tsr ? decodeTs(tsr.body) : ALL;
    this.o.log(`Tunnel agreed: VPN address ${address}, ESP AES-256 ${espSuite.integ === AUTH_HMAC_SHA2_384_192 ? 'SHA384' : 'SHA256'}, networks ${networks.map((n) => `${n.start}-${n.end}`).join(', ')}`);
    return {
      address,
      netmask: attr(CP_ATTR.INTERNAL_IP4_NETMASK)[0] ?? null,
      dns: attr(CP_ATTR.INTERNAL_IP4_DNS),
      networks,
      subnets,
      child,
      remote: { address: this.remoteAddress, port: this.remotePort },
      udpEncapsulation: this.natT,
      localPort: this.socket!.address().port,
    };
  }

  // ---------------------------------------------------------------- the gateway's requests

  /** A request from the gateway (a liveness check, a DELETE, a rekey): answered as RFC 7296 §2.2 asks. */
  private answer(sa: SaState, msg: Buffer): void {
    const h = decodeHeader(msg);
    if (h.messageId === sa.peerId && sa.lastPeerResponse) return this.send(sa.lastPeerResponse);
    if (h.messageId !== sa.peerId + 1) return;
    let ps: Payload[];
    try {
      ps = this.open_(sa, msg);
    } catch {
      return;
    }
    sa.peerId = h.messageId;
    let reply: Payload[] = [];
    let after: (() => void) | null = null;
    let ended: string | null = null;
    if (h.exchange === EXCHANGE.INFORMATIONAL) {
      for (const d of ps.filter((p) => p.type === PAYLOAD.DELETE)) {
        if (d.body[0] === PROTOCOL.IKE) {
          if (sa === this.oldSa) {
            // The IKE SA a rekey replaced: housekeeping, the tunnel goes on with the new one.
            after = () => {
              this.oldSa = null;
              this.o.log('The old IKE SA was deleted');
            };
          } else ended = 'The FortiGate ended the IPsec tunnel';
        } else if (d.body[0] === PROTOCOL.ESP && d.body[1] === 4) {
          const count = d.body.readUInt16BE(2);
          for (let i = 0; i < count; i++) {
            const spi = d.body.subarray(4 + i * 4, 8 + i * 4);
            const c = this.children.find((x) => x.sa.spiOut.equals(spi));
            if (!c) continue;
            // Answer with our side of the deleted child SA (§1.4.1).
            reply.push({ type: PAYLOAD.DELETE, critical: false, body: Buffer.concat([Buffer.from([PROTOCOL.ESP, 4, 0, 1]), c.sa.spiIn]) });
            this.dropChild(c);
          }
          if (!this.children.length) ended = 'The FortiGate ended the IPsec tunnel';
        }
      }
    } else if (h.exchange === EXCHANGE.CREATE_CHILD_SA) {
      try {
        const r = this.answerCreateChild(sa, ps);
        reply = r.reply;
        after = r.after;
      } catch (e) {
        const ie = e instanceof IkeError ? e : null;
        this.o.log(`Could not take the FortiGate's new keys: ${e instanceof Error ? e.message : String(e)}`);
        reply = [{ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: ie?.notify ?? NOTIFY.NO_PROPOSAL_CHOSEN, data: ie?.data }) }];
      }
    }
    sa.lastPeerResponse = this.encrypted(sa, h.exchange, reply, true, h.messageId);
    this.send(sa.lastPeerResponse);
    after?.();
    if (ended) this.gone(ended);
  }

  /** The gateway renews keys: a new ESP SA (with PFS when it sends a KE), or a new IKE SA (§1.3.2, §1.3.3). */
  private answerCreateChild(sa: SaState, ps: Payload[]): { reply: Payload[]; after: () => void } {
    const saPayload = ps.find((p) => p.type === PAYLOAD.SA);
    const nonce = ps.find((p) => p.type === PAYLOAD.NONCE);
    const kePayload = ps.find((p) => p.type === PAYLOAD.KE);
    if (!saPayload || !nonce) throw new IkeError('A rekey without SA or nonce', NOTIFY.INVALID_SYNTAX);
    const proposals = decodeSa(saPayload.body);
    const ni = Buffer.from(nonce.body);
    const nr = randomBytes(32);
    const ke = kePayload ? decodeKe(kePayload.body) : null;
    const keyExchange = (offered: Transform[]) => {
      if (!ke) return null;
      if (!offered.some((t) => t.id === ke.group) || !DH_GROUP[ke.group]) {
        const supported = offered.find((t) => DH_GROUP[t.id])?.id;
        if (!supported) throw new IkeError(`it asks for DH group ${ke.group}`, NOTIFY.NO_PROPOSAL_CHOSEN);
        const data = Buffer.alloc(2);
        data.writeUInt16BE(supported);
        throw new IkeError(`it sent DH group ${ke.group}, FortiConnect asks for ${supported}`, NOTIFY.INVALID_KE_PAYLOAD, data);
      }
      const dh = new DiffieHellman(ke.group);
      return { dh, secret: dh.computeSecret(ke.data) };
    };

    if (proposals[0]?.protocol === PROTOCOL.IKE) {
      const p = proposals.find((x) => x.protocol === PROTOCOL.IKE && x.spi.length === 8 && this.ikeSuite(x) && ke && ofType(x, TRANSFORM.DH).some((t) => t.id === ke.group));
      if (!p || !ke) throw new IkeError('none of its IKE proposals fits', NOTIFY.NO_PROPOSAL_CHOSEN);
      const suite = { ...this.ikeSuite(p)!, dh: ke.group };
      const x = keyExchange(ofType(p, TRANSFORM.DH))!;
      const spiR = randomBytes(8);
      const keys = deriveRekeyedIkeKeys(suite, sa.suite.prf!, sa.keys.skD, x.secret, ni, nr, p.spi, spiR);
      const chosen: Proposal = { number: p.number, protocol: PROTOCOL.IKE, spi: spiR, transforms: [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 }, { type: TRANSFORM.PRF, id: suite.prf! }, { type: TRANSFORM.INTEG, id: suite.integ }, { type: TRANSFORM.DH, id: suite.dh! }] };
      return {
        reply: [
          { type: PAYLOAD.SA, critical: false, body: encodeSa([chosen]) },
          { type: PAYLOAD.NONCE, critical: false, body: nr },
          { type: PAYLOAD.KE, critical: false, body: encodeKe(x.dh.group, x.dh.publicValue) },
        ],
        after: () => {
          // The gateway started this rekey, so it is the new IKE SA's initiator; the old one goes when it deletes it.
          this.oldSa = sa;
          this.sa = { spiI: Buffer.from(p.spi), spiR, weInitiator: false, suite, keys, nextId: 0, peerId: -1, lastPeerResponse: null, since: Date.now() };
          this.o.log('The FortiGate renewed the IKE keys');
        },
      };
    }

    const p = proposals.find((x) => {
      try {
        this.espSuite(x);
        return !ke || ofType(x, TRANSFORM.DH).length > 0;
      } catch {
        return false;
      }
    });
    if (!p) throw new IkeError('none of its ESP proposals fits', NOTIFY.NO_PROPOSAL_CHOSEN);
    const suite = this.espSuite(p);
    const x = keyExchange(ofType(p, TRANSFORM.DH));
    const spiIn = randomBytes(4);
    // The gateway started the exchange, so the first keys are its direction: our inbound.
    const k = deriveChildKeys(sa.suite.prf!, sa.keys.skD, ni, nr, suite, x?.secret);
    const child: ChildSa = { spiOut: Buffer.from(p.spi), spiIn, suite, encrOut: k.encrIn, integOut: k.integIn, encrIn: k.encrOut, integIn: k.integOut };
    const chosen: Proposal = {
      number: p.number,
      protocol: PROTOCOL.ESP,
      spi: spiIn,
      transforms: [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: suite.encr.keyLength }, { type: TRANSFORM.INTEG, id: suite.integ }, ...(x ? [{ type: TRANSFORM.DH, id: x.dh.group }] : []), { type: TRANSFORM.ESN, id: ESN_NONE }],
    };
    const tsi = ps.find((q) => q.type === PAYLOAD.TSi);
    const tsr = ps.find((q) => q.type === PAYLOAD.TSr);
    return {
      reply: [
        { type: PAYLOAD.SA, critical: false, body: encodeSa([chosen]) },
        { type: PAYLOAD.NONCE, critical: false, body: nr },
        ...(x ? [{ type: PAYLOAD.KE, critical: false, body: encodeKe(x.dh.group, x.dh.publicValue) }] : []),
        { type: PAYLOAD.TSi, critical: false, body: tsi ? Buffer.from(tsi.body) : encodeTs(ALL) },
        { type: PAYLOAD.TSr, critical: false, body: tsr ? Buffer.from(tsr.body) : encodeTs(ALL) },
      ],
      after: () => {
        this.addChild(child);
        this.o.log(`The FortiGate renewed the IPsec keys${x ? ` (PFS, DH group ${x.dh.group})` : ''}`);
      },
    };
  }

  private addChild(child: ChildSa): void {
    this.children.push({ sa: child, since: Date.now() });
    this.events?.child?.(child);
  }

  private dropChild(c: ChildState): void {
    this.children = this.children.filter((x) => x !== c);
    this.events?.childGone?.(c.sa.spiIn);
  }

  // ---------------------------------------------------------------- our own rekeys

  /** Renew a little before the lifetime runs out (10 % of it, at most 10 minutes, a bit earlier at random). */
  private rekeyDue(since: number, lifetimeS: number): boolean {
    const margin = Math.min(600, lifetimeS * 0.1) * (1 + 0.5 * this.rekeyJitter);
    return Date.now() - since >= (lifetimeS - margin) * 1000;
  }

  private checkLifetimes(): void {
    if (this.rekeying || this.closed || !this.sa || !this.events) return;
    const current = this.children[this.children.length - 1];
    const ikeDue = this.rekeyDue(this.sa.since, this.o.lifetimes?.ike ?? 86400);
    const childDue = !!current && this.rekeyDue(current.since, this.o.lifetimes?.child ?? 43200);
    if (!ikeDue && !childDue) return;
    this.rekeying = true;
    this.ownRequest(() => (ikeDue ? this.rekeyIke() : this.rekeyChild(current)))
      .catch((e: Error) => {
        if (!this.closed && e.message !== 'Cancelled') this.o.log(`Renewing the ${ikeDue ? 'IKE' : 'IPsec'} keys failed: ${e.message}`);
      })
      .finally(() => (this.rekeying = false));
  }

  /** New ESP keys from our side (with PFS), then the old SA deleted (§1.3.3). */
  private async rekeyChild(old: ChildState): Promise<void> {
    const sa = this.sa!;
    let group: number | null = this.o.pfsGroup === undefined ? (sa.suite.dh ?? null) : this.o.pfsGroup;
    for (let tries = 0; tries < 3; tries++) {
      const spiIn = randomBytes(4);
      const ni = randomBytes(32);
      const dh = group ? new DiffieHellman(group) : null;
      const rekeyNotify = encodeNotify({ protocol: PROTOCOL.ESP, type: NOTIFY.REKEY_SA, spi: old.sa.spiIn });
      let ps: Payload[];
      try {
        ps = await this.call(EXCHANGE.CREATE_CHILD_SA, [
          { type: PAYLOAD.NOTIFY, critical: false, body: rekeyNotify },
          { type: PAYLOAD.SA, critical: false, body: encodeSa([this.espProposal(spiIn, group)]) },
          { type: PAYLOAD.NONCE, critical: false, body: ni },
          ...(dh ? [{ type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) }] : []),
          { type: PAYLOAD.TSi, critical: false, body: encodeTs(ALL) },
          { type: PAYLOAD.TSr, critical: false, body: encodeTs(ALL) },
        ]);
      } catch (e) {
        const wanted = e instanceof IkeError && e.notify === NOTIFY.INVALID_KE_PAYLOAD && e.data && e.data.length >= 2 ? e.data.readUInt16BE(0) : 0;
        if (wanted && DH_GROUP[wanted] && wanted !== group) {
          this.o.log(`The gateway wants DH group ${wanted} for the new IPsec keys; asking again`);
          group = wanted;
          continue;
        }
        if (e instanceof IkeError && e.notify === NOTIFY.NO_PROPOSAL_CHOSEN && group) {
          group = null;
          continue;
        }
        throw e;
      }
      const chosenPayload = ps.find((p) => p.type === PAYLOAD.SA);
      const nonce = ps.find((p) => p.type === PAYLOAD.NONCE);
      const kePayload = ps.find((p) => p.type === PAYLOAD.KE);
      const chosen = chosenPayload ? decodeSa(chosenPayload.body)[0] : undefined;
      if (!nonce) throw new IkeError('The gateway answered the rekey without a nonce');
      const suite = this.espSuite(chosen);
      const secret = dh && kePayload ? dh.computeSecret(decodeKe(kePayload.body).data) : undefined;
      const k = deriveChildKeys(sa.suite.prf!, sa.keys.skD, ni, Buffer.from(nonce.body), suite, secret);
      this.addChild({ spiOut: Buffer.from(chosen!.spi), spiIn, suite, ...k });
      this.o.log(`Renewed the IPsec keys${secret ? ` (PFS, DH group ${group})` : ''}`);
      // The rekey's initiator deletes the old SA.
      await this.informational([{ type: PAYLOAD.DELETE, critical: false, body: Buffer.concat([Buffer.from([PROTOCOL.ESP, 4, 0, 1]), old.sa.spiIn]) }]).catch(() => undefined);
      this.dropChild(old);
      return;
    }
    throw new IkeError('The gateway refused every key exchange FortiConnect offered for the new IPsec keys');
  }

  /** A new IKE SA from our side; the ESP SAs move to it, and the old IKE SA is deleted (§2.18). */
  private async rekeyIke(): Promise<void> {
    const sa = this.sa!;
    const group = sa.suite.dh ?? 20;
    const dh = new DiffieHellman(group);
    const spiI = randomBytes(8);
    const ni = randomBytes(32);
    const ps = await this.call(EXCHANGE.CREATE_CHILD_SA, [
      { type: PAYLOAD.SA, critical: false, body: encodeSa([this.ikeProposal([group], spiI)]) },
      { type: PAYLOAD.NONCE, critical: false, body: ni },
      { type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) },
    ]);
    const chosenPayload = ps.find((p) => p.type === PAYLOAD.SA);
    const nonce = ps.find((p) => p.type === PAYLOAD.NONCE);
    const kePayload = ps.find((p) => p.type === PAYLOAD.KE);
    const chosen = chosenPayload ? decodeSa(chosenPayload.body)[0] : undefined;
    const suite = chosen && chosen.spi.length === 8 ? this.ikeSuite(chosen) : null;
    if (!chosen || !suite || !nonce || !kePayload) throw new IkeError('The gateway answered the IKE rekey with something FortiConnect cannot use');
    const secret = dh.computeSecret(decodeKe(kePayload.body).data);
    const keys = deriveRekeyedIkeKeys(suite, sa.suite.prf!, sa.keys.skD, secret, ni, Buffer.from(nonce.body), spiI, chosen.spi);
    this.oldSa = sa;
    this.sa = { spiI, spiR: Buffer.from(chosen.spi), weInitiator: true, suite, keys, nextId: 0, peerId: -1, lastPeerResponse: null, since: Date.now() };
    this.o.log('Renewed the IKE keys');
    await this.informational([{ type: PAYLOAD.DELETE, critical: false, body: Buffer.from([PROTOCOL.IKE, 0, 0, 0]) }], sa).catch(() => undefined);
    this.oldSa = null;
  }

  /** Tell the gateway the IKE SA is gone (INFORMATIONAL with DELETE), without waiting long for its answer. */
  async delete(): Promise<void> {
    const sa = this.sa;
    if (!sa || !this.socket) return this.close();
    this.events = null;
    try {
      const id = sa.nextId++;
      this.send(this.encrypted(sa, EXCHANGE.INFORMATIONAL, [{ type: PAYLOAD.DELETE, critical: false, body: Buffer.from([PROTOCOL.IKE, 0, 0, 0]) }], false, id));
      await new Promise((r) => setTimeout(r, 300));
    } finally {
      this.close();
    }
  }
}
