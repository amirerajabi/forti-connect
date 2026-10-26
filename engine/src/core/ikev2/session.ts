// An IKEv2 initiator for a FortiGate dial-up tunnel as FortiClient sets one up: IKE_SA_INIT, then IKE_AUTH where the
// gateway proves itself with the pre-shared key and the user logs in with EAP-MSCHAPv2, asking for a VPN address (mode
// config). The result is the ESP keys and addresses the data path (the VPN helper) needs. Rekeying and dead peer
// detection run on the established session (`IkeSession`), which also answers the gateway's INFORMATIONAL requests.
import * as dgram from 'node:dgram';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { authValue, decryptSk, deriveChildKeys, deriveIkeKeys, DiffieHellman, encryptSk, icv, INTEG, randomBytes, type IkeKeys, type Suite } from './crypto';
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

const INTEG_ID: Record<Integ, number> = { sha256: AUTH_HMAC_SHA2_256_128, sha384: AUTH_HMAC_SHA2_384_192 };
const PRF_ID: Record<Integ, number> = { sha256: PRF_HMAC_SHA2_256, sha384: PRF_HMAC_SHA2_384 };
const NON_ESP_MARKER = Buffer.alloc(4);

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

export class IkeError extends Error {}

/** One IKEv2 negotiation with a FortiGate, from the first packet to the ESP keys. */
export class IkeSession {
  private socket: dgram.Socket | null = null;
  private remoteAddress = '';
  private remotePort = 500;
  private natT = false;
  private spiI = randomBytes(8);
  private spiR = Buffer.alloc(8);
  private messageId = 0;
  private suite: Suite | null = null;
  private keys: IkeKeys | null = null;
  private ni = randomBytes(32);
  private nr = Buffer.alloc(0);
  private initRequest = Buffer.alloc(0);
  private initResponse = Buffer.alloc(0);
  private idiBody = Buffer.alloc(0);
  private pending: { resolve: (b: Buffer) => void; match: (b: Buffer) => boolean } | null = null;
  private closed = false;
  // ---- after the login: the gateway's own requests, liveness, and ESP on the same socket
  private peerMessageId = -1;
  private lastPeerResponse: Buffer | null = null;
  private lastHeard = Date.now();
  private timers: NodeJS.Timeout[] = [];
  private checking = false;
  private espHandler: ((data: Buffer) => void) | null = null;
  private goneHandler: ((reason: string) => void) | null = null;
  private childSpiIn: Buffer | null = null;

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
   * Keep the established tunnel going: ESP packets from the gateway go to `onEsp`; the gateway's liveness checks are
   * answered; a NAT keepalive goes out every 20 s; when nothing has come from the gateway for 30 s FortiConnect asks it
   * itself (an empty INFORMATIONAL), and `onGone` hears when the gateway ends the tunnel or stops answering.
   */
  keepAlive(onEsp: (data: Buffer) => void, onGone: (reason: string) => void, o: { keepaliveMs?: number; idleMs?: number } = {}): void {
    this.espHandler = onEsp;
    this.goneHandler = onGone;
    this.lastHeard = Date.now();
    if (this.natT) this.timers.push(setInterval(() => this.socket?.send(Buffer.from([0xff]), this.remotePort, this.remoteAddress), o.keepaliveMs ?? 20_000));
    const idle = o.idleMs ?? 30_000;
    this.timers.push(
      setInterval(() => {
        if (this.checking || this.closed || Date.now() - this.lastHeard < idle) return;
        this.checking = true;
        this.messageId++;
        const id = this.messageId;
        this.request(this.encrypted(EXCHANGE.INFORMATIONAL, []), EXCHANGE.INFORMATIONAL, id).then(
          () => {
            this.checking = false;
            this.lastHeard = Date.now();
          },
          (e: Error) => {
            this.checking = false;
            if (!this.closed && e.message !== 'Cancelled') this.gone('The FortiGate stopped answering (dead peer detection)');
          },
        );
      }, Math.min(10_000, idle)),
    );
  }

  /** An ESP packet to the gateway, on the IKE socket so it follows the same NAT mapping. */
  sendEsp(data: Buffer): void {
    this.socket?.send(data, this.remotePort, this.remoteAddress);
  }

  private gone(reason: string): void {
    const h = this.goneHandler;
    this.goneHandler = null;
    this.o.log(reason);
    h?.(reason);
  }

  private onMessage(msg: Buffer, rinfo: dgram.RemoteInfo): void {
    if (rinfo.address !== this.remoteAddress) return;
    let ike = msg;
    if (rinfo.port === (this.o.natPort ?? 4500) && this.natT) {
      // NAT-T: IKE behind a zero marker; a single 0xFF byte is a keepalive; anything else on 4500 is ESP.
      if (msg.length === 1 && msg[0] === 0xff) return;
      if (msg.length < 4 || !msg.subarray(0, 4).equals(NON_ESP_MARKER)) {
        this.lastHeard = Date.now();
        this.espHandler?.(msg);
        return;
      }
      ike = msg.subarray(4);
    }
    if (ike.length < HEADER_LENGTH || !ike.subarray(0, 8).equals(this.spiI)) return;
    this.lastHeard = Date.now();
    const flags = ike[19];
    if ((flags & FLAG.RESPONSE) === 0) {
      if (this.keys && this.goneHandler) this.answer(ike);
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
  private request(packet: Buffer, exchange: number, messageId: number): Promise<Buffer> {
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
          return h.exchange === exchange && h.messageId === messageId && (h.flags & FLAG.RESPONSE) !== 0;
        },
        resolve: (b) => {
          clearTimeout(timer);
          resolve(b);
        },
      };
      attempt();
    });
  }

  // ---------------------------------------------------------------- IKE_SA_INIT

  private natHash(spiR: Buffer, address: string, port: number): Buffer {
    const p = Buffer.alloc(2);
    p.writeUInt16BE(port);
    return createHash('sha1').update(Buffer.concat([this.spiI, spiR, ip4(address), p])).digest();
  }

  private ikeProposal(dh: number[]): Proposal {
    const integ = this.o.ike?.integ ?? ['sha384', 'sha256'];
    return {
      number: 1,
      protocol: PROTOCOL.IKE,
      spi: Buffer.alloc(0),
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
      const res = await this.request(this.initRequest, EXCHANGE.IKE_SA_INIT, 0);
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
      if (err) throw new IkeError(notifyError(err.type));

      const sa = ps.find((p) => p.type === PAYLOAD.SA);
      const ke = ps.find((p) => p.type === PAYLOAD.KE);
      const nonce = ps.find((p) => p.type === PAYLOAD.NONCE);
      if (!sa || !ke || !nonce) throw new IkeError('The gateway answered IKE_SA_INIT without SA, KE or nonce');
      const chosen = decodeSa(sa.body)[0];
      const pick = (t: number) => chosen?.transforms.find((x) => x.type === t);
      const encr = pick(TRANSFORM.ENCR);
      const integ = pick(TRANSFORM.INTEG)?.id;
      const prfId = pick(TRANSFORM.PRF)?.id;
      const group = pick(TRANSFORM.DH)?.id;
      if (!encr || encr.id !== ENCR_AES_CBC || !integ || !INTEG[integ] || !prfId || group !== dh.group) throw new IkeError('The gateway chose IKE algorithms this profile did not offer');
      this.suite = { encr: { id: ENCR_AES_CBC, keyLength: (encr.keyLength ?? 256) as 256 }, integ, prf: prfId, dh: group };
      this.spiR = Buffer.from(h.spiR);
      this.nr = Buffer.from(nonce.body);
      this.initResponse = Buffer.from(res.subarray(0, h.length));
      const secret = dh.computeSecret(decodeKe(ke.body).data);
      this.keys = deriveIkeKeys(this.suite, secret, this.ni, this.nr, this.spiI, this.spiR);
      this.o.log(`IKE_SA_INIT done: ${encr.keyLength ?? 256}-bit AES, ${integ === AUTH_HMAC_SHA2_384_192 ? 'SHA384' : 'SHA256'}, DH group ${group}`);

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

  // ---------------------------------------------------------------- IKE_AUTH

  /** A request from the gateway (a liveness check, a DELETE, a rekey): answered as RFC 7296 §2.2 asks. */
  private answer(msg: Buffer): void {
    const h = decodeHeader(msg);
    if (h.messageId === this.peerMessageId && this.lastPeerResponse) return this.send(this.lastPeerResponse);
    if (h.messageId !== this.peerMessageId + 1) return;
    let ps: Payload[];
    try {
      ps = this.open_(msg);
    } catch {
      return;
    }
    this.peerMessageId = h.messageId;
    const reply: Payload[] = [];
    let ended: string | null = null;
    if (h.exchange === EXCHANGE.INFORMATIONAL) {
      for (const d of ps.filter((p) => p.type === PAYLOAD.DELETE)) {
        if (d.body[0] === PROTOCOL.IKE) ended = 'The FortiGate ended the IPsec tunnel';
        else if (d.body[0] === PROTOCOL.ESP && this.childSpiIn) {
          // Answer with our side of the deleted child SA (§1.4.1).
          const body = Buffer.concat([Buffer.from([PROTOCOL.ESP, 4, 0, 1]), this.childSpiIn]);
          reply.push({ type: PAYLOAD.DELETE, critical: false, body });
          ended = 'The FortiGate ended the IPsec tunnel';
        }
      }
    } else if (h.exchange === EXCHANGE.CREATE_CHILD_SA) {
      // Rekeying comes later: say no, and the gateway keeps the current keys until they expire.
      this.o.log('The FortiGate asked for new IPsec keys; FortiConnect cannot rekey yet');
      reply.push({ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NO_ADDITIONAL_SAS }) });
    }
    this.lastPeerResponse = this.encrypted(h.exchange, reply, FLAG.INITIATOR | FLAG.RESPONSE, h.messageId);
    this.send(this.lastPeerResponse);
    if (ended) this.gone(ended);
  }

  private encrypted(exchange: number, payloads: Payload[], flags: number = FLAG.INITIATOR, messageId = this.messageId): Buffer {
    const s = this.suite!;
    const k = this.keys!;
    const inner = encodePayloads(payloads);
    const body = encryptSk(s, k.skEi, inner);
    const icvLen = INTEG[s.integ].icvLength;
    const total = HEADER_LENGTH + 4 + body.length + icvLen;
    const header = encodeHeader({ spiI: this.spiI, spiR: this.spiR, next: PAYLOAD.SK, exchange, flags, messageId }, total);
    const sk = Buffer.from([payloads[0]?.type ?? PAYLOAD.NONE, 0, 0, 0]);
    sk.writeUInt16BE(4 + body.length + icvLen, 2);
    const unsigned = Buffer.concat([header, sk, body]);
    return Buffer.concat([unsigned, icv(s, k.skAi, unsigned)]);
  }

  /** Decrypt a response: its payloads, in order. */
  private open_(msg: Buffer): Payload[] {
    const h = decodeHeader(msg);
    const m = msg.subarray(0, h.length);
    if (h.next !== PAYLOAD.SK) {
      // Only an unprotected error may come back unencrypted (e.g. INVALID_SYNTAX before keys).
      const ps = decodePayloads(h.next, m.subarray(HEADER_LENGTH));
      const n = ps.find((p) => p.type === PAYLOAD.NOTIFY);
      throw new IkeError(n ? notifyError(decodeNotify(n.body).type) : 'The gateway answered without encryption');
    }
    const first = m[HEADER_LENGTH];
    const skLen = m.readUInt16BE(HEADER_LENGTH + 2);
    const body = m.subarray(HEADER_LENGTH + 4, HEADER_LENGTH + skLen);
    const inner = decryptSk(this.suite!, this.keys!.skEr, this.keys!.skAr, m, body);
    return decodePayloads(first, inner);
  }

  private async exchange(payloads: Payload[]): Promise<Payload[]> {
    this.messageId++;
    const msg = this.encrypted(EXCHANGE.IKE_AUTH, payloads);
    const res = await this.request(msg, EXCHANGE.IKE_AUTH, this.messageId);
    const ps = this.open_(res);
    const err = ps.filter((p) => p.type === PAYLOAD.NOTIFY).map((p) => decodeNotify(p.body)).find((n) => n.type < 16384);
    if (err) throw new IkeError(notifyError(err.type));
    return ps;
  }

  private espProposal(spi: Buffer): Proposal {
    const integ = this.o.esp?.integ ?? ['sha256', 'sha384'];
    return {
      number: 1,
      protocol: PROTOCOL.ESP,
      spi,
      transforms: [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 }, ...integ.map((i) => ({ type: TRANSFORM.INTEG, id: INTEG_ID[i] })), { type: TRANSFORM.ESN, id: ESN_NONE }],
    };
  }

  private verifyAuth(ps: Payload[], secret: Buffer, idrBody: Buffer, what: string): void {
    const auth = ps.find((p) => p.type === PAYLOAD.AUTH);
    if (!auth) throw new IkeError(`The gateway did not prove itself (${what})`);
    const a = decodeAuth(auth.body);
    if (a.method !== AUTH_SHARED_KEY) throw new IkeError(`The gateway proved itself with method ${a.method}; FortiConnect expects a pre-shared key`);
    const want = authValue(this.suite!.prf!, secret, this.initResponse, this.ni, this.keys!.skPr, idrBody);
    if (!want.equals(a.data)) throw new IkeError(what === 'pre-shared key' ? 'The pre-shared key does not match the FortiGate' : 'The gateway could not prove the login (EAP keys differ)');
  }

  private async auth(): Promise<IkeResult> {
    const id = this.o.localId || this.o.userName;
    // FortiClient sends its local ID as a key ID unless it looks like an FQDN or e-mail address.
    const idType = /@/.test(id) ? ID_TYPE.RFC822_ADDR : ID_TYPE.KEY_ID;
    this.idiBody = encodeId(idType, Buffer.from(id, 'utf8'));
    const spiIn = randomBytes(4);
    const all: TrafficSelector[] = [{ start: '0.0.0.0', end: '255.255.255.255' }];
    this.o.log(`IKE_AUTH as "${id}", user ${this.o.userName} (EAP)`);
    let ps = await this.exchange([
      { type: PAYLOAD.IDi, critical: false, body: this.idiBody },
      { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.INITIAL_CONTACT }) },
      { type: PAYLOAD.CP, critical: false, body: encodeCp(CFG_REQUEST, [CP_ATTR.INTERNAL_IP4_ADDRESS, CP_ATTR.INTERNAL_IP4_NETMASK, CP_ATTR.INTERNAL_IP4_DNS, CP_ATTR.INTERNAL_IP4_SUBNET].map((type) => ({ type, value: Buffer.alloc(0) }))) },
      { type: PAYLOAD.SA, critical: false, body: encodeSa([this.espProposal(spiIn)]) },
      { type: PAYLOAD.TSi, critical: false, body: encodeTs(all) },
      { type: PAYLOAD.TSr, critical: false, body: encodeTs(all) },
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
      ps = await this.exchange([{ type: PAYLOAD.EAP, critical: false, body: answer }]);
    }
    if (!peer.msk) throw new IkeError('EAP ended without keys');
    this.o.log('EAP-MSCHAPv2 accepted');

    // The final AUTH: signed with the MSK the password produced (RFC 7296 §2.16).
    const auth = authValue(this.suite!.prf!, peer.msk, this.initRequest, this.nr, this.keys!.skPi, this.idiBody);
    ps = await this.exchange([{ type: PAYLOAD.AUTH, critical: false, body: encodeAuth(AUTH_SHARED_KEY, auth) }]);
    this.verifyAuth(ps, peer.msk, idrBody, 'EAP');

    const cp = ps.find((p) => p.type === PAYLOAD.CP);
    const cfg = cp ? decodeCp(cp.body) : null;
    const attr = (t: number) => (cfg?.cfgType === CFG_REPLY ? cfg.attrs.filter((a) => a.type === t && a.value.length >= 4).map((a) => ip4s(a.value.subarray(0, 4))) : []);
    // INTERNAL_IP4_SUBNET: address then netmask (RFC 7296 §3.15.1); FortiClient routes these, as a split tunnel.
    const subnets = cfg?.cfgType === CFG_REPLY
      ? cfg.attrs
          .filter((a) => a.type === CP_ATTR.INTERNAL_IP4_SUBNET && a.value.length >= 8)
          .map((a) => `${ip4s(a.value.subarray(0, 4))}/${[...a.value.subarray(4, 8)].reduce((n, b) => n + ((b >>> 0).toString(2).match(/1/g)?.length ?? 0), 0)}`)
      : [];
    const address = attr(CP_ATTR.INTERNAL_IP4_ADDRESS)[0];
    if (!address) throw new IkeError('The FortiGate did not give this computer a VPN address');
    const sa = ps.find((p) => p.type === PAYLOAD.SA);
    const chosen = sa ? decodeSa(sa.body)[0] : null;
    if (!chosen || chosen.protocol !== PROTOCOL.ESP || chosen.spi.length !== 4) throw new IkeError('The gateway did not agree on the ESP settings (phase 2)');
    const integ = chosen.transforms.find((t) => t.type === TRANSFORM.INTEG)?.id;
    const encr = chosen.transforms.find((t) => t.type === TRANSFORM.ENCR);
    if (!integ || !INTEG[integ] || !encr || encr.id !== ENCR_AES_CBC) throw new IkeError('The gateway chose ESP algorithms this profile did not offer');
    const espSuite: Suite = { encr: { id: ENCR_AES_CBC, keyLength: (encr.keyLength ?? 256) as 256 }, integ };
    const k = deriveChildKeys(this.suite!.prf!, this.keys!.skD, this.ni, this.nr, espSuite);
    this.childSpiIn = spiIn;
    const tsr = ps.find((p) => p.type === PAYLOAD.TSr);
    const networks = tsr ? decodeTs(tsr.body) : all;
    this.o.log(`Tunnel agreed: VPN address ${address}, ESP AES-256 ${integ === AUTH_HMAC_SHA2_384_192 ? 'SHA384' : 'SHA256'}, networks ${networks.map((n) => `${n.start}-${n.end}`).join(', ')}`);
    return {
      address,
      netmask: attr(CP_ATTR.INTERNAL_IP4_NETMASK)[0] ?? null,
      dns: attr(CP_ATTR.INTERNAL_IP4_DNS),
      networks,
      subnets,
      child: { spiOut: Buffer.from(chosen.spi), spiIn, suite: espSuite, ...k },
      remote: { address: this.remoteAddress, port: this.remotePort },
      udpEncapsulation: this.natT,
      localPort: this.socket!.address().port,
    };
  }

  /** Tell the gateway the IKE SA is gone (INFORMATIONAL with DELETE), without waiting long for its answer. */
  async delete(): Promise<void> {
    if (!this.keys || !this.socket) return this.close();
    this.goneHandler = null;
    try {
      this.messageId++;
      const msg = this.encrypted(EXCHANGE.INFORMATIONAL, [{ type: PAYLOAD.DELETE, critical: false, body: Buffer.from([PROTOCOL.IKE, 0, 0, 0]) }]);
      this.send(msg);
      await new Promise((r) => setTimeout(r, 300));
    } finally {
      this.close();
    }
  }
}
