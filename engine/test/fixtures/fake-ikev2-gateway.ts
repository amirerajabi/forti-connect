// A small IKEv2 responder for the engine tests, written from RFC 7296 / RFC 2759 like the initiator but from the other
// side: it answers IKE_SA_INIT, proves itself with a pre-shared key, runs EAP-MSCHAPv2 against a known password,
// checks the initiator's final AUTH and hands out a VPN address and ESP keys, the way a FortiGate dial-up tunnel does.
import { createHash } from 'node:crypto';
import * as dgram from 'node:dgram';
import { authValue, decryptSk, deriveChildKeys, deriveIkeKeys, DiffieHellman, encryptSk, icv, INTEG, randomBytes, type IkeKeys, type Suite } from '../../src/core/ikev2/crypto';
import { Esp } from '../../src/core/ikev2/esp';
import { authenticatorResponse, decodeEap, EAP_CODE, EAP_TYPE, encodeEap, generateNtResponse, mschapv2Msk } from '../../src/core/ikev2/mschapv2';
import {
  AUTH_SHARED_KEY,
  CFG_REPLY,
  CP_ATTR,
  decodeAuth,
  decodeHeader,
  decodeKe,
  decodePayloads,
  decodeSa,
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
  EXCHANGE,
  FLAG,
  HEADER_LENGTH,
  ID_TYPE,
  ip4,
  NOTIFY,
  PAYLOAD,
  PROTOCOL,
  TRANSFORM,
  type Payload,
} from '../../src/core/ikev2/payloads';

export interface FakeGatewayOptions {
  psk: string;
  userName: string;
  password: string;
  /** Only accept this group in IKE_SA_INIT (answers INVALID_KE_PAYLOAD otherwise). */
  group?: number;
}

export interface FakeGateway {
  port: number;
  /** Inner packets the gateway received over ESP (it sends each one straight back). */
  received: Buffer[];
  /** The gateway's own request: an empty INFORMATIONAL (a liveness check); resolves with the answer's payload types. */
  probe(): Promise<number[]>;
  /** The gateway ends the IKE SA. */
  deleteIke(): Promise<void>;
  /** What the gateway saw and decided, for the test to check. */
  seen: { idi?: string; idType?: number; childSpiIn?: Buffer; childKeys?: ReturnType<typeof deriveChildKeys>; espSuite?: Suite };
  close(): void;
}

export async function startFakeGateway(o: FakeGatewayOptions): Promise<FakeGateway> {
  const sock = dgram.createSocket('udp4');
  await new Promise<void>((r) => sock.bind(0, '127.0.0.1', r));
  const port = sock.address().port;
  const seen: FakeGateway['seen'] = {};
  const spiR = randomBytes(8);
  let spiI = Buffer.alloc(8);
  let suite: Suite;
  let keys: IkeKeys;
  let ni = Buffer.alloc(0);
  const nr = randomBytes(32);
  let initRequest = Buffer.alloc(0);
  let initResponse = Buffer.alloc(0);
  const idrBody = encodeId(ID_TYPE.KEY_ID, Buffer.from('fortigate', 'utf8'));
  let idiBody = Buffer.alloc(0);
  let espProposalSpi = Buffer.alloc(0);
  let espIntegId = 0;
  const authChallenge = randomBytes(16);
  let ntResponse: Buffer | null = null;
  let peerChallenge: Buffer | null = null;
  let msk: Buffer | null = null;
  let stage = 0;
  let esp: Esp | null = null;
  let client: dgram.RemoteInfo | null = null;
  const received: Buffer[] = [];
  let ownMessageId = 0;
  const waiting = new Map<number, (types: number[]) => void>();

  // In the tests the "NAT-T" port is the same socket: everything after IKE_SA_INIT carries the zero marker.
  const reply = (data: Buffer, rinfo: dgram.RemoteInfo, marker: boolean) => sock.send(marker ? Buffer.concat([Buffer.alloc(4), data]) : data, rinfo.port, rinfo.address);

  const encrypted = (messageId: number, payloads: Payload[], exchange: number = EXCHANGE.IKE_AUTH) => {
    const inner = encodePayloads(payloads);
    const body = encryptSk(suite, keys.skEr, inner);
    const icvLen = INTEG[suite.integ].icvLength;
    const header = encodeHeader({ spiI, spiR, next: PAYLOAD.SK, exchange, flags: FLAG.RESPONSE, messageId }, HEADER_LENGTH + 4 + body.length + icvLen);
    const sk = Buffer.from([payloads[0]?.type ?? PAYLOAD.NONE, 0, 0, 0]);
    sk.writeUInt16BE(4 + body.length + icvLen, 2);
    const unsigned = Buffer.concat([header, sk, body]);
    return Buffer.concat([unsigned, icv(suite, keys.skAr, unsigned)]);
  };

  /** A request from the gateway (it is the IKE responder, so its messages carry neither I nor R flag). */
  const own = (exchange: number, payloads: Payload[]) => {
    const id = ownMessageId++;
    const inner = encodePayloads(payloads);
    const body = encryptSk(suite, keys.skEr, inner);
    const icvLen = INTEG[suite.integ].icvLength;
    const header = encodeHeader({ spiI, spiR, next: PAYLOAD.SK, exchange, flags: 0, messageId: id }, HEADER_LENGTH + 4 + body.length + icvLen);
    const sk = Buffer.from([payloads[0]?.type ?? PAYLOAD.NONE, 0, 0, 0]);
    sk.writeUInt16BE(4 + body.length + icvLen, 2);
    const unsigned = Buffer.concat([header, sk, body]);
    return new Promise<number[]>((resolve) => {
      waiting.set(id, resolve);
      reply(Buffer.concat([unsigned, icv(suite, keys.skAr, unsigned)]), client!, true);
    });
  };

  sock.on('message', (raw, rinfo) => {
    if (raw.length === 1 && raw[0] === 0xff) return;
    const marker = raw.length >= 4 && raw.readUInt32BE(0) === 0;
    if (!marker && esp && stage === 5) {
      // ESP from the client: deliver (here: keep) the packet and send it straight back.
      try {
        const inner = esp.decapsulate(raw);
        received.push(inner);
        sock.send(esp.encapsulate(inner), rinfo.port, rinfo.address);
      } catch {
        /* not for us */
      }
      return;
    }
    const msg = marker ? raw.subarray(4) : raw;
    const h = decodeHeader(msg);
    if (h.exchange === EXCHANGE.IKE_SA_INIT) {
      const ps = decodePayloads(h.next, msg.subarray(HEADER_LENGTH, h.length));
      const proposal = decodeSa(ps.find((p) => p.type === PAYLOAD.SA)!.body)[0];
      const ke = decodeKe(ps.find((p) => p.type === PAYLOAD.KE)!.body);
      if (o.group && ke.group !== o.group) {
        const data = Buffer.alloc(2);
        data.writeUInt16BE(o.group);
        return reply(encodeMessage({ spiI: h.spiI, spiR: Buffer.alloc(8), exchange: EXCHANGE.IKE_SA_INIT, flags: FLAG.RESPONSE, messageId: 0 }, [{ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.INVALID_KE_PAYLOAD, data }) }]), rinfo, false);
      }
      spiI = Buffer.from(h.spiI);
      ni = Buffer.from(ps.find((p) => p.type === PAYLOAD.NONCE)!.body);
      initRequest = Buffer.from(msg.subarray(0, h.length));
      const integ = proposal.transforms.find((t) => t.type === TRANSFORM.INTEG)!.id;
      const prfId = proposal.transforms.find((t) => t.type === TRANSFORM.PRF)!.id;
      suite = { encr: { id: ENCR_AES_CBC, keyLength: 256 }, integ, prf: prfId, dh: ke.group };
      const dh = new DiffieHellman(ke.group);
      const chosen = { number: 1, protocol: PROTOCOL.IKE, spi: Buffer.alloc(0), transforms: [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 }, { type: TRANSFORM.PRF, id: prfId }, { type: TRANSFORM.INTEG, id: integ }, { type: TRANSFORM.DH, id: ke.group }] };
      const natData = createHash('sha1').update(Buffer.concat([spiI, spiR, ip4('203.0.113.9'), Buffer.from([0x01, 0xf4])])).digest();
      initResponse = encodeMessage({ spiI, spiR, exchange: EXCHANGE.IKE_SA_INIT, flags: FLAG.RESPONSE, messageId: 0 }, [
        { type: PAYLOAD.SA, critical: false, body: encodeSa([chosen]) },
        { type: PAYLOAD.KE, critical: false, body: encodeKe(ke.group, dh.publicValue) },
        { type: PAYLOAD.NONCE, critical: false, body: nr },
        { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NAT_DETECTION_SOURCE_IP, data: natData }) },
        { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NAT_DETECTION_DESTINATION_IP, data: natData }) },
      ]);
      keys = deriveIkeKeys(suite, dh.computeSecret(ke.data), ni, nr, spiI, spiR);
      return reply(initResponse, rinfo, false);
    }
    const m = msg.subarray(0, h.length);
    if (h.flags & FLAG.RESPONSE) {
      // The client's answer to one of the gateway's own requests.
      const inner = decryptSk(suite, keys.skEi, keys.skAi, m, m.subarray(HEADER_LENGTH + 4, HEADER_LENGTH + m.readUInt16BE(HEADER_LENGTH + 2)));
      const types = decodePayloads(m[HEADER_LENGTH], inner).map((p) => p.type);
      waiting.get(h.messageId)?.(types);
      waiting.delete(h.messageId);
      return;
    }
    if (h.exchange === EXCHANGE.INFORMATIONAL && stage === 5) {
      // The client's liveness check or DELETE: an empty answer.
      return reply(encrypted(h.messageId, [], EXCHANGE.INFORMATIONAL), rinfo, true);
    }
    if (h.exchange !== EXCHANGE.IKE_AUTH) return;
    const inner = decryptSk(suite, keys.skEi, keys.skAi, m, m.subarray(HEADER_LENGTH + 4, HEADER_LENGTH + m.readUInt16BE(HEADER_LENGTH + 2)));
    const ps = decodePayloads(m[HEADER_LENGTH], inner);
    client = rinfo;
    const send = (payloads: Payload[]) => reply(encrypted(h.messageId, payloads), rinfo, true);
    if (stage === 0) {
      const idi = ps.find((p) => p.type === PAYLOAD.IDi)!;
      idiBody = Buffer.from(idi.body);
      seen.idType = idi.body[0];
      seen.idi = idi.body.subarray(4).toString('utf8');
      const esp = decodeSa(ps.find((p) => p.type === PAYLOAD.SA)!.body)[0];
      espProposalSpi = esp.spi;
      espIntegId = esp.transforms.find((t) => t.type === TRANSFORM.INTEG)!.id;
      stage = 1;
      const auth = authValue(suite.prf!, Buffer.from(o.psk, 'utf8'), initResponse, ni, keys.skPr, idrBody);
      return send([
        { type: PAYLOAD.IDr, critical: false, body: idrBody },
        { type: PAYLOAD.AUTH, critical: false, body: encodeAuth(AUTH_SHARED_KEY, auth) },
        { type: PAYLOAD.EAP, critical: false, body: encodeEap({ code: EAP_CODE.REQUEST, id: 1, type: EAP_TYPE.IDENTITY, data: Buffer.alloc(0) }) },
      ]);
    }
    const eapIn = ps.find((p) => p.type === PAYLOAD.EAP);
    if (stage === 1 && eapIn) {
      stage = 2;
      const name = Buffer.from('fortigate');
      const ms = Buffer.alloc(5);
      ms[0] = 1;
      ms[1] = 7;
      ms.writeUInt16BE(5 + 16 + name.length, 2);
      ms[4] = 16;
      return send([{ type: PAYLOAD.EAP, critical: false, body: encodeEap({ code: EAP_CODE.REQUEST, id: 2, type: EAP_TYPE.MSCHAPV2, data: Buffer.concat([ms, authChallenge, name]) }) }]);
    }
    if (stage === 2 && eapIn) {
      const r = decodeEap(eapIn.body);
      const value = r.data.subarray(5, 5 + 49);
      peerChallenge = Buffer.from(value.subarray(0, 16));
      ntResponse = Buffer.from(value.subarray(24, 48));
      const userName = r.data.subarray(5 + 49).toString('utf8');
      const ok = userName === o.userName && generateNtResponse(authChallenge, peerChallenge, o.userName, o.password).equals(ntResponse);
      const text = ok ? `${authenticatorResponse(o.password, ntResponse, peerChallenge, authChallenge, o.userName)} M=Welcome` : 'E=691 R=0 C=00000000000000000000000000000000 V=3 M=Authentication failure';
      const ms = Buffer.alloc(4);
      ms[0] = ok ? 3 : 4;
      ms[1] = 7;
      ms.writeUInt16BE(4 + text.length, 2);
      stage = ok ? 3 : 9;
      if (ok) msk = mschapv2Msk(o.password, ntResponse);
      return send([{ type: PAYLOAD.EAP, critical: false, body: encodeEap({ code: EAP_CODE.REQUEST, id: 3, type: EAP_TYPE.MSCHAPV2, data: Buffer.concat([ms, Buffer.from(text, 'ascii')]) }) }]);
    }
    if (stage === 3 && eapIn) {
      stage = 4;
      return send([{ type: PAYLOAD.EAP, critical: false, body: encodeEap({ code: EAP_CODE.SUCCESS, id: 3, data: Buffer.alloc(0) }) }]);
    }
    if (stage === 4) {
      const a = decodeAuth(ps.find((p) => p.type === PAYLOAD.AUTH)!.body);
      const want = authValue(suite.prf!, msk!, initRequest, nr, keys.skPi, idiBody);
      if (!want.equals(a.data)) return send([{ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.AUTHENTICATION_FAILED }) }]);
      const spiOurs = randomBytes(4);
      const espSuite: Suite = { encr: { id: ENCR_AES_CBC, keyLength: 256 }, integ: espIntegId };
      seen.espSuite = espSuite;
      seen.childSpiIn = spiOurs;
      seen.childKeys = deriveChildKeys(suite.prf!, keys.skD, ni, nr, espSuite);
      stage = 5;
      // The gateway's side of the ESP SA: what the client sends out comes in here, and the other way round.
      const ck = seen.childKeys;
      esp = new Esp({ spiOut: espProposalSpi, spiIn: spiOurs, suite: espSuite, encrOut: ck.encrIn, integOut: ck.integIn, encrIn: ck.encrOut, integIn: ck.integOut });
      return send([
        { type: PAYLOAD.AUTH, critical: false, body: encodeAuth(AUTH_SHARED_KEY, authValue(suite.prf!, msk!, initResponse, ni, keys.skPr, idrBody)) },
        { type: PAYLOAD.CP, critical: false, body: encodeCp(CFG_REPLY, [{ type: CP_ATTR.INTERNAL_IP4_ADDRESS, value: ip4('10.212.134.5') }, { type: CP_ATTR.INTERNAL_IP4_DNS, value: ip4('10.0.0.53') }, { type: CP_ATTR.INTERNAL_IP4_SUBNET, value: Buffer.concat([ip4('192.168.57.0'), ip4('255.255.255.0')]) }]) },
        { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.ESP, spi: spiOurs, transforms: [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 }, { type: TRANSFORM.INTEG, id: espIntegId }, { type: TRANSFORM.ESN, id: 0 }] }]) },
        { type: PAYLOAD.TSi, critical: false, body: encodeTs([{ start: '10.212.134.5', end: '10.212.134.5' }]) },
        { type: PAYLOAD.TSr, critical: false, body: encodeTs([{ start: '10.0.0.0', end: '10.255.255.255' }]) },
      ]);
    }
  });
  return {
    port,
    seen,
    received,
    probe: () => own(EXCHANGE.INFORMATIONAL, []),
    deleteIke: () => own(EXCHANGE.INFORMATIONAL, [{ type: PAYLOAD.DELETE, critical: false, body: Buffer.from([PROTOCOL.IKE, 0, 0, 0]) }]).then(() => undefined),
    close: () => sock.close(),
  };
}
