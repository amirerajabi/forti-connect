// A small IKEv2 responder for the engine tests, written from RFC 7296 / RFC 2759 like the initiator but from the other
// side: it answers IKE_SA_INIT, proves itself with a pre-shared key, runs EAP-MSCHAPv2 against a known password,
// checks the initiator's final AUTH and hands out a VPN address and ESP keys, the way a FortiGate dial-up tunnel does.
// Afterwards it answers the client's rekeys and DELETEs, and can renew the ESP and IKE keys itself.
import { createHash } from 'node:crypto';
import * as dgram from 'node:dgram';
import { authValue, decryptSk, deriveChildKeys, deriveIkeKeys, deriveRekeyedIkeKeys, DiffieHellman, encryptSk, icv, INTEG, randomBytes, type IkeKeys, type Suite } from '../../src/core/ikev2/crypto';
import { Esp, type EspKeys } from '../../src/core/ikev2/esp';
import { authenticatorResponse, decodeEap, EAP_CODE, EAP_TYPE, encodeEap, generateNtResponse, mschapv2Msk } from '../../src/core/ikev2/mschapv2';
import {
  AUTH_SHARED_KEY,
  CFG_REPLY,
  CP_ATTR,
  decodeAuth,
  decodeHeader,
  decodeKe,
  decodeNotify,
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
  /** Only accept this PFS group when the client renews ESP keys (answers INVALID_KE_PAYLOAD naming it otherwise). */
  pfsGroup?: number;
}

export interface FakeGateway {
  port: number;
  /** Inner packets the gateway received over ESP (it sends each one straight back, with its newest keys). */
  received: Buffer[];
  /** The gateway's own request: an empty INFORMATIONAL (a liveness check); resolves with the answer's payload types. */
  probe(): Promise<number[]>;
  /** The gateway ends the IKE SA. */
  deleteIke(): Promise<void>;
  /** The gateway renews the ESP keys (with PFS on its IKE group unless `pfs` is false), then deletes the old ESP SA. */
  rekeyChild(pfs?: boolean): Promise<void>;
  /** The gateway renews the IKE keys, then deletes the old IKE SA. */
  rekeyIke(): Promise<void>;
  /** What the gateway saw and decided, for the test to check. */
  seen: {
    idi?: string;
    idType?: number;
    childSpiIn?: Buffer;
    childKeys?: ReturnType<typeof deriveChildKeys>;
    espSuite?: Suite;
    /** Rekeys the client started: ESP (its PFS group, 0 without) and IKE; DELETEs it sent; ESP SAs alive now. */
    clientChildRekeys: number[];
    clientIkeRekeys: number;
    deletes: string[];
    espSas: number;
    /** Packets that came in, per gateway inbound SPI (hex). */
    perSpi: Record<string, number>;
  };
  close(): void;
}

/** One IKE SA from the gateway's side; after a rekey it started, the gateway is its initiator. */
interface Sa {
  spiI: Buffer;
  spiR: Buffer;
  suite: Suite;
  keys: IkeKeys;
  gwInitiator: boolean;
  ownId: number;
}

/** An ESP SA the gateway holds, with its SPIs at hand. */
interface GwEsp {
  esp: Esp;
  k: EspKeys;
}

export async function startFakeGateway(o: FakeGatewayOptions): Promise<FakeGateway> {
  const sock = dgram.createSocket('udp4');
  await new Promise<void>((r) => sock.bind(0, '127.0.0.1', r));
  const port = sock.address().port;
  const seen: FakeGateway['seen'] = { clientChildRekeys: [], clientIkeRekeys: 0, deletes: [], espSas: 0, perSpi: {} };
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
  let client: dgram.RemoteInfo | null = null;
  const received: Buffer[] = [];
  const waiting = new Map<string, (ps: Payload[]) => void>();
  /** After the login: the IKE SA and the one a rekey replaced (until its DELETE). */
  let ike: Sa | null = null;
  let oldIke: Sa | null = null;
  /** ESP SAs, the newest last: what the gateway sends with, and what it accepts by SPI. */
  let esps: GwEsp[] = [];

  // In the tests the "NAT-T" port is the same socket: everything after IKE_SA_INIT carries the zero marker.
  const reply = (data: Buffer, rinfo: dgram.RemoteInfo, marker: boolean) => sock.send(marker ? Buffer.concat([Buffer.alloc(4), data]) : data, rinfo.port, rinfo.address);

  /** A message on IKE SA `sa` from the gateway's side. */
  const protect = (sa: Sa, exchange: number, payloads: Payload[], response: boolean, messageId: number) => {
    const [encKey, integKey] = sa.gwInitiator ? [sa.keys.skEi, sa.keys.skAi] : [sa.keys.skEr, sa.keys.skAr];
    const inner = encodePayloads(payloads);
    const body = encryptSk(sa.suite, encKey, inner);
    const icvLen = INTEG[sa.suite.integ].icvLength;
    const flags = (sa.gwInitiator ? FLAG.INITIATOR : 0) | (response ? FLAG.RESPONSE : 0);
    const header = encodeHeader({ spiI: sa.spiI, spiR: sa.spiR, next: PAYLOAD.SK, exchange, flags, messageId }, HEADER_LENGTH + 4 + body.length + icvLen);
    const sk = Buffer.from([payloads[0]?.type ?? PAYLOAD.NONE, 0, 0, 0]);
    sk.writeUInt16BE(4 + body.length + icvLen, 2);
    const unsigned = Buffer.concat([header, sk, body]);
    return Buffer.concat([unsigned, icv(sa.suite, integKey, unsigned)]);
  };
  const unprotect = (sa: Sa, m: Buffer) => {
    const [encKey, integKey] = sa.gwInitiator ? [sa.keys.skEr, sa.keys.skAr] : [sa.keys.skEi, sa.keys.skAi];
    const inner = decryptSk(sa.suite, encKey, integKey, m, m.subarray(HEADER_LENGTH + 4, HEADER_LENGTH + m.readUInt16BE(HEADER_LENGTH + 2)));
    return decodePayloads(m[HEADER_LENGTH], inner);
  };
  /** The IKE SA during the login, the gateway being its responder. */
  const loginSa = (): Sa => ({ spiI, spiR, suite, keys, gwInitiator: false, ownId: 0 });

  /** A request from the gateway on the current IKE SA (or `sa`); resolves with the client's answer. */
  const own = (exchange: number, payloads: Payload[], sa: Sa = ike!) => {
    const id = sa.ownId++;
    return new Promise<Payload[]>((resolve) => {
      waiting.set(`${sa.spiI.toString('hex')}:${id}`, resolve);
      reply(protect(sa, exchange, payloads, false, id), client!, true);
    });
  };

  const espDelete = (spi: Buffer): Payload => ({ type: PAYLOAD.DELETE, critical: false, body: Buffer.concat([Buffer.from([PROTOCOL.ESP, 4, 0, 1]), spi]) });
  const addEsp = (k: EspKeys) => {
    esps.push({ esp: new Esp(k), k });
    seen.espSas = esps.length;
  };
  const dropEsp = (e: GwEsp) => {
    esps = esps.filter((x) => x !== e);
    seen.espSas = esps.length;
  };
  const espTransforms = (integ: number, dh: number | null) => [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 }, { type: TRANSFORM.INTEG, id: integ }, ...(dh ? [{ type: TRANSFORM.DH, id: dh }] : []), { type: TRANSFORM.ESN, id: 0 }];
  const ikeTransforms = (s: Suite) => [{ type: TRANSFORM.ENCR, id: ENCR_AES_CBC, keyLength: 256 }, { type: TRANSFORM.PRF, id: s.prf! }, { type: TRANSFORM.INTEG, id: s.integ }, { type: TRANSFORM.DH, id: s.dh! }];
  const tsi = () => ({ type: PAYLOAD.TSi, critical: false, body: encodeTs([{ start: '10.212.134.5', end: '10.212.134.5' }]) });
  const tsr = () => ({ type: PAYLOAD.TSr, critical: false, body: encodeTs([{ start: '10.0.0.0', end: '10.255.255.255' }]) });

  /** The client's CREATE_CHILD_SA: new ESP keys (rekeying one), or a new IKE SA. */
  const answerCreateChild = (sa: Sa, ps: Payload[]): { reply: Payload[]; after?: () => void } => {
    const proposal = decodeSa(ps.find((p) => p.type === PAYLOAD.SA)!.body)[0];
    const niC = Buffer.from(ps.find((p) => p.type === PAYLOAD.NONCE)!.body);
    const kePayload = ps.find((p) => p.type === PAYLOAD.KE);
    const ke = kePayload ? decodeKe(kePayload.body) : null;
    const nrG = randomBytes(32);
    if (proposal.protocol === PROTOCOL.IKE) {
      const dh = new DiffieHellman(ke!.group);
      const integ = proposal.transforms.find((t) => t.type === TRANSFORM.INTEG)!.id;
      const prfId = proposal.transforms.find((t) => t.type === TRANSFORM.PRF)!.id;
      const s2: Suite = { encr: { id: ENCR_AES_CBC, keyLength: 256 }, integ, prf: prfId, dh: ke!.group };
      const newSpiR = randomBytes(8);
      const k = deriveRekeyedIkeKeys(s2, sa.suite.prf!, sa.keys.skD, dh.computeSecret(ke!.data), niC, nrG, proposal.spi, newSpiR);
      seen.clientIkeRekeys++;
      return {
        reply: [
          { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.IKE, spi: newSpiR, transforms: ikeTransforms(s2) }]) },
          { type: PAYLOAD.NONCE, critical: false, body: nrG },
          { type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) },
        ],
        after: () => {
          oldIke = sa;
          ike = { spiI: Buffer.from(proposal.spi), spiR: newSpiR, suite: s2, keys: k, gwInitiator: false, ownId: 0 };
        },
      };
    }
    if (ke && o.pfsGroup && ke.group !== o.pfsGroup) {
      const data = Buffer.alloc(2);
      data.writeUInt16BE(o.pfsGroup);
      return { reply: [{ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.INVALID_KE_PAYLOAD, data }) }] };
    }
    const rekeyed = ps.filter((p) => p.type === PAYLOAD.NOTIFY).map((p) => decodeNotify(p.body)).find((n) => n.type === NOTIFY.REKEY_SA);
    if (!rekeyed) return { reply: [{ type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NO_ADDITIONAL_SAS }) }] };
    const integ = proposal.transforms.find((t) => t.type === TRANSFORM.INTEG)!.id;
    const espSuite: Suite = { encr: { id: ENCR_AES_CBC, keyLength: 256 }, integ };
    const dh = ke ? new DiffieHellman(ke.group) : null;
    const ck = deriveChildKeys(sa.suite.prf!, sa.keys.skD, niC, nrG, espSuite, dh ? dh.computeSecret(ke!.data) : undefined);
    const spiG = randomBytes(4);
    seen.clientChildRekeys.push(ke?.group ?? 0);
    // The client started this exchange: the first keys are its sending direction, the gateway's inbound.
    addEsp({ spiOut: proposal.spi, spiIn: spiG, suite: espSuite, encrOut: ck.encrIn, integOut: ck.integIn, encrIn: ck.encrOut, integIn: ck.integOut });
    return {
      reply: [
        { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.ESP, spi: spiG, transforms: espTransforms(integ, dh?.group ?? null) }]) },
        { type: PAYLOAD.NONCE, critical: false, body: nrG },
        ...(dh ? [{ type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) }] : []),
        tsi(),
        tsr(),
      ],
    };
  };

  /** A request from the client once the tunnel is up, or its answer to one of the gateway's. */
  const established = (h: ReturnType<typeof decodeHeader>, m: Buffer, rinfo: dgram.RemoteInfo) => {
    const sa = ike?.spiI.equals(h.spiI) ? ike : oldIke?.spiI.equals(h.spiI) ? oldIke : null;
    if (!sa) return;
    const ps = unprotect(sa, m);
    if (h.flags & FLAG.RESPONSE) {
      const key = `${sa.spiI.toString('hex')}:${h.messageId}`;
      waiting.get(key)?.(ps);
      waiting.delete(key);
      return;
    }
    let out: Payload[] = [];
    let after: (() => void) | undefined;
    if (h.exchange === EXCHANGE.INFORMATIONAL) {
      // A liveness check (empty), or a DELETE: of an ESP SA (answered with the gateway's half) or of the old IKE SA.
      for (const d of ps.filter((p) => p.type === PAYLOAD.DELETE)) {
        if (d.body[0] === PROTOCOL.IKE) {
          const wasOld = sa === oldIke;
          seen.deletes.push(wasOld ? 'old-ike' : 'ike');
          if (wasOld) after = () => (oldIke = null);
          continue;
        }
        const spi = d.body.subarray(4, 8);
        seen.deletes.push(`esp:${spi.toString('hex')}`);
        const e = esps.find((x) => x.k.spiOut.equals(spi));
        if (e) {
          out.push(espDelete(e.k.spiIn));
          dropEsp(e);
        }
      }
    } else if (h.exchange === EXCHANGE.CREATE_CHILD_SA) {
      const r = answerCreateChild(sa, ps);
      out = r.reply;
      after = r.after;
    }
    reply(protect(sa, h.exchange, out, true, h.messageId), rinfo, true);
    after?.();
  };

  sock.on('message', (raw, rinfo) => {
    if (raw.length === 1 && raw[0] === 0xff) return;
    const marker = raw.length >= 4 && raw.readUInt32BE(0) === 0;
    if (!marker && esps.length && stage === 5) {
      // ESP from the client: deliver (here: keep) the packet and send it straight back, with the newest keys.
      const e = esps.find((x) => x.esp.isOurs(raw));
      if (!e) return;
      try {
        const inner = e.esp.decapsulate(raw);
        received.push(inner);
        const spi = e.k.spiIn.toString('hex');
        seen.perSpi[spi] = (seen.perSpi[spi] ?? 0) + 1;
        sock.send(esps[esps.length - 1].esp.encapsulate(inner), rinfo.port, rinfo.address);
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
      const natData = createHash('sha1').update(Buffer.concat([spiI, spiR, ip4('203.0.113.9'), Buffer.from([0x01, 0xf4])])).digest();
      initResponse = encodeMessage({ spiI, spiR, exchange: EXCHANGE.IKE_SA_INIT, flags: FLAG.RESPONSE, messageId: 0 }, [
        { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.IKE, spi: Buffer.alloc(0), transforms: ikeTransforms(suite) }]) },
        { type: PAYLOAD.KE, critical: false, body: encodeKe(ke.group, dh.publicValue) },
        { type: PAYLOAD.NONCE, critical: false, body: nr },
        { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NAT_DETECTION_SOURCE_IP, data: natData }) },
        { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ type: NOTIFY.NAT_DETECTION_DESTINATION_IP, data: natData }) },
      ]);
      keys = deriveIkeKeys(suite, dh.computeSecret(ke.data), ni, nr, spiI, spiR);
      return reply(initResponse, rinfo, false);
    }
    const m = msg.subarray(0, h.length);
    if (stage === 5) return established(h, m, rinfo);
    if (h.exchange !== EXCHANGE.IKE_AUTH) return;
    const ps = unprotect(loginSa(), m);
    client = rinfo;
    const send = (payloads: Payload[]) => reply(protect(loginSa(), EXCHANGE.IKE_AUTH, payloads, true, h.messageId), rinfo, true);
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
      // The gateway's side of the ESP SA: what the client sends out comes in here, and the other way round.
      const ck = seen.childKeys;
      addEsp({ spiOut: espProposalSpi, spiIn: spiOurs, suite: espSuite, encrOut: ck.encrIn, integOut: ck.integIn, encrIn: ck.encrOut, integIn: ck.integOut });
      send([
        { type: PAYLOAD.AUTH, critical: false, body: encodeAuth(AUTH_SHARED_KEY, authValue(suite.prf!, msk!, initResponse, ni, keys.skPr, idrBody)) },
        { type: PAYLOAD.CP, critical: false, body: encodeCp(CFG_REPLY, [{ type: CP_ATTR.INTERNAL_IP4_ADDRESS, value: ip4('10.212.134.5') }, { type: CP_ATTR.INTERNAL_IP4_DNS, value: ip4('10.0.0.53') }, { type: CP_ATTR.INTERNAL_IP4_SUBNET, value: Buffer.concat([ip4('192.168.57.0'), ip4('255.255.255.0')]) }]) },
        { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.ESP, spi: spiOurs, transforms: espTransforms(espIntegId, null) }]) },
        tsi(),
        tsr(),
      ]);
      ike = loginSa();
      stage = 5;
    }
  });

  const rekeyChild = async (pfs = true) => {
    const sa = ike!;
    const old = esps[esps.length - 1];
    const integ = seen.espSuite!.integ;
    const espSuite: Suite = { encr: { id: ENCR_AES_CBC, keyLength: 256 }, integ };
    const dh = pfs ? new DiffieHellman(sa.suite.dh!) : null;
    const niG = randomBytes(32);
    const spiG = randomBytes(4);
    const ps = await own(EXCHANGE.CREATE_CHILD_SA, [
      { type: PAYLOAD.NOTIFY, critical: false, body: encodeNotify({ protocol: PROTOCOL.ESP, type: NOTIFY.REKEY_SA, spi: old.k.spiIn }) },
      { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.ESP, spi: spiG, transforms: espTransforms(integ, dh?.group ?? null) }]) },
      { type: PAYLOAD.NONCE, critical: false, body: niG },
      ...(dh ? [{ type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) }] : []),
      tsi(),
      tsr(),
    ]);
    const chosen = decodeSa(ps.find((p) => p.type === PAYLOAD.SA)!.body)[0];
    const nrC = Buffer.from(ps.find((p) => p.type === PAYLOAD.NONCE)!.body);
    const ke = ps.find((p) => p.type === PAYLOAD.KE);
    const ck = deriveChildKeys(sa.suite.prf!, sa.keys.skD, niG, nrC, espSuite, dh && ke ? dh.computeSecret(decodeKe(ke.body).data) : undefined);
    // The gateway started this exchange: the first keys are its sending direction.
    addEsp({ spiOut: chosen.spi, spiIn: spiG, suite: espSuite, ...ck });
    await own(EXCHANGE.INFORMATIONAL, [espDelete(old.k.spiIn)]);
    dropEsp(old);
  };

  const rekeyIke = async () => {
    const sa = ike!;
    const dh = new DiffieHellman(sa.suite.dh!);
    const niG = randomBytes(32);
    const newSpiI = randomBytes(8);
    const ps = await own(EXCHANGE.CREATE_CHILD_SA, [
      { type: PAYLOAD.SA, critical: false, body: encodeSa([{ number: 1, protocol: PROTOCOL.IKE, spi: newSpiI, transforms: ikeTransforms(sa.suite) }]) },
      { type: PAYLOAD.NONCE, critical: false, body: niG },
      { type: PAYLOAD.KE, critical: false, body: encodeKe(dh.group, dh.publicValue) },
    ]);
    const chosen = decodeSa(ps.find((p) => p.type === PAYLOAD.SA)!.body)[0];
    const nrC = Buffer.from(ps.find((p) => p.type === PAYLOAD.NONCE)!.body);
    const secret = dh.computeSecret(decodeKe(ps.find((p) => p.type === PAYLOAD.KE)!.body).data);
    const k = deriveRekeyedIkeKeys(sa.suite, sa.suite.prf!, sa.keys.skD, secret, niG, nrC, newSpiI, chosen.spi);
    // The gateway started this rekey, so it is the new IKE SA's initiator.
    oldIke = sa;
    ike = { spiI: newSpiI, spiR: Buffer.from(chosen.spi), suite: sa.suite, keys: k, gwInitiator: true, ownId: 0 };
    await own(EXCHANGE.INFORMATIONAL, [{ type: PAYLOAD.DELETE, critical: false, body: Buffer.from([PROTOCOL.IKE, 0, 0, 0]) }], sa);
    oldIke = null;
  };

  return {
    port,
    seen,
    received,
    probe: () => own(EXCHANGE.INFORMATIONAL, []).then((ps) => ps.map((p) => p.type)),
    deleteIke: () => own(EXCHANGE.INFORMATIONAL, [{ type: PAYLOAD.DELETE, critical: false, body: Buffer.from([PROTOCOL.IKE, 0, 0, 0]) }]).then(() => undefined),
    rekeyChild,
    rekeyIke,
    close: () => sock.close(),
  };
}
