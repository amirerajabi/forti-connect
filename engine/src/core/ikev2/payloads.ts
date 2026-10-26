// IKEv2 messages (RFC 7296) as FortiConnect needs them for a FortiGate dial-up tunnel: the header, the payloads of
// IKE_SA_INIT and IKE_AUTH (SA, KE, nonce, notify, ID, AUTH, EAP, configuration, traffic selectors) and the encrypted
// SK payload's framing. Pure encoding: no sockets, no keys.

export const EXCHANGE = { IKE_SA_INIT: 34, IKE_AUTH: 35, CREATE_CHILD_SA: 36, INFORMATIONAL: 37 } as const;

export const PAYLOAD = {
  NONE: 0,
  SA: 33,
  KE: 34,
  IDi: 35,
  IDr: 36,
  CERT: 37,
  CERTREQ: 38,
  AUTH: 39,
  NONCE: 40,
  NOTIFY: 41,
  DELETE: 42,
  VENDOR: 43,
  TSi: 44,
  TSr: 45,
  SK: 46,
  CP: 47,
  EAP: 48,
} as const;

export const FLAG = { INITIATOR: 0x08, RESPONSE: 0x20 } as const;

/** Transform types and the IDs used here. */
export const TRANSFORM = { ENCR: 1, PRF: 2, INTEG: 3, DH: 4, ESN: 5 } as const;
export const ENCR_AES_CBC = 12;
export const PRF_HMAC_SHA2_256 = 5;
export const PRF_HMAC_SHA2_384 = 6;
export const AUTH_HMAC_SHA2_256_128 = 12;
export const AUTH_HMAC_SHA2_384_192 = 13;
export const ESN_NONE = 0;
export const ATTR_KEY_LENGTH = 14;

export const PROTOCOL = { IKE: 1, ESP: 3 } as const;

export const NOTIFY = {
  UNSUPPORTED_CRITICAL_PAYLOAD: 1,
  INVALID_IKE_SPI: 4,
  INVALID_SYNTAX: 7,
  INVALID_MESSAGE_ID: 9,
  NO_PROPOSAL_CHOSEN: 14,
  INVALID_KE_PAYLOAD: 17,
  AUTHENTICATION_FAILED: 24,
  SINGLE_PAIR_REQUIRED: 34,
  NO_ADDITIONAL_SAS: 35,
  INTERNAL_ADDRESS_FAILURE: 36,
  FAILED_CP_REQUIRED: 37,
  TS_UNACCEPTABLE: 38,
  INITIAL_CONTACT: 16384,
  NAT_DETECTION_SOURCE_IP: 16388,
  NAT_DETECTION_DESTINATION_IP: 16389,
  COOKIE: 16390,
  REKEY_SA: 16393,
  EAP_ONLY_AUTHENTICATION: 16417,
} as const;

/** Error notify types are below 16384; their names for messages. */
export function notifyName(type: number): string {
  const name = Object.entries(NOTIFY).find(([, v]) => v === type)?.[0];
  return name ?? `notify ${type}`;
}

export const ID_TYPE = { IPV4_ADDR: 1, FQDN: 2, RFC822_ADDR: 3, KEY_ID: 11 } as const;
export const AUTH_SHARED_KEY = 2;
export const CFG_REQUEST = 1;
export const CFG_REPLY = 2;
export const CP_ATTR = { INTERNAL_IP4_ADDRESS: 1, INTERNAL_IP4_NETMASK: 2, INTERNAL_IP4_DNS: 3, INTERNAL_IP4_SUBNET: 13 } as const;
export const TS_IPV4_ADDR_RANGE = 7;

export interface Header {
  spiI: Buffer;
  spiR: Buffer;
  /** Type of the first payload. */
  next: number;
  exchange: number;
  flags: number;
  messageId: number;
  length: number;
}

export interface Payload {
  type: number;
  critical: boolean;
  body: Buffer;
}

export const HEADER_LENGTH = 28;

export function encodeHeader(h: Omit<Header, 'length'>, length: number): Buffer {
  const b = Buffer.alloc(HEADER_LENGTH);
  h.spiI.copy(b, 0);
  h.spiR.copy(b, 8);
  b[16] = h.next;
  b[17] = 0x20; // version 2.0
  b[18] = h.exchange;
  b[19] = h.flags;
  b.writeUInt32BE(h.messageId, 20);
  b.writeUInt32BE(length, 24);
  return b;
}

export function decodeHeader(b: Buffer): Header {
  if (b.length < HEADER_LENGTH) throw new Error('IKE message too short');
  if (b[17] >> 4 !== 2) throw new Error(`IKE version ${b[17] >> 4}.${b[17] & 15} is not 2`);
  return {
    spiI: b.subarray(0, 8),
    spiR: b.subarray(8, 16),
    next: b[16],
    exchange: b[18],
    flags: b[19],
    messageId: b.readUInt32BE(20),
    length: b.readUInt32BE(24),
  };
}

/** A chain of payloads: each generic header names the type of the one after it. */
export function encodePayloads(payloads: Payload[]): Buffer {
  const parts = payloads.map((p, i) => {
    const h = Buffer.alloc(4);
    h[0] = payloads[i + 1]?.type ?? PAYLOAD.NONE;
    h[1] = p.critical ? 0x80 : 0;
    h.writeUInt16BE(4 + p.body.length, 2);
    return Buffer.concat([h, p.body]);
  });
  return Buffer.concat(parts);
}

export function decodePayloads(first: number, data: Buffer): Payload[] {
  const out: Payload[] = [];
  let type = first;
  let off = 0;
  while (type !== PAYLOAD.NONE) {
    if (off + 4 > data.length) throw new Error('IKE payload runs past the message');
    const next = data[off];
    const critical = (data[off + 1] & 0x80) !== 0;
    const len = data.readUInt16BE(off + 2);
    if (len < 4 || off + len > data.length) throw new Error('IKE payload length is wrong');
    out.push({ type, critical, body: data.subarray(off + 4, off + len) });
    // The SK payload holds the rest of the message (its own "next" names its first inner payload).
    if (type === PAYLOAD.SK) break;
    type = next;
    off += len;
  }
  return out;
}

/** A whole plaintext message: header plus payloads. */
export function encodeMessage(h: Omit<Header, 'length' | 'next'>, payloads: Payload[]): Buffer {
  const body = encodePayloads(payloads);
  return Buffer.concat([encodeHeader({ ...h, next: payloads[0]?.type ?? PAYLOAD.NONE }, HEADER_LENGTH + body.length), body]);
}

// ---------------------------------------------------------------- SA payload

export interface Transform {
  type: number;
  id: number;
  keyLength?: number;
}

export interface Proposal {
  number: number;
  protocol: number;
  spi: Buffer;
  transforms: Transform[];
}

export function encodeSa(proposals: Proposal[]): Buffer {
  return Buffer.concat(
    proposals.map((p, pi) => {
      const ts = p.transforms.map((t, ti) => {
        const attrs = t.keyLength ? Buffer.from([0x80, ATTR_KEY_LENGTH, t.keyLength >> 8, t.keyLength & 0xff]) : Buffer.alloc(0);
        const b = Buffer.alloc(8);
        b[0] = ti === p.transforms.length - 1 ? 0 : 3;
        b.writeUInt16BE(8 + attrs.length, 2);
        b[4] = t.type;
        b.writeUInt16BE(t.id, 6);
        return Buffer.concat([b, attrs]);
      });
      const body = Buffer.concat(ts);
      const h = Buffer.alloc(8);
      h[0] = pi === proposals.length - 1 ? 0 : 2;
      h.writeUInt16BE(8 + p.spi.length + body.length, 2);
      h[4] = p.number;
      h[5] = p.protocol;
      h[6] = p.spi.length;
      h[7] = p.transforms.length;
      return Buffer.concat([h, p.spi, body]);
    }),
  );
}

export function decodeSa(b: Buffer): Proposal[] {
  const out: Proposal[] = [];
  let off = 0;
  while (off < b.length) {
    const more = b[off];
    const len = b.readUInt16BE(off + 2);
    const number = b[off + 4];
    const protocol = b[off + 5];
    const spiSize = b[off + 6];
    const count = b[off + 7];
    const spi = Buffer.from(b.subarray(off + 8, off + 8 + spiSize));
    const transforms: Transform[] = [];
    let t = off + 8 + spiSize;
    for (let i = 0; i < count; i++) {
      const tlen = b.readUInt16BE(t + 2);
      const tr: Transform = { type: b[t + 4], id: b.readUInt16BE(t + 6) };
      for (let a = t + 8; a + 4 <= t + tlen; ) {
        const at = b.readUInt16BE(a);
        if (at & 0x8000) {
          if ((at & 0x7fff) === ATTR_KEY_LENGTH) tr.keyLength = b.readUInt16BE(a + 2);
          a += 4;
        } else {
          a += 4 + b.readUInt16BE(a + 2);
        }
      }
      transforms.push(tr);
      t += tlen;
    }
    out.push({ number, protocol, spi, transforms });
    off += len;
    if (more === 0) break;
  }
  return out;
}

// ------------------------------------------------------------ other payloads

export function encodeKe(group: number, data: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt16BE(group, 0);
  return Buffer.concat([h, data]);
}

export function decodeKe(b: Buffer): { group: number; data: Buffer } {
  return { group: b.readUInt16BE(0), data: b.subarray(4) };
}

export interface Notify {
  protocol: number;
  type: number;
  spi: Buffer;
  data: Buffer;
}

export function encodeNotify(n: Partial<Notify> & { type: number }): Buffer {
  const spi = n.spi ?? Buffer.alloc(0);
  const h = Buffer.alloc(4);
  h[0] = n.protocol ?? 0;
  h[1] = spi.length;
  h.writeUInt16BE(n.type, 2);
  return Buffer.concat([h, spi, n.data ?? Buffer.alloc(0)]);
}

export function decodeNotify(b: Buffer): Notify {
  const spiSize = b[1];
  return { protocol: b[0], type: b.readUInt16BE(2), spi: b.subarray(4, 4 + spiSize), data: b.subarray(4 + spiSize) };
}

/** ID payload body: type, three reserved bytes, the identity. This body is what AUTH signs. */
export function encodeId(type: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([type, 0, 0, 0]), value]);
}

export function encodeAuth(method: number, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([method, 0, 0, 0]), data]);
}

export function decodeAuth(b: Buffer): { method: number; data: Buffer } {
  return { method: b[0], data: b.subarray(4) };
}

export interface CpAttribute {
  type: number;
  value: Buffer;
}

export function encodeCp(cfgType: number, attrs: CpAttribute[]): Buffer {
  return Buffer.concat([
    Buffer.from([cfgType, 0, 0, 0]),
    ...attrs.map((a) => {
      const h = Buffer.alloc(4);
      h.writeUInt16BE(a.type & 0x7fff, 0);
      h.writeUInt16BE(a.value.length, 2);
      return Buffer.concat([h, a.value]);
    }),
  ]);
}

export function decodeCp(b: Buffer): { cfgType: number; attrs: CpAttribute[] } {
  const attrs: CpAttribute[] = [];
  for (let off = 4; off + 4 <= b.length; ) {
    const type = b.readUInt16BE(off) & 0x7fff;
    const len = b.readUInt16BE(off + 2);
    attrs.push({ type, value: b.subarray(off + 4, off + 4 + len) });
    off += 4 + len;
  }
  return { cfgType: b[0], attrs };
}

export interface TrafficSelector {
  start: string;
  end: string;
}

function ip4(s: string): Buffer {
  return Buffer.from(s.split('.').map(Number));
}

function ip4s(b: Buffer): string {
  return [...b].join('.');
}

export function encodeTs(list: TrafficSelector[]): Buffer {
  return Buffer.concat([
    Buffer.from([list.length, 0, 0, 0]),
    ...list.map((t) => {
      const h = Buffer.alloc(8);
      h[0] = TS_IPV4_ADDR_RANGE;
      h[1] = 0;
      h.writeUInt16BE(16, 2);
      h.writeUInt16BE(0, 4);
      h.writeUInt16BE(65535, 6);
      return Buffer.concat([h, ip4(t.start), ip4(t.end)]);
    }),
  ]);
}

export function decodeTs(b: Buffer): TrafficSelector[] {
  const out: TrafficSelector[] = [];
  const count = b[0];
  let off = 4;
  for (let i = 0; i < count && off + 8 <= b.length; i++) {
    const type = b[off];
    const len = b.readUInt16BE(off + 2);
    if (type === TS_IPV4_ADDR_RANGE && len === 16) out.push({ start: ip4s(b.subarray(off + 8, off + 12)), end: ip4s(b.subarray(off + 12, off + 16)) });
    off += len;
  }
  return out;
}

export { ip4, ip4s };
