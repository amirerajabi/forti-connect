// EAP-MSCHAPv2 (RFC 2759 for the challenge / response, RFC 3079 for the keys): the user-name-and-password method a
// FortiGate's IKEv2 dial-up tunnel asks FortiClient for. MS-CHAPv2 is built on MD4 and single DES, which OpenSSL 3
// (and so Node outside Electron) no longer offers, so both are written out here; the RFC test vectors check them.
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------- MD4 (RFC 1320)

export function md4(input: Buffer): Buffer {
  const len = input.length;
  const padLen = (len % 64 < 56 ? 56 : 120) - (len % 64);
  const msg = Buffer.alloc(len + padLen + 8);
  input.copy(msg);
  msg[len] = 0x80;
  msg.writeUInt32LE((len * 8) >>> 0, len + padLen);
  msg.writeUInt32LE(Math.floor((len * 8) / 0x100000000), len + padLen + 4);
  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;
  const rotl = (x: number, n: number) => (x << n) | (x >>> (32 - n));
  const x = new Array<number>(16);
  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) x[i] = msg.readUInt32LE(off + i * 4);
    const [aa, bb, cc, dd] = [a, b, c, d];
    const f = (p: number, q: number, r: number) => (p & q) | (~p & r);
    const g = (p: number, q: number, r: number) => (p & q) | (p & r) | (q & r);
    const h = (p: number, q: number, r: number) => p ^ q ^ r;
    for (const k of [0, 4, 8, 12]) {
      a = rotl((a + f(b, c, d) + x[k]) | 0, 3);
      d = rotl((d + f(a, b, c) + x[k + 1]) | 0, 7);
      c = rotl((c + f(d, a, b) + x[k + 2]) | 0, 11);
      b = rotl((b + f(c, d, a) + x[k + 3]) | 0, 19);
    }
    for (const k of [0, 1, 2, 3]) {
      a = rotl((a + g(b, c, d) + x[k] + 0x5a827999) | 0, 3);
      d = rotl((d + g(a, b, c) + x[k + 4] + 0x5a827999) | 0, 5);
      c = rotl((c + g(d, a, b) + x[k + 8] + 0x5a827999) | 0, 9);
      b = rotl((b + g(c, d, a) + x[k + 12] + 0x5a827999) | 0, 13);
    }
    for (const k of [0, 2, 1, 3]) {
      a = rotl((a + h(b, c, d) + x[k] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + h(a, b, c) + x[k + 8] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + h(d, a, b) + x[k + 4] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + h(c, d, a) + x[k + 12] + 0x6ed9eba1) | 0, 15);
    }
    a = (a + aa) | 0;
    b = (b + bb) | 0;
    c = (c + cc) | 0;
    d = (d + dd) | 0;
  }
  const out = Buffer.alloc(16);
  out.writeInt32LE(a, 0);
  out.writeInt32LE(b, 4);
  out.writeInt32LE(c, 8);
  out.writeInt32LE(d, 12);
  return out;
}

// ---------------------------------------------------------------------- DES (FIPS 46-3), encryption of one block

const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const S = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

/** Bits as an array of 0/1, most significant bit of the first byte first. */
function bits(b: Buffer): number[] {
  const out: number[] = [];
  for (const byte of b) for (let i = 7; i >= 0; i--) out.push((byte >> i) & 1);
  return out;
}

function fromBits(a: number[]): Buffer {
  const out = Buffer.alloc(a.length / 8);
  for (let i = 0; i < a.length; i++) out[i >> 3] |= a[i] << (7 - (i & 7));
  return out;
}

const permute = (input: number[], table: number[]) => table.map((p) => input[p - 1]);

/** Single DES, one 8-byte block, 8-byte key (parity bits ignored). */
export function desEncryptBlock(key: Buffer, block: Buffer): Buffer {
  const k = permute(bits(key), PC1);
  let c = k.slice(0, 28);
  let d = k.slice(28);
  const subkeys: number[][] = [];
  for (const s of SHIFTS) {
    c = [...c.slice(s), ...c.slice(0, s)];
    d = [...d.slice(s), ...d.slice(0, s)];
    subkeys.push(permute([...c, ...d], PC2));
  }
  const ip = permute(bits(block), IP);
  let l = ip.slice(0, 32);
  let r = ip.slice(32);
  for (let round = 0; round < 16; round++) {
    const e = permute(r, E).map((v, i) => v ^ subkeys[round][i]);
    const sOut: number[] = [];
    for (let j = 0; j < 8; j++) {
      const six = e.slice(j * 6, j * 6 + 6);
      const row = (six[0] << 1) | six[5];
      const col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4];
      const v = S[j][row * 16 + col];
      sOut.push((v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1);
    }
    const f = permute(sOut, P);
    const nr = l.map((v, i) => v ^ f[i]);
    l = r;
    r = nr;
  }
  return fromBits(permute([...r, ...l], FP));
}

/** A 7-byte key spread over 8 bytes, 7 bits each (the 8th, parity, is ignored by DES). */
function desKey7(k7: Buffer): Buffer {
  const b = bits(k7);
  const out: number[] = [];
  for (let i = 0; i < 8; i++) out.push(...b.slice(i * 7, i * 7 + 7), 0);
  return fromBits(out);
}

// ---------------------------------------------------------------------- MS-CHAPv2 (RFC 2759 §8)

export function ntPasswordHash(password: string): Buffer {
  return md4(Buffer.from(password, 'utf16le'));
}

export function challengeHash(peerChallenge: Buffer, authChallenge: Buffer, userName: string): Buffer {
  return createHash('sha1').update(Buffer.concat([peerChallenge, authChallenge, Buffer.from(userName, 'utf8')])).digest().subarray(0, 8);
}

export function challengeResponse(challenge: Buffer, passwordHash: Buffer): Buffer {
  const z = Buffer.concat([passwordHash, Buffer.alloc(5)]);
  return Buffer.concat([0, 7, 14].map((o) => desEncryptBlock(desKey7(z.subarray(o, o + 7)), challenge)));
}

export function generateNtResponse(authChallenge: Buffer, peerChallenge: Buffer, userName: string, password: string): Buffer {
  return challengeResponse(challengeHash(peerChallenge, authChallenge, userName), ntPasswordHash(password));
}

const MAGIC1 = Buffer.from('Magic server to client signing constant', 'ascii');
const MAGIC2 = Buffer.from('Pad to make it do more than one iteration', 'ascii');

/** The "S=…" string the server sends back, proving it knew the password too. */
export function authenticatorResponse(password: string, ntResponse: Buffer, peerChallenge: Buffer, authChallenge: Buffer, userName: string): string {
  const hashHash = md4(ntPasswordHash(password));
  const digest = createHash('sha1').update(Buffer.concat([hashHash, ntResponse, MAGIC1])).digest();
  const ch = challengeHash(peerChallenge, authChallenge, userName);
  return `S=${createHash('sha1').update(Buffer.concat([digest, ch, MAGIC2])).digest('hex').toUpperCase()}`;
}

// ---------------------------------------------------------------------- keys (RFC 3079 §3.4)

const KEY_MAGIC1 = Buffer.from('This is the MPPE Master Key', 'ascii');
const KEY_MAGIC2 = Buffer.from('On the client side, this is the send key; on the server side, it is the receive key.', 'ascii');
const KEY_MAGIC3 = Buffer.from('On the client side, this is the receive key; on the server side, it is the send key.', 'ascii');
const SHS_PAD1 = Buffer.alloc(40, 0x00);
const SHS_PAD2 = Buffer.alloc(40, 0xf2);

export function masterKey(password: string, ntResponse: Buffer): Buffer {
  const hashHash = md4(ntPasswordHash(password));
  return createHash('sha1').update(Buffer.concat([hashHash, ntResponse, KEY_MAGIC1])).digest().subarray(0, 16);
}

function asymmetricStartKey(master: Buffer, magic: Buffer): Buffer {
  return createHash('sha1').update(Buffer.concat([master, SHS_PAD1, magic, SHS_PAD2])).digest().subarray(0, 16);
}

/**
 * The MSK IKEv2 signs its final AUTH with: the server's receive key then its send key (MasterReceiveKey |
 * MasterSendKey, as Windows and strongSwan build it). Any 32 zero bytes some implementations append change nothing:
 * HMAC pads a short key with zeros anyway.
 */
export function mschapv2Msk(password: string, ntResponse: Buffer): Buffer {
  const m = masterKey(password, ntResponse);
  return Buffer.concat([asymmetricStartKey(m, KEY_MAGIC2), asymmetricStartKey(m, KEY_MAGIC3)]);
}

// ---------------------------------------------------------------------- EAP framing (RFC 3748) for MS-CHAPv2

export const EAP_CODE = { REQUEST: 1, RESPONSE: 2, SUCCESS: 3, FAILURE: 4 } as const;
export const EAP_TYPE = { IDENTITY: 1, NAK: 3, MSCHAPV2: 26 } as const;
const OP = { CHALLENGE: 1, RESPONSE: 2, SUCCESS: 3, FAILURE: 4 } as const;

export interface EapPacket {
  code: number;
  id: number;
  type?: number;
  data: Buffer;
}

export function decodeEap(b: Buffer): EapPacket {
  const len = b.readUInt16BE(2);
  const p: EapPacket = { code: b[0], id: b[1], data: Buffer.alloc(0) };
  if ((p.code === EAP_CODE.REQUEST || p.code === EAP_CODE.RESPONSE) && len > 4) {
    p.type = b[4];
    p.data = b.subarray(5, len);
  }
  return p;
}

export function encodeEap(p: EapPacket): Buffer {
  const body = p.type === undefined ? Buffer.alloc(0) : Buffer.concat([Buffer.from([p.type]), p.data]);
  const h = Buffer.from([p.code, p.id, 0, 0]);
  h.writeUInt16BE(4 + body.length, 2);
  return Buffer.concat([h, body]);
}

/** The peer side of EAP-MSCHAPv2: answers the gateway's EAP requests until it says success or failure. */
export class MschapV2Peer {
  private ntResponse: Buffer | null = null;
  private expected: string | null = null;
  msk: Buffer | null = null;

  constructor(private readonly userName: string, private readonly password: string, private readonly peerChallenge = randomBytes(16)) {}

  /** The response to one EAP request; throws with a message for the user when the gateway refuses. */
  respond(req: EapPacket): Buffer {
    if (req.type === EAP_TYPE.IDENTITY) return encodeEap({ code: EAP_CODE.RESPONSE, id: req.id, type: EAP_TYPE.IDENTITY, data: Buffer.from(this.userName, 'utf8') });
    if (req.type !== EAP_TYPE.MSCHAPV2) {
      // Ask for MS-CHAPv2 instead of whatever was offered (a Legacy Nak).
      return encodeEap({ code: EAP_CODE.RESPONSE, id: req.id, type: EAP_TYPE.NAK, data: Buffer.from([EAP_TYPE.MSCHAPV2]) });
    }
    const op = req.data[0];
    const msId = req.data[1];
    if (op === OP.CHALLENGE) {
      const valueSize = req.data[4];
      const authChallenge = req.data.subarray(5, 5 + valueSize);
      if (authChallenge.length !== 16) throw new Error('The gateway sent a malformed MS-CHAPv2 challenge');
      this.ntResponse = generateNtResponse(authChallenge, this.peerChallenge, this.userName, this.password);
      this.expected = authenticatorResponse(this.password, this.ntResponse, this.peerChallenge, authChallenge, this.userName);
      const name = Buffer.from(this.userName, 'utf8');
      const value = Buffer.concat([this.peerChallenge, Buffer.alloc(8), this.ntResponse, Buffer.from([0])]);
      const ms = Buffer.alloc(5);
      ms[0] = OP.RESPONSE;
      ms[1] = msId;
      ms.writeUInt16BE(5 + value.length + name.length, 2);
      ms[4] = value.length;
      return encodeEap({ code: EAP_CODE.RESPONSE, id: req.id, type: EAP_TYPE.MSCHAPV2, data: Buffer.concat([ms, value, name]) });
    }
    if (op === OP.SUCCESS) {
      const message = req.data.subarray(4).toString('ascii');
      const s = /S=([0-9A-Fa-f]{40})/.exec(message)?.[0]?.toUpperCase().replace(/^S=/, 'S=');
      if (!this.ntResponse || !this.expected || s !== this.expected) throw new Error('The gateway could not prove it knows your password (MS-CHAPv2 authenticator response does not match)');
      this.msk = mschapv2Msk(this.password, this.ntResponse);
      return encodeEap({ code: EAP_CODE.RESPONSE, id: req.id, type: EAP_TYPE.MSCHAPV2, data: Buffer.from([OP.SUCCESS]) });
    }
    if (op === OP.FAILURE) {
      const message = req.data.subarray(4).toString('ascii');
      const e = /E=(\d+)/.exec(message)?.[1];
      throw new Error(e === '691' || !e ? 'The FortiGate refused the user name or password' : e === '648' ? 'The password has expired on the FortiGate' : `The FortiGate refused the login (MS-CHAPv2 error ${e})`);
    }
    throw new Error(`The gateway sent an MS-CHAPv2 message FortiConnect does not know (${op})`);
  }
}
