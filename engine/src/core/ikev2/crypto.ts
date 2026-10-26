// IKEv2 keys and protection (RFC 7296 §2.13–2.15, §3.14): the algorithms a FortiGate proposal names, Diffie-Hellman on
// the NIST curves of groups 20 and 21 (RFC 5903), the key schedule, the SK payload's encryption and integrity, and the
// AUTH value. Node's crypto does the primitives.
import { createCipheriv, createDecipheriv, createECDH, createHmac, randomBytes, timingSafeEqual, type ECDH } from 'node:crypto';
import { AUTH_HMAC_SHA2_256_128, AUTH_HMAC_SHA2_384_192, ENCR_AES_CBC, PRF_HMAC_SHA2_256, PRF_HMAC_SHA2_384 } from './payloads';

/** One side of a negotiated IKE or ESP suite. */
export interface Suite {
  encr: { id: typeof ENCR_AES_CBC; keyLength: 128 | 192 | 256 };
  integ: number;
  prf?: number;
  dh?: number;
}

export const INTEG = {
  [AUTH_HMAC_SHA2_256_128]: { hash: 'sha256', keyLength: 32, icvLength: 16 },
  [AUTH_HMAC_SHA2_384_192]: { hash: 'sha384', keyLength: 48, icvLength: 24 },
} as Record<number, { hash: string; keyLength: number; icvLength: number }>;

export const PRF = {
  [PRF_HMAC_SHA2_256]: { hash: 'sha256', length: 32 },
  [PRF_HMAC_SHA2_384]: { hash: 'sha384', length: 48 },
} as Record<number, { hash: string; length: number }>;

/** Diffie-Hellman groups on NIST curves: the key exchange data is x | y, each padded to the coordinate size. */
export const DH_GROUP = {
  19: { curve: 'prime256v1', size: 32 },
  20: { curve: 'secp384r1', size: 48 },
  21: { curve: 'secp521r1', size: 66 },
} as Record<number, { curve: string; size: number }>;

export class DiffieHellman {
  private readonly ecdh: ECDH;
  readonly publicValue: Buffer;

  constructor(readonly group: number) {
    const g = DH_GROUP[group];
    if (!g) throw new Error(`Diffie-Hellman group ${group} is not supported`);
    this.ecdh = createECDH(g.curve);
    // Uncompressed point 0x04 | x | y; IKEv2 sends x | y.
    this.publicValue = this.ecdh.generateKeys().subarray(1);
  }

  /** The shared secret: the x coordinate of the shared point (RFC 5903 §7). */
  computeSecret(peer: Buffer): Buffer {
    const g = DH_GROUP[this.group];
    if (peer.length !== 2 * g.size) throw new Error('The gateway sent a key exchange value of the wrong size');
    return this.ecdh.computeSecret(Buffer.concat([Buffer.from([4]), peer]));
  }
}

export function prf(alg: number, key: Buffer, data: Buffer): Buffer {
  return createHmac(PRF[alg].hash, key).update(data).digest();
}

/** prf+ (RFC 7296 §2.13): T1 | T2 | … with Tn = prf(K, Tn-1 | S | n), cut to `length`. */
export function prfPlus(alg: number, key: Buffer, seed: Buffer, length: number): Buffer {
  const out: Buffer[] = [];
  let t = Buffer.alloc(0);
  let total = 0;
  for (let n = 1; total < length; n++) {
    if (n > 255) throw new Error('prf+ asked for too much key material');
    t = prf(alg, key, Buffer.concat([t, seed, Buffer.from([n])]));
    out.push(t);
    total += t.length;
  }
  return Buffer.concat(out).subarray(0, length);
}

export interface IkeKeys {
  skD: Buffer;
  skAi: Buffer;
  skAr: Buffer;
  skEi: Buffer;
  skEr: Buffer;
  skPi: Buffer;
  skPr: Buffer;
}

/** SKEYSEED and the seven keys (RFC 7296 §2.14). */
export function deriveIkeKeys(suite: Suite, sharedSecret: Buffer, ni: Buffer, nr: Buffer, spiI: Buffer, spiR: Buffer): IkeKeys {
  const p = suite.prf!;
  const skeyseed = prf(p, Buffer.concat([ni, nr]), sharedSecret);
  const prfLen = PRF[p].length;
  const integLen = INTEG[suite.integ].keyLength;
  const encrLen = suite.encr.keyLength / 8;
  const km = prfPlus(p, skeyseed, Buffer.concat([ni, nr, spiI, spiR]), prfLen * 3 + integLen * 2 + encrLen * 2);
  let off = 0;
  const take = (n: number) => km.subarray(off, (off += n));
  return { skD: take(prfLen), skAi: take(integLen), skAr: take(integLen), skEi: take(encrLen), skEr: take(encrLen), skPi: take(prfLen), skPr: take(prfLen) };
}

/** Keys of a child (ESP) SA: KEYMAT = prf+(SK_d, Ni | Nr), initiator-to-responder first (§2.17). */
export function deriveChildKeys(prfAlg: number, skD: Buffer, ni: Buffer, nr: Buffer, esp: Suite) {
  const encrLen = esp.encr.keyLength / 8;
  const integLen = INTEG[esp.integ].keyLength;
  const km = prfPlus(prfAlg, skD, Buffer.concat([ni, nr]), 2 * (encrLen + integLen));
  let off = 0;
  const take = (n: number) => Buffer.from(km.subarray(off, (off += n)));
  return { encrOut: take(encrLen), integOut: take(integLen), encrIn: take(encrLen), integIn: take(integLen) };
}

function cipherName(keyLength: number): 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc' {
  return `aes-${keyLength}-cbc` as 'aes-128-cbc';
}

/**
 * The SK payload body for `inner` (already-encoded payloads): IV | ciphertext(inner | padding | pad length) | ICV.
 * `aad` is the message from the IKE header up to and including the SK payload's generic header; the ICV covers it and
 * the IV and ciphertext. Returns the body without the ICV filled in, and a function to compute the ICV over the whole
 * message once the header's length is known.
 */
export function encryptSk(suite: Suite, encKey: Buffer, inner: Buffer): Buffer {
  const iv = randomBytes(16);
  const padLen = (16 - ((inner.length + 1) % 16)) % 16;
  const plain = Buffer.concat([inner, Buffer.alloc(padLen), Buffer.from([padLen])]);
  const c = createCipheriv(cipherName(suite.encr.keyLength), encKey, iv);
  c.setAutoPadding(false);
  return Buffer.concat([iv, c.update(plain), c.final()]);
}

export function icv(suite: Suite, integKey: Buffer, data: Buffer): Buffer {
  const i = INTEG[suite.integ];
  return createHmac(i.hash, integKey).update(data).digest().subarray(0, i.icvLength);
}

/** Check the ICV at the end of `message` and decrypt the SK payload body (`body` is IV | ciphertext | ICV). */
export function decryptSk(suite: Suite, encKey: Buffer, integKey: Buffer, message: Buffer, body: Buffer): Buffer {
  const icvLen = INTEG[suite.integ].icvLength;
  const got = message.subarray(message.length - icvLen);
  const want = icv(suite, integKey, message.subarray(0, message.length - icvLen));
  if (got.length !== want.length || !timingSafeEqual(got, want)) throw new Error('An IKE message failed its integrity check');
  const iv = body.subarray(0, 16);
  const ct = body.subarray(16, body.length - icvLen);
  if (ct.length % 16) throw new Error('An encrypted IKE payload has a bad length');
  const d = createDecipheriv(cipherName(suite.encr.keyLength), encKey, iv);
  d.setAutoPadding(false);
  const plain = Buffer.concat([d.update(ct), d.final()]);
  const padLen = plain[plain.length - 1];
  if (padLen + 1 > plain.length) throw new Error('An encrypted IKE payload has bad padding');
  return plain.subarray(0, plain.length - padLen - 1);
}

/**
 * AUTH with a shared secret (RFC 7296 §2.15): prf(prf(secret, "Key Pad for IKEv2"), message | peer nonce |
 * prf(SK_p, ID body)). After EAP, the secret is the EAP method's MSK (§2.16).
 */
export function authValue(prfAlg: number, secret: Buffer, message: Buffer, peerNonce: Buffer, skP: Buffer, idBody: Buffer): Buffer {
  const key = prf(prfAlg, secret, Buffer.from('Key Pad for IKEv2', 'ascii'));
  return prf(prfAlg, key, Buffer.concat([message, peerNonce, prf(prfAlg, skP, idBody)]));
}

export { randomBytes };
