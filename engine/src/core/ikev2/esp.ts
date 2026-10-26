// ESP in tunnel mode (RFC 4303) with AES-CBC (RFC 3602) and HMAC-SHA2 (RFC 4868), inside UDP (RFC 3948): the packets
// that carry the user's traffic once IKEv2 has agreed the keys. One SA each way; the inbound side checks the ICV
// before decrypting and drops replays (a 64-packet window).
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { INTEG, type Suite } from './crypto';

/** Next header of an inner IPv4 packet (tunnel mode). */
const NEXT_IPV4 = 4;
const REPLAY_WINDOW = 64;

export interface EspKeys {
  spiOut: Buffer;
  spiIn: Buffer;
  suite: Suite;
  encrOut: Buffer;
  integOut: Buffer;
  encrIn: Buffer;
  integIn: Buffer;
}

export class EspError extends Error {}

export class Esp {
  private seqOut = 0;
  /** Highest sequence number seen, and the bitmap of the ones just below it. */
  private seqHigh = 0;
  private window = 0n;
  private readonly cipher: string;
  private readonly hash: string;
  private readonly icvLength: number;
  /** Bytes of inner packets each way, for the traffic counters. */
  bytesOut = 0;
  bytesIn = 0;

  constructor(private readonly k: EspKeys) {
    this.cipher = `aes-${k.suite.encr.keyLength}-cbc`;
    const i = INTEG[k.suite.integ];
    this.hash = i.hash;
    this.icvLength = i.icvLength;
  }

  /** An IPv4 packet from this computer, as the ESP packet to send (the body of a UDP datagram to port 4500). */
  encapsulate(packet: Buffer): Buffer {
    this.seqOut++;
    if (this.seqOut > 0xffffffff) throw new EspError('The ESP sequence number ran out: the tunnel needs new keys');
    const head = Buffer.alloc(8);
    this.k.spiOut.copy(head, 0);
    head.writeUInt32BE(this.seqOut, 4);
    // Payload | padding 1, 2, 3, … | pad length | next header, to a multiple of the block size (RFC 4303 §2.4).
    const padLen = (16 - ((packet.length + 2) % 16)) % 16;
    const pad = Buffer.alloc(padLen);
    for (let i = 0; i < padLen; i++) pad[i] = i + 1;
    const iv = randomBytes(16);
    const c = createCipheriv(this.cipher, this.k.encrOut, iv);
    c.setAutoPadding(false);
    const ct = Buffer.concat([c.update(Buffer.concat([packet, pad, Buffer.from([padLen, NEXT_IPV4])])), c.final()]);
    const unsigned = Buffer.concat([head, iv, ct]);
    const icv = createHmac(this.hash, this.k.integOut).update(unsigned).digest().subarray(0, this.icvLength);
    this.bytesOut += packet.length;
    return Buffer.concat([unsigned, icv]);
  }

  /** True when `data` is ESP for our inbound SA (not a NAT-T keepalive or IKE, which start differently). */
  isOurs(data: Buffer): boolean {
    return data.length >= 8 + 16 + 16 + this.icvLength && data.subarray(0, 4).equals(this.k.spiIn);
  }

  /** The IPv4 packet inside an ESP packet from the gateway; throws (and the packet is dropped) when it is not valid. */
  decapsulate(data: Buffer): Buffer {
    if (!this.isOurs(data)) throw new EspError('Not ESP for this tunnel');
    const seq = data.readUInt32BE(4);
    if (!this.replayOk(seq)) throw new EspError('Replayed ESP packet');
    const icv = data.subarray(data.length - this.icvLength);
    const want = createHmac(this.hash, this.k.integIn).update(data.subarray(0, data.length - this.icvLength)).digest().subarray(0, this.icvLength);
    if (!timingSafeEqual(icv, want)) throw new EspError('ESP packet failed its integrity check');
    const iv = data.subarray(8, 24);
    const ct = data.subarray(24, data.length - this.icvLength);
    if (ct.length === 0 || ct.length % 16) throw new EspError('ESP packet has a bad length');
    const d = createDecipheriv(this.cipher, this.k.encrIn, iv);
    d.setAutoPadding(false);
    const plain = Buffer.concat([d.update(ct), d.final()]);
    const next = plain[plain.length - 1];
    const padLen = plain[plain.length - 2];
    if (padLen + 2 > plain.length) throw new EspError('ESP packet has bad padding');
    this.markSeen(seq);
    // Next header 59 is a dummy packet (RFC 4303 §2.6): valid, but nothing to deliver.
    if (next === 59) return Buffer.alloc(0);
    if (next !== NEXT_IPV4) throw new EspError(`ESP carries next header ${next}, not IPv4`);
    const inner = plain.subarray(0, plain.length - 2 - padLen);
    this.bytesIn += inner.length;
    return inner;
  }

  private replayOk(seq: number): boolean {
    if (seq === 0) return false;
    if (seq > this.seqHigh) return true;
    const diff = this.seqHigh - seq;
    if (diff >= REPLAY_WINDOW) return false;
    return (this.window & (1n << BigInt(diff))) === 0n;
  }

  private markSeen(seq: number): void {
    if (seq > this.seqHigh) {
      const shift = seq - this.seqHigh;
      this.window = shift >= REPLAY_WINDOW ? 1n : ((this.window << BigInt(shift)) | 1n) & ((1n << BigInt(REPLAY_WINDOW)) - 1n);
      this.seqHigh = seq;
    } else {
      this.window |= 1n << BigInt(this.seqHigh - seq);
    }
  }
}
