// Checking a gateway before connecting: for SSL-VPN a TLS handshake (how long it takes, the certificate's pin for
// OpenConnect's --servercert, whether the system trusts it) and a look at the portal page; for IPsec, whose IKE runs
// over UDP without an answer to a stray packet, only the DNS lookup.
import { createHash, X509Certificate } from 'node:crypto';
import * as dns from 'node:dns';
import * as net from 'node:net';
import * as tls from 'node:tls';
import type { GatewayCheck, VpnType } from '../../../shared/protocol';
import { errorMessage } from './util';

/** OpenConnect's pin: SHA-256 of the certificate's public key (SubjectPublicKeyInfo), base64. */
export function certPin(raw: Buffer): string {
  const spki = new X509Certificate(raw).publicKey.export({ type: 'spki', format: 'der' });
  return `pin-sha256:${createHash('sha256').update(spki).digest('base64')}`;
}

/** Signs that a page is a FortiGate's SSL-VPN portal. */
const FORTIGATE = /\/remote\/login|fgt_lang|ftnt|fortinet|sslvpn/i;

export function checkGateway(type: VpnType, host: string, port: number, timeoutMs = 8000): Promise<GatewayCheck> {
  return type === 'ssl' ? checkTls(host, port, timeoutMs) : checkDns(host);
}

async function checkDns(host: string): Promise<GatewayCheck> {
  const started = Date.now();
  if (net.isIP(host)) return { ok: true, ms: 0 };
  try {
    await dns.promises.lookup(host);
    return { ok: true, ms: Date.now() - started };
  } catch (e) {
    return { ok: false, ms: -1, error: errorMessage(e) };
  }
}

function checkTls(host: string, port: number, timeoutMs: number): Promise<GatewayCheck> {
  return new Promise((resolve) => {
    const started = Date.now();
    let result: GatewayCheck | null = null;
    let page = '';
    const servername = net.isIP(host) ? undefined : host;
    // Not rejecting an unknown certificate is the point: FortiGates often use their own, and the user decides.
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
    const done = () => {
      clearTimeout(timer);
      socket.destroy();
      if (result) result.fortigate = FORTIGATE.test(page);
      resolve(result ?? { ok: false, ms: -1, error: 'No answer' });
    };
    const timer = setTimeout(() => {
      if (!result) result = { ok: false, ms: -1, error: 'Timed out' };
      done();
    }, timeoutMs);
    socket.once('secureConnect', () => {
      const ms = Date.now() - started;
      const cert = socket.getPeerX509Certificate();
      result = {
        ok: true,
        ms,
        certPin: cert ? certPin(cert.raw) : undefined,
        certSubject: cert ? (/CN=([^\n]+)/.exec(cert.subject)?.[1] ?? cert.subject.split('\n')[0]) : undefined,
        certTrusted: socket.authorized,
      };
      socket.write(`GET /remote/login HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: FortiConnect\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', (d: Buffer) => {
      page += d.toString('latin1');
      if (page.length > 64 * 1024) done();
    });
    socket.once('end', done);
    socket.once('close', done);
    socket.once('error', (e) => {
      if (!result) result = { ok: false, ms: -1, error: errorMessage(e) };
      done();
    });
  });
}

/** Time to open a TCP connection, in ms; -1 when it fails or takes longer than `timeoutMs`. */
export function tcpPing(host: string, port: number, timeoutMs = 3000): Promise<number> {
  return new Promise((resolve) => {
    const started = Date.now();
    const s = net.connect({ host, port });
    const end = (v: number) => {
      s.destroy();
      resolve(v);
    };
    s.setTimeout(timeoutMs, () => end(-1));
    s.once('connect', () => end(Date.now() - started));
    s.once('error', () => end(-1));
  });
}
