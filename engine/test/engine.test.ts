// Engine tests: profiles and links, settings, the secret store, each backend's command line and the way its output is
// read, the gateway check against a local TLS server, and the Manager connecting through a fake VPN program that asks
// what OpenConnect asks. Nothing here starts a real VPN, touches the network outside 127.0.0.1, or needs admin rights.
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as tls from 'node:tls';
import { after, before, describe, test } from 'node:test';
import type { Backends, EngineEvent, Profile, ProfileConfig } from '../../shared/protocol';
import { charonArgs, charonCommand, charonDialect, shellQuote } from '../src/core/backends/charon';
import { ADMIN_PROMPT, openconnectArgs, openconnectDialect, parseVersion, withSudo } from '../src/core/backends/openconnect';
import { ProcessTunnel } from '../src/core/backends/process';
import { detectHelper, helloHelper, helperProcess } from '../src/core/backends/helper';
import { HELPER_PS1, HELPER_VERSION, installScript } from '../src/core/backends/helper-script';
import { createEnv, entryName, rasError } from '../src/core/backends/ras';
import { Manager } from '../src/core/Manager';
import { certPin, checkGateway } from '../src/core/net';
import { buildLink, normalizeConfig, parseLink, parseLinks, profileKey } from '../src/core/profiles';
import { SecretStore, seal, secretKey, unseal } from '../src/core/secrets';
import { defaultSettings, mergeSettings } from '../src/core/settings';
import { CounterWatcher, parseNetstat, type Counters } from '../src/core/traffic';
import { powershell } from '../src/core/system';
import { createServer, ENGINE_VERSION } from '../src/http/server';

const FIXTURES = path.join(import.meta.dirname, 'fixtures');
const FAKE_VPN = path.join(FIXTURES, 'fake-vpn.mjs');
const KEY = Buffer.alloc(32, 7);

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'forticonnect-test-'));
}

const SSL: ProfileConfig = { type: 'ssl', gateway: 'vpn.example.com', port: 10443, username: 'amir', realm: 'staff' };
const IPSEC: ProfileConfig = { type: 'ipsec', gateway: 'gw.example.com', port: 443, username: 'amir', ike: 'ikev1', aggressive: true, localId: 'dialup', routes: ['10.0.0.0/8'] };

describe('profiles', () => {
  test('a pasted portal address fills gateway, port and realm', () => {
    const c = normalizeConfig({ type: 'ssl', gateway: 'https://vpn.example.com:10443/staff', username: 'amir' });
    assert.deepEqual([c.gateway, c.port, c.realm], ['vpn.example.com', 10443, 'staff']);
    const bare = normalizeConfig({ type: 'ssl', gateway: 'vpn.example.com:8443', username: '' });
    assert.deepEqual([bare.gateway, bare.port, bare.realm], ['vpn.example.com', 8443, undefined]);
    assert.equal(normalizeConfig({ type: 'ssl', gateway: '2001:db8::1', username: '' }).gateway, '2001:db8::1');
  });

  test('bad input is refused with a message', () => {
    assert.throws(() => normalizeConfig({ type: 'ssl', gateway: 'not a host!' }), /address of the FortiGate/);
    assert.throws(() => normalizeConfig({ type: 'ssl', gateway: 'a.b', trustedCert: 'sha1:abc' }), /pin-sha256/);
    assert.throws(() => normalizeConfig({ type: 'ipsec', gateway: 'a.b', routes: ['10.0.0.0/33'] }), /not a network/);
  });

  test('IPsec fields stay off SSL-VPN profiles and the other way round', () => {
    const s = normalizeConfig({ ...IPSEC, type: 'ssl' });
    assert.equal(s.ike, undefined);
    assert.equal(s.routes, undefined);
    const i = normalizeConfig({ ...SSL, type: 'ipsec' });
    assert.equal(i.realm, undefined);
    assert.equal(i.ike, 'ikev1');
    assert.equal(normalizeConfig({ ...IPSEC, ike: 'ikev2' }).aggressive, undefined);
  });

  test('links round-trip without secrets', () => {
    for (const c of [normalizeConfig(SSL), normalizeConfig(IPSEC), normalizeConfig({ type: 'ssl', gateway: '2001:db8::1', port: 443, username: '' })]) {
      const link = buildLink('Office VPN', c);
      assert.match(link, /^forticonnect:\/\//);
      const back = parseLink(link)!;
      assert.equal(back.name, 'Office VPN');
      assert.deepEqual(back.config, c);
    }
    assert.equal(parseLink('https://example.com'), null);
    assert.equal(parseLink('forticonnect://bad host?type=ssl'), null);
    const { links, skipped } = parseLinks(`${buildLink('a', normalizeConfig(SSL))}\nhello\n${buildLink('b', normalizeConfig(IPSEC))}`);
    assert.equal(links.length, 2);
    assert.equal(skipped, 1);
  });

  test('the same gateway and user is one profile', () => {
    assert.equal(profileKey(normalizeConfig(SSL)), profileKey(normalizeConfig({ ...SSL, gateway: 'VPN.example.com', trustedCert: undefined })));
    assert.notEqual(profileKey(normalizeConfig(SSL)), profileKey(normalizeConfig({ ...SSL, username: 'other' })));
  });
});

describe('settings', () => {
  test('every field is coerced', () => {
    const s = mergeSettings(defaultSettings(), { logLevel: 'loud' as never, reconnect: false, openconnectPath: ' "C:\\oc\\openconnect.exe" ', language: 'fa' });
    assert.equal(s.logLevel, 'normal');
    assert.equal(s.reconnect, false);
    assert.equal(s.openconnectPath, 'C:\\oc\\openconnect.exe');
    assert.equal(s.language, 'fa');
  });
});

describe('secrets', () => {
  test('sealed with AES-GCM, unreadable with another key', () => {
    const s = seal(KEY, { password: 'hunter2', psk: 'shared' });
    assert.deepEqual(unseal(KEY, s), { password: 'hunter2', psk: 'shared' });
    assert.equal(unseal(Buffer.alloc(32, 8), s), null);
  });

  test('the file holds no secret in plain text', async () => {
    const dir = tmpDir();
    const file = path.join(dir, 'secrets.json');
    const store = new SecretStore(file, KEY);
    store.set('p1', { password: 'hunter2', psk: 'shared-key' });
    store.set('p2', { password: 'x' });
    store.set('p2', { password: '' });
    await store.flush();
    const raw = fs.readFileSync(file, 'utf8');
    assert.ok(!raw.includes('hunter2') && !raw.includes('shared-key'));
    const again = new SecretStore(file, KEY);
    again.load();
    assert.deepEqual(again.get('p1'), { password: 'hunter2', psk: 'shared-key' });
    assert.deepEqual(again.get('p2'), {});
  });

  test('the key comes from the desktop shell, else from a file made once', () => {
    const dir = tmpDir();
    assert.deepEqual(secretKey(dir, KEY.toString('hex')), KEY);
    const a = secretKey(dir, undefined);
    assert.equal(a.length, 32);
    assert.deepEqual(secretKey(dir, undefined), a);
  });
});

describe('OpenConnect', () => {
  test('command line', () => {
    const args = openconnectArgs({ profile: normalizeConfig({ ...SSL, trustedCert: `pin-sha256:${'A'.repeat(43)}=` }), platform: 'win32', verbose: true, vpncScript: 'C:\\oc\\vpnc-script-win.js' });
    assert.deepEqual(args, ['--protocol=fortinet', '--no-proxy', '--user', 'amir', '--servercert', `pin-sha256:${'A'.repeat(43)}=`, '--interface', 'FortiConnect', '--script', 'C:\\oc\\vpnc-script-win.js', '--verbose', 'https://vpn.example.com:10443/staff']);
    const mac = openconnectArgs({ profile: normalizeConfig({ ...SSL, realm: undefined, port: 443 }), platform: 'darwin', verbose: false, vpncScript: null });
    assert.deepEqual(mac, ['--protocol=fortinet', '--no-proxy', '--user', 'amir', 'https://vpn.example.com:443']);
  });

  test('sudo only where it is needed', () => {
    assert.deepEqual(withSudo('/usr/sbin/openconnect', ['x'], 'linux', false), { file: 'sudo', args: ['-S', '-p', ADMIN_PROMPT, '--', '/usr/sbin/openconnect', 'x'] });
    assert.deepEqual(withSudo('/usr/sbin/openconnect', ['x'], 'linux', true), { file: '/usr/sbin/openconnect', args: ['x'] });
    assert.deepEqual(withSudo('C:\\oc.exe', ['x'], 'win32', false), { file: 'C:\\oc.exe', args: ['x'] });
  });

  test('version and Fortinet support', () => {
    assert.deepEqual(parseVersion('OpenConnect version v9.12\nUsing GnuTLS 3.8.0. Features present: TPMv2, PKCS#11\nSupported protocols: anyconnect (default), nc, gp, pulse, f5, fortinet, array\n'), { version: '9.12', fortinet: true });
    assert.deepEqual(parseVersion('OpenConnect version v8.10\nSupported protocols: anyconnect (default), nc, gp, pulse\n'), { version: '8.10', fortinet: false });
  });

  test('questions and the connected line', () => {
    const c = openconnectDialect.classify;
    assert.equal(c('Username:'), 'username');
    assert.equal(c('Password:'), 'password');
    assert.equal(c('New password:'), 'text');
    assert.equal(c('Please enter your token code:'), 'otp');
    assert.equal(c("Enter 'yes' to accept, 'no' to abort; anything else to view: "), 'cert');
    assert.equal(c(ADMIN_PROMPT), 'admin');
    assert.equal(c('Connected to 1.2.3.4:443'), null);
    assert.deepEqual(openconnectDialect.progress('Connected tun0 as 10.212.134.200, using SSL, with DTLS disabled'), { up: true, address: '10.212.134.200', device: 'tun0' });
    assert.deepEqual(openconnectDialect.progress('Configured as 10.212.134.200, with SSL connected and DTLS in progress'), { up: true, address: '10.212.134.200', device: undefined });
    assert.equal(openconnectDialect.progress('Connected to HTTPS on vpn.example.com with ciphersuite (TLS1.3)'), null);
    assert.match(openconnectDialect.failure('Login failed.', 1), /refused the user name/);
    // Printed even when the pinned certificate is then accepted: not a failure, not the reason for one.
    assert.equal(openconnectDialect.isError('Server certificate verify failed: signer not found'), false);
    assert.equal(openconnectDialect.level?.('Server certificate verify failed: signer not found'), 'info');
  });
});

describe('strongSwan (macOS / Linux IPsec)', () => {
  test('IKEv1 + XAuth, aggressive mode, with the peer ID', () => {
    assert.deepEqual(charonArgs(normalizeConfig(IPSEC), false), ['--host', 'gw.example.com', '--identity', 'dialup', '--profile', 'ikev1-xauth-psk-am', '--xauth-username', 'amir', '--remote-ts', '10.0.0.0/8']);
    assert.deepEqual(charonArgs(normalizeConfig({ ...IPSEC, aggressive: false, localId: undefined, routes: [] }), true), ['--host', 'gw.example.com', '--identity', 'amir', '--profile', 'ikev1-xauth-psk', '--xauth-username', 'amir', '--debug', '2']);
    assert.deepEqual(charonArgs(normalizeConfig({ ...IPSEC, ike: 'ikev2', routes: [] }), false), ['--host', 'gw.example.com', '--identity', 'amir', '--eap-identity', 'amir', '--profile', 'ikev2-eap']);
  });

  test('runs under a terminal and sudo', () => {
    const mac = charonCommand('/opt/homebrew/sbin/charon-cmd', ['--host', 'gw'], 'darwin', false);
    assert.deepEqual(mac, { file: '/usr/bin/script', args: ['-q', '/dev/null', 'sudo', '-S', '-p', ADMIN_PROMPT, '--', '/opt/homebrew/sbin/charon-cmd', '--host', 'gw'] });
    const linux = charonCommand('/usr/sbin/charon-cmd', ['--identity', "o'neil"], 'linux', true);
    assert.deepEqual(linux, { file: 'script', args: ['-qfec', `/usr/sbin/charon-cmd --identity 'o'\\''neil'`, '/dev/null'] });
    assert.equal(shellQuote('a b'), "'a b'");
  });

  test('questions and progress', () => {
    assert.equal(charonDialect.classify('Preshared Key:'), 'psk');
    assert.equal(charonDialect.classify('EAP password:'), 'password');
    assert.deepEqual(charonDialect.progress('installing new virtual IP 10.10.20.3'), { address: '10.10.20.3' });
    assert.deepEqual(charonDialect.progress('CHILD_SA cmd{1} established with SPIs c1a2b3c4_i'), { up: true });
    assert.match(charonDialect.failure('received AUTHENTICATION_FAILED notify error', 1), /refused the user name/);
    assert.match(charonDialect.failure('giving up after 5 retransmits', 1), /did not answer/);
  });
});

describe('Windows VPN client (IPsec)', () => {
  test('entry names and values handed to PowerShell', () => {
    assert.equal(entryName('Office "HQ"; rm -rf'), 'FortiConnect Office HQ rm -rf');
    assert.deepEqual(createEnv('FortiConnect X', normalizeConfig({ ...IPSEC, ike: 'l2tp' }), 'psk!'), { FC_NAME: 'FortiConnect X', FC_GATEWAY: 'gw.example.com', FC_MODE: 'l2tp', FC_PSK: 'psk!', FC_ROUTES: '10.0.0.0/8' });
  });

  test('rasdial errors in words', () => {
    assert.match(rasError('Remote Access error 691 - The remote connection was denied', 691), /refused the user name/);
    assert.match(rasError('Remote Access error 809 - …', 809), /UDP ports 500 and 4500/);
    assert.match(rasError('Remote Access error 123 - Something odd happened', 123), /Windows VPN: Remote Access error 123/);
  });
});

test('macOS traffic counters from netstat', () => {
  const out = 'Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\nutun4      1400  <Link#21>                          1200     0     987654      900     0     123456     0\nutun4      1400  10.212.134/24 10.212.134.200       1200     -     987654      900     -     123456     -\n';
  assert.deepEqual(parseNetstat(out), { rx: 987654, tx: 123456 });
});

describe('gateway check', () => {
  let server: tls.Server;
  let port = 0;
  const cert = fs.readFileSync(path.join(FIXTURES, 'gateway.crt'));
  before(async () => {
    server = tls.createServer({ cert, key: fs.readFileSync(path.join(FIXTURES, 'gateway.key')) }, (s) => {
      s.once('data', () => s.end('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<form action="/remote/logincheck">'));
      s.on('error', () => undefined);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as { port: number }).port;
  });
  after(() => server.close());

  test('SSL-VPN: time, certificate pin, not trusted, looks like a FortiGate', async () => {
    const r = await checkGateway('ssl', '127.0.0.1', port);
    assert.equal(r.ok, true);
    assert.ok(r.ms >= 0);
    assert.equal(r.certPin, certPin(new (await import('node:crypto')).X509Certificate(cert).raw));
    assert.match(r.certPin!, /^pin-sha256:[A-Za-z0-9+/]{43}=$/);
    assert.equal(r.certSubject, 'fortigate.test');
    assert.equal(r.certTrusted, false);
    assert.equal(r.fortigate, true);
  });

  test('a closed port fails', async () => {
    const r = await checkGateway('ssl', '127.0.0.1', 1, 2000);
    assert.equal(r.ok, false);
  });
});

// ------------------------------------------------------------------ the Manager with a fake VPN program

const BACKENDS: Backends = {
  ssl: { available: true, kind: 'openconnect', path: FAKE_VPN, version: 'test' },
  ipsec: { available: false, kind: 'charon', path: null, version: null },
  elevated: true,
  platform: 'linux',
};

async function fakeManager(mode: string, extra: { reconnect?: boolean; checkCertificates?: boolean; reachable?: () => boolean } = {}) {
  const dir = tmpDir();
  /** The profiles the tunnel was made for, as the backend saw them (with the certificate pin to pass on). */
  const started: Profile[] = [];
  const m = new Manager(dir, {
    platform: 'linux',
    elevated: true,
    backends: BACKENDS,
    secretKey: KEY,
    reconnectDelays: [0.05],
    checkCertificates: extra.checkCertificates ?? false,
    gatewayReachable: async () => extra.reachable?.() ?? true,
    networkPollMs: 50,
    tunnelFactory: (ctx) => {
      started.push(ctx.profile);
      return new ProcessTunnel({ file: process.execPath, args: [FAKE_VPN, mode], username: ctx.profile.username, secrets: ctx.secrets, dialect: openconnectDialect, hooks: ctx.hooks, names: ['node'], stopSignal: 'SIGINT', connectTimeoutMs: 15_000 });
    },
  });
  await m.load();
  await m.updateSettings({ reconnect: extra.reconnect ?? false });
  const events: EngineEvent[] = [];
  m.on('event', (e: EngineEvent) => events.push(e));
  return { m, dir, events, started };
}

/** Wait for the connection to ask something, and return the question. */
function nextPrompt(m: Manager, timeoutMs = 10_000) {
  return new Promise<NonNullable<ReturnType<Manager['state']>['connection']['prompt']>>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('no prompt')), timeoutMs);
    const check = () => {
      const p = m.state().connection.prompt;
      if (p) {
        clearTimeout(t);
        m.off('event', check);
        resolve(p);
      }
    };
    m.on('event', check);
    check();
  });
}

describe('Manager', () => {
  test('connects with the saved password, asks for the FortiToken code, never logs the password', async () => {
    const { m } = await fakeManager('ok');
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    assert.equal(p.hasPassword, true);
    assert.ok(!JSON.stringify(m.state()).includes('secret"'));
    const connecting = m.connect(p.id);
    const q = await nextPrompt(m);
    assert.equal(q.kind, 'otp');
    m.answer(q.id, '123456');
    const c = await connecting;
    assert.equal(c.status, 'connected');
    assert.equal(c.address, '10.10.0.5');
    assert.ok(m.state().logs.some((l) => l.text.includes('password=•••')));
    assert.ok(!m.state().logs.some((l) => l.text.includes('secret')));
    assert.ok(m.getProfile(p.id)!.lastConnectedAt);
    const d = await m.disconnect();
    assert.equal(d.status, 'disconnected');
    await m.shutdown();
  });

  test('asks for the password when it is not saved, and remembers it when told to', async () => {
    const { m } = await fakeManager('ok');
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: false, password: 'ignored' });
    assert.equal(p.hasPassword, false);
    const connecting = m.connect(p.id);
    const q1 = await nextPrompt(m);
    assert.equal(q1.kind, 'password');
    m.answer(q1.id, 'secret', true);
    const q2 = await nextPrompt(m);
    assert.equal(q2.kind, 'otp');
    m.answer(q2.id, '123456');
    assert.equal((await connecting).status, 'connected');
    assert.equal(m.getProfile(p.id)!.hasPassword, true);
    assert.equal(m.getProfile(p.id)!.savePassword, true);
    await m.shutdown();
  });

  test('an untrusted certificate is put to the user, and trusting it saves its pin', async () => {
    const { m } = await fakeManager('cert');
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const connecting = m.connect(p.id);
    const q = await nextPrompt(m);
    assert.equal(q.kind, 'cert');
    assert.equal(q.detail, `pin-sha256:${'A'.repeat(43)}=`);
    m.answer(q.id, 'yes');
    const otp = await nextPrompt(m);
    m.answer(otp.id, '123456');
    assert.equal((await connecting).status, 'connected');
    assert.equal(m.getProfile(p.id)!.trustedCert, `pin-sha256:${'A'.repeat(43)}=`);
    await m.shutdown();
  });

  test('a refused password is a clear error', async () => {
    const { m } = await fakeManager('ok');
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'wrong' });
    await assert.rejects(m.connect(p.id), /refused the user name, password or code/);
    assert.equal(m.state().connection.status, 'disconnected');
    assert.match(m.state().connection.error ?? '', /refused/);
    await m.shutdown();
  });

  test('disconnecting while a question waits cancels the connection', async () => {
    const { m } = await fakeManager('ok');
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const connecting = m.connect(p.id).catch((e: Error) => e.message);
    await nextPrompt(m);
    await m.disconnect();
    assert.equal(await connecting, 'Cancelled');
    assert.equal(m.state().connection.status, 'disconnected');
    assert.equal(m.state().connection.prompt, null);
    assert.equal(m.state().connection.error, undefined);
    await m.shutdown();
  });

  test('a dropped tunnel reconnects (asking again for the code), then gives up', async () => {
    const { m, events } = await fakeManager('drop', { reconnect: true });
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const first = m.connect(p.id);
    m.answer((await nextPrompt(m)).id, '123456');
    assert.equal((await first).status, 'connected');
    // The drop, one retry (which asks for the code again and connects), the second drop, then no attempts are left.
    m.answer((await nextPrompt(m)).id, '123456');
    await new Promise<void>((resolve) => {
      const check = () => events.some((e) => e.type === 'notify' && e.level === 'error') && resolve();
      m.on('event', check);
      check();
    });
    assert.ok(events.some((e) => e.type === 'connection' && e.connection.retry === 1));
    assert.equal(m.state().connection.status, 'disconnected');
    assert.match(m.state().connection.error ?? '', /connection to the gateway lost/);
    await m.shutdown();
  });

  test('a gateway that refuses to resume: a lost tunnel ends at once, waits for the network, then logs in again', async () => {
    // The gateway "does not answer" for the first three looks after the drop.
    let looks = 0;
    const { m, events } = await fakeManager('lost', { reconnect: true, reachable: () => ++looks > 3 });
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const first = m.connect(p.id);
    m.answer((await nextPrompt(m)).id, '123456');
    assert.equal((await first).status, 'connected');
    // OpenConnect's reconnect loop starts; the engine ends it instead of waiting minutes, waits, then logs in again.
    const again = await nextPrompt(m);
    assert.equal(again.kind, 'otp');
    assert.ok(m.state().logs.some((l) => /does not let a session resume: logging in again/.test(l.text)));
    assert.ok(m.state().logs.some((l) => /Waiting for the network: vpn\.example\.com:10443 does not answer/.test(l.text)));
    assert.ok(m.state().logs.some((l) => /answers again/.test(l.text)));
    assert.ok(events.some((e) => e.type === 'connection' && e.connection.waitingForNetwork === true));
    // Waiting for the network used up no attempts: this is still the first.
    assert.equal(Math.max(...events.flatMap((e) => (e.type === 'connection' && e.connection.retry ? [e.connection.retry] : []))), 1);
    assert.equal(looks, 4);
    m.answer(again.id, '123456');
    await new Promise<void>((resolve) => {
      const check = () => m.state().connection.status === 'connected' && resolve();
      m.on('event', check);
      check();
    });
    assert.equal(m.state().connection.waitingForNetwork, undefined);
    await m.disconnect();
    await m.shutdown();
  });

  test('a gateway that allows resuming: OpenConnect is left to resume the session itself', async () => {
    const { m } = await fakeManager('lost-resumable', { reconnect: true });
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const first = m.connect(p.id);
    m.answer((await nextPrompt(m)).id, '123456');
    assert.equal((await first).status, 'connected');
    await new Promise((r) => setTimeout(r, 1000));
    assert.ok(m.state().logs.some((l) => /remaining timeout/.test(l.text)));
    assert.equal(m.state().connection.status, 'connected');
    await m.disconnect();
    await m.shutdown();
  });

  test('disconnecting while waiting for the network stops waiting', async () => {
    const { m } = await fakeManager('lost', { reconnect: true, reachable: () => false });
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const first = m.connect(p.id);
    m.answer((await nextPrompt(m)).id, '123456');
    await first;
    await new Promise<void>((resolve) => {
      const check = () => m.state().connection.waitingForNetwork && resolve();
      m.on('event', check);
      check();
    });
    await m.disconnect();
    const c = m.state().connection;
    assert.equal(c.status, 'disconnected');
    assert.equal(c.waitingForNetwork, undefined);
    assert.equal(c.retry, undefined);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(m.state().connection.status, 'disconnected');
    await m.shutdown();
  });

  test('profiles: edit keeps or clears secrets, duplicate copies them, links import once', async () => {
    const { m } = await fakeManager('ok');
    const p = m.addProfile({ name: 'Branch', ...IPSEC, savePassword: true, password: 'pw', psk: 'k' });
    assert.deepEqual([p.hasPassword, p.hasPsk], [true, true]);
    const kept = m.updateProfile(p.id, { name: 'Branch 2' });
    assert.deepEqual([kept.name, kept.hasPassword, kept.hasPsk, kept.localId], ['Branch 2', true, true, 'dialup']);
    const cleared = m.updateProfile(p.id, { psk: '' });
    assert.equal(cleared.hasPsk, false);
    const copy = m.duplicateProfile(p.id);
    assert.equal(copy.hasPassword, true);
    const link = m.link(p.id);
    assert.deepEqual(m.importText(link), { added: 0, duplicates: 1, skipped: 0 });
    assert.deepEqual(m.importText(buildLink('New', normalizeConfig(SSL))), { added: 1, duplicates: 0, skipped: 0 });
    await m.deleteProfiles([p.id]);
    assert.equal(m.state().profiles.length, 2);
    await m.shutdown();
  });

  test('a VPN program left running by a crash is stopped on the next start', async () => {
    const dir = tmpDir();
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    await new Promise((r) => setTimeout(r, 300));
    fs.writeFileSync(path.join(dir, 'runtime.json'), JSON.stringify({ leftover: { kind: 'process', pid: child.pid, names: ['node'] } }));
    const exited = new Promise((r) => child.once('exit', r));
    const m = new Manager(dir, { platform: 'linux', elevated: true, backends: BACKENDS, secretKey: KEY });
    await m.load();
    await Promise.race([exited, new Promise((_, rej) => setTimeout(() => rej(new Error('still running')), 5000))]);
    assert.ok(m.state().logs.some((l) => /left running by the last run/.test(l.text)));
    await m.shutdown();
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, 'runtime.json'), 'utf8')), {});
  });
});

// OpenConnect on Windows asks about an untrusted certificate on stdout, which never reaches a pipe in time: the Manager
// settles the certificate itself, before OpenConnect starts, against a local self-signed "FortiGate".
describe('Manager: the gateway certificate before connecting', () => {
  let server: tls.Server;
  let port = 0;
  const cert = fs.readFileSync(path.join(FIXTURES, 'gateway.crt'));
  const pin = certPin(new X509Certificate(cert).raw);
  before(async () => {
    server = tls.createServer({ cert, key: fs.readFileSync(path.join(FIXTURES, 'gateway.key')) }, (s) => {
      s.once('data', () => s.end('HTTP/1.1 200 OK\r\n\r\n/remote/login'));
      s.on('error', () => undefined);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as { port: number }).port;
  });
  after(() => server.close());

  test('an untrusted certificate is asked about first, and its pin goes to OpenConnect', async () => {
    const { m, started } = await fakeManager('ok', { checkCertificates: true });
    const p = m.addProfile({ name: 'Office', type: 'ssl', gateway: '127.0.0.1', port, username: 'amir', savePassword: true, password: 'secret' });
    const connecting = m.connect(p.id);
    const q = await nextPrompt(m);
    assert.equal(q.kind, 'cert');
    assert.equal(q.detail, pin);
    assert.match(q.message, /not trusted by this computer \(issued to "fortigate\.test"\)/);
    assert.equal(started.length, 0, 'OpenConnect must not start before the certificate is settled');
    m.answer(q.id, 'yes');
    m.answer((await nextPrompt(m)).id, '123456');
    assert.equal((await connecting).status, 'connected');
    assert.equal(started[0].trustedCert, pin);
    assert.equal(m.getProfile(p.id)!.trustedCert, pin);
    await m.shutdown();
  });

  test('a pinned certificate connects without asking', async () => {
    const { m } = await fakeManager('ok', { checkCertificates: true });
    const p = m.addProfile({ name: 'Office', type: 'ssl', gateway: '127.0.0.1', port, username: 'amir', trustedCert: pin, savePassword: true, password: 'secret' });
    const connecting = m.connect(p.id);
    const q = await nextPrompt(m);
    assert.equal(q.kind, 'otp');
    m.answer(q.id, '123456');
    assert.equal((await connecting).status, 'connected');
    await m.shutdown();
  });

  test('a changed certificate is flagged, and refusing it cancels', async () => {
    const { m, started } = await fakeManager('ok', { checkCertificates: true });
    const old = `pin-sha256:${'B'.repeat(43)}=`;
    const p = m.addProfile({ name: 'Office', type: 'ssl', gateway: '127.0.0.1', port, username: 'amir', trustedCert: old, savePassword: true, password: 'secret' });
    const connecting = m.connect(p.id);
    const q = await nextPrompt(m);
    assert.equal(q.kind, 'cert');
    assert.match(q.message, /has changed since you trusted it/);
    m.answer(q.id, 'no');
    assert.equal((await connecting.catch((e: Error) => e.message)), 'Cancelled');
    assert.equal(started.length, 0);
    assert.equal(m.getProfile(p.id)!.trustedCert, old);
    assert.equal(m.state().connection.status, 'disconnected');
    await m.shutdown();
  });
});

// The Windows VPN helper: the real script (PowerShell compiling the C#), run in test mode as this user on its own pipe,
// with the fake VPN program in place of OpenConnect. The Manager runs as a normal user and connects through it.
describe('Windows VPN helper', { skip: process.platform !== 'win32' }, () => {
  const pipeName = `forticonnect-test-${process.pid}`;
  const pipe = `\\\\.\\pipe\\${pipeName}`;
  let helper: ChildProcess;
  let helperLog = '';
  const dir = tmpDir();
  const HELPER_BACKENDS: Backends = {
    ssl: { available: true, kind: 'openconnect', path: 'C:\\Program Files\\OpenConnect\\openconnect.exe', version: 'test' },
    ipsec: { available: true, kind: 'ras', path: null, version: null },
    elevated: false,
    platform: 'win32',
    helper: { state: 'running', version: HELPER_VERSION, current: HELPER_VERSION },
  };

  before(async () => {
    fs.writeFileSync(path.join(dir, 'fc-helper.ps1'), HELPER_PS1);
    helper = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 'fc-helper.ps1'), '-PipeName', pipeName, '-TestCommand', `${process.execPath}|${FAKE_VPN}|ok`, '-WorkDir', path.join(dir, 'work')], { windowsHide: true });
    helper.stdout?.on('data', (d: Buffer) => (helperLog += d));
    helper.stderr?.on('data', (d: Buffer) => (helperLog += d));
    // PowerShell compiles the helper when it starts.
    const until = Date.now() + 90_000;
    while (Date.now() < until) {
      if ((await helloHelper(pipe, 1000)) === HELPER_VERSION) return;
      if (helper.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error(`The helper did not start: ${helperLog}`);
  });
  after(() => helper?.kill());

  test('answers hello with its version, and detection says running', async () => {
    assert.equal(await helloHelper(pipe), HELPER_VERSION);
    const info = await detectHelper(pipe);
    assert.equal(info.state, 'running');
    assert.equal(await helloHelper('\\\\.\\pipe\\forticonnect-nobody-here', 500), null);
  });

  test('the Manager connects SSL-VPN through it without administrator rights, and disconnecting ends it', async () => {
    const m = new Manager(tmpDir(), { platform: 'win32', elevated: false, backends: HELPER_BACKENDS, secretKey: KEY, checkCertificates: false, helperPipe: pipe });
    await m.load();
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    const connecting = m.connect(p.id);
    const q = await nextPrompt(m, 20_000);
    assert.equal(q.kind, 'otp');
    m.answer(q.id, '123456');
    const c = await connecting;
    assert.equal(c.status, 'connected');
    assert.equal(c.address, '10.10.0.5');
    assert.ok(!m.state().logs.some((l) => l.text.includes('secret')));
    // The helper built OpenConnect's command line itself.
    assert.ok(m.state().logs.some((l) => l.text.includes('password=•••')));
    await m.disconnect();
    assert.equal(m.state().connection.status, 'disconnected');
    // Ended with Ctrl+C (the fake answers it by logging out), not killed: OpenConnect cleans up its adapter that way.
    assert.ok(m.state().logs.some((l) => l.text.includes('Logged out')), `the VPN program was not asked to stop. helper.log:\n${fs.readFileSync(path.join(dir, 'work', 'helper.log'), 'utf8')}`);
    assert.doesNotMatch(fs.readFileSync(path.join(dir, 'work', 'helper.log'), 'utf8'), /killing it/);
    // One connection at a time, and the last one is gone: a new one may start.
    const again = m.connect(p.id);
    m.answer((await nextPrompt(m, 20_000)).id, '123456');
    assert.equal((await again).status, 'connected');
    await m.shutdown();
  });

  test('it refuses fields it cannot check, and an absent helper is a clear error', async () => {
    const bad = helperProcess({ gateway: 'evil.example.com & calc', port: 443, realm: '', user: 'u', servercert: '', verbose: false }, pipe);
    const err = await new Promise<string>((resolve) => bad.onError((e) => resolve(e.message)));
    assert.match(err, /Invalid gateway/);
    const none = helperProcess({ gateway: 'vpn.example.com', port: 443, realm: '', user: 'u', servercert: '', verbose: false }, '\\\\.\\pipe\\forticonnect-nobody-here');
    assert.match(await new Promise<string>((resolve) => none.onError((e) => resolve(e.message))), /not running/);
    const m = new Manager(tmpDir(), { platform: 'win32', elevated: false, backends: { ...HELPER_BACKENDS, helper: { state: 'missing', version: null, current: HELPER_VERSION } }, secretKey: KEY, checkCertificates: false });
    await m.load();
    const p = m.addProfile({ name: 'Office', ...SSL, savePassword: true, password: 'secret' });
    await assert.rejects(m.connect(p.id), /needs the FortiConnect VPN helper/);
    await m.shutdown();
  });
});

// Regressions: PowerShell quits without running a multi-line script piped to its stdin, which left the traffic counter
// (and Windows' IPsec setup) silently doing nothing, and the traffic showing 0 B/s.
describe('PowerShell on Windows', { skip: process.platform !== 'win32' }, () => {
  test('a multi-line script runs, with values from the environment', async () => {
    const r = await powershell("$a = $env:FC_TEST\nif ($a -eq 'x') {\n  Write-Output 'ran'\n}\n", { FC_TEST: 'x' });
    assert.equal(r.code, 0);
    assert.equal(r.out.trim(), 'ran');
  });

  test('the traffic counter reads a real adapter', async () => {
    const name = Object.entries(os.networkInterfaces()).find(([n, a]) => !/loopback/i.test(n) && a?.some((x) => !x.internal))?.[0];
    assert.ok(name, 'no network adapter to read');
    const w = new CounterWatcher('win32');
    const sample = await new Promise<Counters | null>((resolve) => {
      const t = setTimeout(() => resolve(null), 15_000);
      w.start(name, (c) => {
        clearTimeout(t);
        resolve(c);
      });
    });
    w.stop();
    assert.ok(sample && sample.rx >= 0 && sample.tx >= 0, `no counters for "${name}"`);
  });
});

test('the elevated install script embeds the helper and only takes a real account id', () => {
  // The OpenConnect FortiConnect ships is copied next to the helper; a path that could break out of the quotes is refused.
  assert.match(installScript('S-1-5-21-1-2-3-1001', 'C:\\Users\\a\\AppData\\Local\\Programs\\FortiConnect\\resources\\core'), /\$from = 'C:\\Users\\a\\AppData\\Local\\Programs\\FortiConnect\\resources\\core'[\s\S]*Copy-Item -Destination \$oc/);
  assert.throws(() => installScript('S-1-5-21-1-2-3-1001', "C:\\x'; Remove-Item C:\\ -Recurse; '"), /Unusual characters/);
  assert.doesNotMatch(installScript('S-1-5-21-1-2-3-1001'), /Copy-Item/);
  const s = installScript('S-1-5-21-1-2-3-1001');
  assert.match(s, /Register-ScheduledTask/);
  assert.match(s, /'S-1-5-21-1-2-3-1001'/);
  const embedded = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/.exec(s)![1];
  assert.equal(gunzipSync(Buffer.from(embedded, 'base64')).toString('utf8'), HELPER_PS1);
  assert.throws(() => installScript("S-1-5'; Remove-Item C:\\ -Recurse; '"), /account id/);
  // It travels as -EncodedCommand, which Windows caps at 32767 characters for the whole command line.
  assert.ok(Buffer.from(s, 'utf16le').toString('base64').length < 30_000, `the encoded install script is too long: ${Buffer.from(s, 'utf16le').toString('base64').length}`);
});

describe('HTTP API', () => {
  test('token, state without secrets, profiles', async () => {
    const { m } = await fakeManager('ok');
    const server = createServer(m, 'tok');
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const call = (method: string, p: string, body?: unknown, token = 'tok') =>
      fetch(`${base}${p}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    try {
      assert.equal((await call('GET', '/api/state', undefined, 'nope')).status, 401);
      const created = (await (await call('POST', '/api/profiles', { name: 'Office', ...SSL, savePassword: true, password: 'top-secret' })).json()) as { id: string; hasPassword: boolean };
      assert.equal(created.hasPassword, true);
      const stateText = await (await call('GET', '/api/state')).text();
      assert.ok(!stateText.includes('top-secret'));
      const state = JSON.parse(stateText) as { version: string; profiles: unknown[] };
      assert.equal(state.version, ENGINE_VERSION);
      assert.equal(state.profiles.length, 1);
      const bad = await call('POST', '/api/profiles', { name: 'x', type: 'ssl', gateway: '' });
      assert.equal(bad.status, 400);
      assert.match(((await bad.json()) as { error: string }).error, /address of the FortiGate/);
      const link = (await (await call('GET', `/api/profiles/${created.id}/link`)).json()) as { link: string };
      assert.match(link.link, /^forticonnect:\/\/vpn\.example\.com:10443\?/);
      const answer = await call('POST', '/api/connect/answer', { id: 'nope', value: 'x' });
      assert.equal(answer.status, 400);
    } finally {
      server.close();
      await m.shutdown();
    }
  });
});
