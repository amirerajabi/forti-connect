// The engine's state and everything that changes it: the profiles and their secrets, the connection (a tunnel from
// backends/, its questions to the user, reconnecting when it drops), gateway checks, live traffic and the log. The HTTP
// server is a thin layer over this class; every change is broadcast as an EngineEvent.
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  Backends,
  ConnectionState,
  EngineEvent,
  GatewayCheck,
  ImportResult,
  LogLine,
  Profile,
  ProfileConfig,
  ProfileInput,
  Prompt,
  Settings,
  Traffic,
  VpnType,
} from '../../../shared/protocol';
import { createTunnel, detectBackends, type TunnelFactory } from './backends';
import { disconnectRas } from './backends/ras';
import type { Leftover, PromptRequest, Tunnel } from './backends/types';
import { checkGateway } from './net';
import { buildLink, normalizeConfig, normalizeInput, parseLinks, profileKey } from './profiles';
import { SecretStore, secretKey } from './secrets';
import { BACKEND_KEYS, defaultSettings, mergeSettings } from './settings';
import { currentPlatform, isElevated, processName, type Platform } from './system';
import { CounterWatcher, type Counters } from './traffic';
import { atomicWrite, errorMessage, newId, readJson } from './util';

const MAX_LOG = 600;
const RECONNECT_DELAYS = [3, 5, 10, 20, 30];
const TEST_PARALLEL = 8;

/** A profile as saved: what the UI sees, minus what is worked out (which secrets are saved). */
type StoredProfile = Omit<Profile, 'hasPassword' | 'hasPsk'>;

interface ProfilesFile {
  profiles: StoredProfile[];
  selectedId: string | null;
}

interface RuntimeFile {
  /** A tunnel that was up when the engine last ran: a crash would leave it behind, so the next start ends it. */
  leftover?: Leftover;
}

export interface ManagerOptions {
  platform?: Platform;
  elevated?: boolean;
  /** Tests run a fake VPN program. */
  tunnelFactory?: TunnelFactory;
  /** Tests skip looking for OpenConnect and strongSwan. */
  backends?: Backends;
  secretKey?: Buffer;
  /** Seconds between reconnect attempts (tests make them short). */
  reconnectDelays?: number[];
  /** How long a connection has to stay up before the reconnect attempts count from zero again. */
  stableAfterMs?: number;
  /** false: skip the certificate check before SSL-VPN connects (tests whose gateways are not real). */
  checkCertificates?: boolean;
}

const EMPTY_TRAFFIC: Traffic = { up: 0, down: 0, totalUp: 0, totalDown: 0 };
const IDLE: ConnectionState = { status: 'disconnected', profileId: null, since: null, address: null, device: null, prompt: null };

export class Manager extends EventEmitter {
  private settings: Settings = defaultSettings();
  private profiles: StoredProfile[] = [];
  private selectedId: string | null = null;
  private connection: ConnectionState = { ...IDLE };
  private traffic: Traffic = { ...EMPTY_TRAFFIC };
  private backends: Backends;
  private logs: LogLine[] = [];
  private pendingLogs: LogLine[] = [];
  private logTimer: NodeJS.Timeout | null = null;
  private runtime: RuntimeFile = {};
  private tunnel: Tunnel | null = null;
  private pending: { prompt: Prompt; resolve: (v: string | null) => void } | null = null;
  /** The computer password, kept in memory only, so reconnecting does not ask for it again. */
  private adminPassword: string | null = null;
  private counters: CounterWatcher;
  private lastCounters: (Counters & { at: number }) | null = null;
  private firstCounters: Counters | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private retry = 0;
  /** Resets the attempt count once a connection has stayed up: a tunnel that keeps dropping must not retry forever. */
  private stableTimer: NodeJS.Timeout | null = null;
  /** Connect / disconnect run one at a time. */
  private op: Promise<unknown> = Promise.resolve();
  private saving: Promise<void> = Promise.resolve();
  private testing = false;
  private testRun: Promise<void> | null = null;
  private secrets!: SecretStore;
  private readonly platform: Platform;
  private readonly elevated: boolean;
  private readonly makeTunnel: TunnelFactory;
  private readonly delays: number[];
  private readonly files: { profiles: string; settings: string; runtime: string; secrets: string };

  readonly dataDir: string;

  constructor(dataDir: string, private readonly opts: ManagerOptions = {}) {
    super();
    this.dataDir = path.resolve(dataDir);
    this.platform = opts.platform ?? currentPlatform();
    this.elevated = opts.elevated ?? isElevated();
    this.makeTunnel = opts.tunnelFactory ?? createTunnel;
    this.delays = opts.reconnectDelays ?? RECONNECT_DELAYS;
    this.counters = new CounterWatcher(this.platform);
    this.backends = opts.backends ?? {
      ssl: { available: false, kind: 'openconnect', path: null, version: null },
      ipsec: { available: false, kind: this.platform === 'win32' ? 'ras' : 'charon', path: null, version: null },
      elevated: this.elevated,
      platform: this.platform,
    };
    this.files = {
      profiles: path.join(this.dataDir, 'profiles.json'),
      settings: path.join(this.dataDir, 'settings.json'),
      runtime: path.join(this.dataDir, 'runtime.json'),
      secrets: path.join(this.dataDir, 'secrets.json'),
    };
  }

  // ---------------------------------------------------------------- lifecycle

  async load(): Promise<void> {
    fs.mkdirSync(this.dataDir, { recursive: true });
    const saved = readJson<Partial<Settings>>(this.files.settings);
    if (saved) this.settings = mergeSettings(defaultSettings(), saved);
    const data = readJson<Partial<ProfilesFile>>(this.files.profiles);
    this.profiles = Array.isArray(data?.profiles) ? data.profiles.filter((p) => p && typeof p.id === 'string' && typeof p.gateway === 'string') : [];
    this.selectedId = data?.selectedId && this.profiles.some((p) => p.id === data.selectedId) ? data.selectedId : (this.profiles[0]?.id ?? null);
    this.secrets = new SecretStore(this.files.secrets, this.opts.secretKey ?? secretKey(this.dataDir));
    this.secrets.load();
    if (this.secrets.unreadable) this.log('warning', `${this.secrets.unreadable} saved passwords could not be read (the key changed); enter them again`);
    this.runtime = readJson<RuntimeFile>(this.files.runtime) ?? {};
    if (this.runtime.leftover) await this.cleanLeftover(this.runtime.leftover);
    if (!this.opts.backends) await this.refreshBackends();
  }

  async shutdown(): Promise<void> {
    await this.disconnect().catch(() => undefined);
    await this.saving;
    await this.secrets?.flush();
  }

  state() {
    return {
      settings: this.settings,
      profiles: this.profileViews(),
      selectedId: this.selectedId,
      connection: this.connection,
      traffic: this.traffic,
      backends: this.backends,
      logs: this.logs,
      testing: this.testing,
    };
  }

  getSettings(): Settings {
    return this.settings;
  }

  private emitEvent(e: EngineEvent): void {
    this.emit('event', e);
  }

  private notify(level: 'info' | 'success' | 'warning' | 'error', text: string, detail?: string): void {
    this.emitEvent({ type: 'notify', level, text, detail });
  }

  // --------------------------------------------------------------------- logs

  log(level: LogLine['level'], text: string): void {
    this.pushLog({ t: Date.now(), level, text });
  }

  private pushLog(line: LogLine): void {
    this.logs.push(line);
    if (this.logs.length > MAX_LOG) this.logs.splice(0, this.logs.length - MAX_LOG);
    this.pendingLogs.push(line);
    // Batched: a VPN program at verbose level writes many lines a second.
    if (!this.logTimer) {
      this.logTimer = setTimeout(() => {
        this.logTimer = null;
        const lines = this.pendingLogs.splice(0);
        if (lines.length) this.emitEvent({ type: 'log', lines });
      }, 250);
    }
  }

  clearLogs(): void {
    this.logs = [];
  }

  // -------------------------------------------------------------- persistence

  private saveProfiles(): void {
    const json = JSON.stringify({ profiles: this.profiles, selectedId: this.selectedId } satisfies ProfilesFile, null, 1);
    this.saving = this.saving.then(() => atomicWrite(this.files.profiles, json)).catch((e) => this.log('error', `Could not save the profiles: ${errorMessage(e)}`));
  }

  private saveRuntime(): void {
    const json = JSON.stringify(this.runtime);
    this.saving = this.saving.then(() => atomicWrite(this.files.runtime, json)).catch(() => undefined);
  }

  private view(p: StoredProfile): Profile {
    const s = this.secrets.get(p.id);
    return { ...p, hasPassword: !!s.password, hasPsk: !!s.psk };
  }

  private profileViews(): Profile[] {
    return this.profiles.map((p) => this.view(p));
  }

  private emitProfiles(): void {
    this.emitEvent({ type: 'profiles', profiles: this.profileViews(), selectedId: this.selectedId });
  }

  private changedProfiles(): void {
    this.saveProfiles();
    this.emitProfiles();
  }

  private setConnection(patch: Partial<ConnectionState>): void {
    this.connection = { ...this.connection, ...patch };
    this.emitEvent({ type: 'connection', connection: this.connection });
  }

  // ------------------------------------------------------------------ settings

  async updateSettings(patch: Partial<Settings>): Promise<Settings> {
    const prev = this.settings;
    const next = mergeSettings(prev, patch);
    this.settings = next;
    const json = JSON.stringify(next, null, 1);
    this.saving = this.saving.then(() => atomicWrite(this.files.settings, json)).catch(() => undefined);
    this.emitEvent({ type: 'settings', settings: next });
    if (BACKEND_KEYS.some((k) => prev[k] !== next[k])) await this.refreshBackends();
    return next;
  }

  async refreshBackends(): Promise<Backends> {
    if (this.opts.backends) return this.backends;
    this.backends = await detectBackends(this.settings, this.dataDir, this.platform, this.elevated);
    this.emitEvent({ type: 'backends', backends: this.backends });
    return this.backends;
  }

  // ------------------------------------------------------------------ profiles

  getProfile(id: string): Profile | undefined {
    const p = this.profiles.find((x) => x.id === id);
    return p ? this.view(p) : undefined;
  }

  private stored(id: string): StoredProfile {
    const p = this.profiles.find((x) => x.id === id);
    if (!p) throw new Error('No such profile');
    return p;
  }

  /** Save or clear the secrets a dialog sent: a string sets, '' clears, undefined keeps. */
  private applySecrets(id: string, input: Partial<ProfileInput>, savePassword: boolean): void {
    const patch: { password?: string | null; psk?: string | null } = {};
    if (typeof input.password === 'string') patch.password = savePassword ? input.password : null;
    else if (!savePassword) patch.password = null;
    if (typeof input.psk === 'string') patch.psk = input.psk;
    this.secrets.set(id, patch);
  }

  addProfile(input: ProfileInput): Profile {
    const c = normalizeInput(input);
    const p: StoredProfile = { ...c, id: newId(), savePassword: input.savePassword !== false, delay: null, addedAt: Date.now(), lastConnectedAt: null };
    this.profiles.push(p);
    this.applySecrets(p.id, input, p.savePassword);
    if (!this.selectedId) this.selectedId = p.id;
    this.changedProfiles();
    return this.view(p);
  }

  updateProfile(id: string, input: Partial<ProfileInput>): Profile {
    const i = this.profiles.findIndex((x) => x.id === id);
    if (i < 0) throw new Error('No such profile');
    const old = this.profiles[i];
    const { id: _id, name: _n, savePassword: _s, delay: _d, addedAt: _a, lastConnectedAt: _l, ...base } = old;
    const c = normalizeInput({ ...input, name: input.name ?? old.name }, base);
    // Changing the type or gateway starts from a clean config, so IPsec fields never linger on an SSL-VPN profile.
    const savePassword = typeof input.savePassword === 'boolean' ? input.savePassword : old.savePassword;
    const sameGateway = c.gateway === old.gateway && c.type === old.type;
    const p: StoredProfile = { ...c, id, savePassword, delay: sameGateway ? old.delay : null, addedAt: old.addedAt, lastConnectedAt: old.lastConnectedAt };
    this.profiles[i] = p;
    this.applySecrets(id, input, savePassword);
    this.changedProfiles();
    return this.view(p);
  }

  duplicateProfile(id: string): Profile {
    const src = this.stored(id);
    const copy: StoredProfile = { ...src, id: newId(), name: `${src.name} (copy)`.slice(0, 100), delay: null, addedAt: Date.now(), lastConnectedAt: null };
    this.profiles.splice(this.profiles.indexOf(src) + 1, 0, copy);
    const s = this.secrets.get(id);
    if (s.password || s.psk) this.secrets.set(copy.id, { password: s.password ?? null, psk: s.psk ?? null });
    this.changedProfiles();
    return this.view(copy);
  }

  async deleteProfiles(ids: string[]): Promise<void> {
    const gone = new Set(ids);
    if (this.connection.profileId && gone.has(this.connection.profileId) && this.connection.status !== 'disconnected') await this.disconnect();
    this.profiles = this.profiles.filter((p) => !gone.has(p.id));
    for (const id of gone) this.secrets.delete(id);
    if (this.selectedId && gone.has(this.selectedId)) this.selectedId = this.profiles[0]?.id ?? null;
    this.changedProfiles();
  }

  select(id: string): void {
    this.stored(id);
    this.selectedId = id;
    this.changedProfiles();
  }

  link(id: string): string {
    const p = this.stored(id);
    return buildLink(p.name, p);
  }

  /** Add the forticonnect:// links found in `text`; secrets are never in a link, so connecting asks for them. */
  importText(text: string): ImportResult {
    const { links, skipped } = parseLinks(text);
    const existing = new Set(this.profiles.map((p) => profileKey(p)));
    let added = 0;
    let duplicates = 0;
    for (const l of links) {
      const key = profileKey(l.config);
      if (existing.has(key)) {
        duplicates++;
        continue;
      }
      existing.add(key);
      this.profiles.push({ ...l.config, id: newId(), name: l.name, savePassword: true, delay: null, addedAt: Date.now(), lastConnectedAt: null });
      added++;
    }
    if (added) {
      this.selectedId ??= this.profiles[0]?.id ?? null;
      this.changedProfiles();
    }
    return { added, duplicates, skipped };
  }

  // ------------------------------------------------------------------ prompts

  /** A tunnel's question: answered from memory (the computer password) or put to the user until they answer. */
  private ask(p: PromptRequest): Promise<string | null> {
    if (p.kind === 'admin') {
      if (p.retry) this.adminPassword = null;
      else if (this.adminPassword) return Promise.resolve(this.adminPassword);
    }
    this.cancelPrompt();
    const prompt: Prompt = { id: newId(), kind: p.kind, message: p.retry && p.kind !== 'admin' ? `That was not accepted. ${p.message}` : p.retry ? `That password was not accepted. ${p.message}` : p.message, detail: p.detail };
    this.setConnection({ prompt });
    if (p.kind !== 'cert') this.notify('info', 'FortiConnect needs your answer to connect', prompt.message);
    return new Promise((resolve) => {
      this.pending = { prompt, resolve };
    });
  }

  answer(promptId: string, value: string, remember = false): void {
    const pending = this.pending;
    if (!pending || pending.prompt.id !== promptId) throw new Error('That question is no longer open');
    if (typeof value !== 'string' || value.length > 4096) throw new Error('Enter an answer');
    this.pending = null;
    this.setConnection({ prompt: null });
    const { kind } = pending.prompt;
    if (kind === 'admin') this.adminPassword = value;
    const id = this.connection.profileId;
    if (remember && id && (kind === 'password' || kind === 'psk') && value) {
      const p = this.profiles.find((x) => x.id === id);
      if (p) {
        if (kind === 'password') p.savePassword = true;
        this.secrets.set(id, { [kind]: value });
        this.changedProfiles();
      }
    }
    pending.resolve(value);
  }

  private cancelPrompt(): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    if (this.connection.prompt) this.setConnection({ prompt: null });
    pending.resolve(null);
  }

  private trustCert(profileId: string, pin: string): void {
    const p = this.profiles.find((x) => x.id === profileId);
    if (!p || p.type !== 'ssl') return;
    p.trustedCert = pin;
    this.log('app', `Trusting the certificate of ${p.gateway} from now on (${pin})`);
    this.changedProfiles();
  }

  /**
   * SSL-VPN: settle the gateway's certificate before OpenConnect starts. OpenConnect asks about a certificate it does not
   * trust on stdout, which Windows holds back while stdout is a pipe, so that question never arrives and connecting
   * times out. Asked here instead, the answer reaches OpenConnect as --servercert. A gateway that cannot be reached is
   * left to OpenConnect to report.
   */
  private async settleCertificate(stored: StoredProfile): Promise<void> {
    if (this.opts.checkCertificates === false) return;
    const check = await checkGateway('ssl', stored.gateway, stored.port);
    if (!check.ok || !check.certPin) return;
    if (check.certTrusted) {
      // The computer trusts it now (a proper certificate replaced a self-signed one): an old pin would only get in the way.
      if (stored.trustedCert && stored.trustedCert !== check.certPin) {
        this.log('app', `${stored.gateway} now has a certificate this computer trusts; the pinned one is no longer needed`);
        stored.trustedCert = undefined;
        this.changedProfiles();
      }
      return;
    }
    if (stored.trustedCert === check.certPin) return;
    const subject = check.certSubject ? ` (issued to "${check.certSubject}")` : '';
    const message = stored.trustedCert
      ? `The gateway's certificate has changed since you trusted it${subject}. Trust the new one only if your administrator replaced it.`
      : `The gateway's certificate is not trusted by this computer${subject}. FortiGates often use their own; trust it if the pin matches what your administrator gave you.`;
    const answer = await this.ask({ kind: 'cert', message, detail: check.certPin });
    if (answer === null || !/^y(es)?$/i.test(answer.trim())) throw new Error('Cancelled');
    this.trustCert(stored.id, check.certPin);
  }

  // ---------------------------------------------------------------- connection

  private queue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.op.then(fn, fn);
    this.op = run.catch(() => undefined);
    return run;
  }

  connect(id?: string): Promise<ConnectionState> {
    this.cancelReconnect();
    this.retry = 0;
    return this.queue(() => this.doConnect(id ?? this.selectedId ?? undefined));
  }

  /** Ends a connection, also one still asking a question or connecting: those are stopped first, then cleaned up in turn. */
  disconnect(): Promise<ConnectionState> {
    this.cancelReconnect();
    this.retry = 0;
    this.cancelPrompt();
    if (this.connection.status === 'connecting') {
      this.setConnection({ status: 'disconnecting', retry: undefined });
      void this.tunnel?.stop();
    }
    return this.queue(() => this.doDisconnect());
  }

  private async doConnect(id: string | undefined): Promise<ConnectionState> {
    const stored = id ? this.profiles.find((p) => p.id === id) : undefined;
    if (!stored) throw new Error('Choose a profile first');
    if (this.tunnel) await this.doDisconnect(true);
    this.selectedId = stored.id;
    this.changedProfiles();
    const profile = this.view(stored);
    this.setConnection({ ...IDLE, status: 'connecting', profileId: profile.id, retry: this.retry || undefined, error: undefined });
    const target = profile.type === 'ssl' ? `${profile.gateway}:${profile.port}` : `${profile.gateway} (${profile.ike?.toUpperCase()})`;
    this.log('app', `Connecting to ${profile.name}: ${profile.type === 'ssl' ? 'SSL-VPN' : 'IPsec'} ${target}`);
    let tunnel: Tunnel | null = null;
    try {
      if (profile.type === 'ssl') await this.settleCertificate(stored);
      tunnel = this.makeTunnel({
        profile: this.view(stored),
        secrets: this.secrets.get(profile.id),
        settings: this.settings,
        backends: this.backends,
        platform: this.platform,
        elevated: this.elevated,
        hooks: {
          log: (l) => this.pushLog(l),
          ask: (p) => this.ask(p),
          trustCert: (pin) => this.trustCert(profile.id, pin),
          dropped: (error) => void this.onDropped(tunnel!, error),
        },
      });
      this.tunnel = tunnel;
      const started = tunnel.start();
      this.rememberLeftover(tunnel);
      const up = await started;
      this.rememberLeftover(tunnel);
      stored.lastConnectedAt = Date.now();
      this.changedProfiles();
      this.markStable();
      this.setConnection({ status: 'connected', since: Date.now(), address: up.address, device: up.device, prompt: null, retry: undefined });
      this.log('app', `Connected${up.address ? `. VPN address ${up.address}` : ''}${up.device ? ` on ${up.device}` : ''}`);
      this.startTraffic(up.device);
      return this.connection;
    } catch (e) {
      const message = errorMessage(e);
      const cancelled = message === 'Cancelled' || this.connection.status === 'disconnecting';
      if (!cancelled) this.log('error', message);
      this.cancelPrompt();
      await tunnel?.stop();
      if (this.tunnel === tunnel) this.tunnel = null;
      this.forgetLeftover();
      this.setConnection({ ...IDLE, profileId: profile.id, error: cancelled ? undefined : message });
      if (cancelled) throw new Error('Cancelled');
      // A drop that could not be repaired: keep trying while attempts are left.
      if (this.retry) this.scheduleReconnect(profile.id, message);
      throw new Error(message);
    }
  }

  private async doDisconnect(switching = false): Promise<ConnectionState> {
    const tunnel = this.tunnel;
    if (!tunnel && this.connection.status === 'disconnected') return this.connection;
    if (!switching && this.connection.status !== 'disconnecting') this.setConnection({ status: 'disconnecting' });
    this.stopTraffic();
    this.tunnel = null;
    await tunnel?.stop();
    this.forgetLeftover();
    if (!switching) {
      this.log('app', 'Disconnected');
      this.setConnection({ ...IDLE, profileId: this.connection.profileId });
    }
    return this.connection;
  }

  private async onDropped(tunnel: Tunnel, error: string): Promise<void> {
    if (this.tunnel !== tunnel) return;
    this.tunnel = null;
    if (this.stableTimer) clearTimeout(this.stableTimer);
    this.stableTimer = null;
    this.stopTraffic();
    this.forgetLeftover();
    const profileId = this.connection.profileId;
    this.log('error', error);
    this.setConnection({ ...IDLE, profileId, error });
    if (profileId && this.settings.reconnect) this.scheduleReconnect(profileId, error);
    else this.notify('error', 'Disconnected', error);
  }

  private scheduleReconnect(profileId: string, error: string): void {
    if (this.retry >= this.delays.length) {
      this.retry = 0;
      this.notify('error', 'Disconnected', error);
      return;
    }
    const wait = this.delays[this.retry];
    this.retry++;
    const attempt = this.retry;
    this.log('app', `Reconnecting in ${wait} s (attempt ${attempt} of ${this.delays.length})`);
    this.setConnection({ retry: attempt });
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.queue(() => this.doConnect(profileId)).catch(() => undefined);
    }, wait * 1000);
  }

  private markStable(): void {
    if (this.stableTimer) clearTimeout(this.stableTimer);
    this.stableTimer = setTimeout(() => {
      this.stableTimer = null;
      this.retry = 0;
    }, this.opts.stableAfterMs ?? 60_000);
    this.stableTimer.unref?.();
  }

  private cancelReconnect(): void {
    if (this.stableTimer) clearTimeout(this.stableTimer);
    this.stableTimer = null;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    if (this.connection.retry) this.setConnection({ retry: undefined });
  }

  // ------------------------------------------------- crash repair (runtime.json)

  private rememberLeftover(tunnel: Tunnel): void {
    const l = tunnel.leftover;
    if (!l || JSON.stringify(l) === JSON.stringify(this.runtime.leftover)) return;
    this.runtime.leftover = l;
    this.saveRuntime();
  }

  private forgetLeftover(): void {
    if (!this.runtime.leftover) return;
    this.runtime = {};
    this.saveRuntime();
  }

  /** End a tunnel the last run left up: a VPN nobody controls would keep routing this computer's traffic. */
  private async cleanLeftover(l: Leftover): Promise<void> {
    try {
      if (l.kind === 'ras') {
        if (this.platform === 'win32') {
          this.log('app', `Ending the Windows VPN connection "${l.name}" left over from the last run`);
          await disconnectRas(l.name);
        }
      } else {
        // Only if that process id still belongs to the VPN program: ids are reused.
        const name = (await processName(l.pid))?.toLowerCase();
        if (name && l.names.some((n) => name.includes(n.toLowerCase()))) {
          this.log('app', `Stopping the VPN left running by the last run (${name}, process ${l.pid})`);
          process.kill(l.pid, process.platform === 'win32' ? undefined : 'SIGINT');
        }
      }
    } catch (e) {
      this.log('warning', `Could not end the VPN left over from the last run: ${errorMessage(e)}`);
    }
    this.runtime = {};
    this.saveRuntime();
  }

  // ------------------------------------------------------------------- traffic

  private startTraffic(device: string | null): void {
    this.stopTraffic();
    this.traffic = { ...EMPTY_TRAFFIC };
    this.emitEvent({ type: 'traffic', traffic: this.traffic });
    if (!device) return;
    this.lastCounters = null;
    this.firstCounters = null;
    this.counters.start(device, (c) => this.onCounters(c));
  }

  private onCounters(c: Counters): void {
    const now = Date.now();
    const prev = this.lastCounters;
    this.lastCounters = { ...c, at: now };
    // The adapter may outlive one connection (Windows keeps RAS counters): count from the first reading.
    this.firstCounters ??= c;
    if (!prev) return;
    const secs = Math.max(0.2, (now - prev.at) / 1000);
    this.traffic = {
      down: Math.max(0, c.rx - prev.rx) / secs,
      up: Math.max(0, c.tx - prev.tx) / secs,
      totalDown: Math.max(0, c.rx - this.firstCounters.rx),
      totalUp: Math.max(0, c.tx - this.firstCounters.tx),
    };
    this.emitEvent({ type: 'traffic', traffic: this.traffic });
  }

  private stopTraffic(): void {
    this.counters.stop();
    if (this.traffic.up || this.traffic.down) {
      this.traffic = { ...this.traffic, up: 0, down: 0 };
      this.emitEvent({ type: 'traffic', traffic: this.traffic });
    }
  }

  // ----------------------------------------------------------- gateway checks

  /** Check a gateway typed into the dialog (before it is saved). */
  checkGateway(type: VpnType, gateway: string, port: number): Promise<GatewayCheck> {
    const c: ProfileConfig = normalizeConfig({ type, gateway, port, username: '' });
    return checkGateway(c.type, c.gateway, c.port);
  }

  /** Check `ids` (all profiles when empty); results arrive as 'delay' events. One run at a time. */
  testDelays(ids: string[]): Promise<void> {
    if (!this.testRun) this.testRun = this.runTests(ids).finally(() => (this.testRun = null));
    return this.testRun;
  }

  private async runTests(ids: string[]): Promise<void> {
    const targets = ids.length ? this.profiles.filter((p) => ids.includes(p.id)) : [...this.profiles];
    if (!targets.length) return;
    this.testing = true;
    this.emitEvent({ type: 'testing', testing: true });
    try {
      for (let i = 0; i < targets.length; i += TEST_PARALLEL) {
        const batch = targets.slice(i, i + TEST_PARALLEL);
        const results = await Promise.all(batch.map(async (p) => ({ id: p.id, delay: await checkGateway(p.type, p.gateway, p.port).then((r) => (r.ok ? r.ms : -1)) })));
        for (const r of results) {
          const p = this.profiles.find((x) => x.id === r.id);
          if (p) p.delay = r.delay;
        }
        this.emitEvent({ type: 'delay', results });
      }
      this.saveProfiles();
    } finally {
      this.testing = false;
      this.emitEvent({ type: 'testing', testing: false });
    }
  }
}
