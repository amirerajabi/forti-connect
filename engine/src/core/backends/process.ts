// A VPN program run as a child process (OpenConnect, charon-cmd), or by the Windows VPN helper on our behalf: its
// output becomes log lines, its questions ("Password:", "Enter 'yes' to accept…") are answered from the saved secrets or
// put to the user, and a line saying the tunnel is up resolves start(). The program-specific parts live in a Dialect.
import { spawn } from 'node:child_process';
import * as os from 'node:os';
import type { LogLine } from '../../../../shared/protocol';
import type { ProfileSecrets } from '../secrets';
import { errorMessage } from '../util';
import type { Leftover, PromptRequest, Tunnel, TunnelHooks, TunnelUp } from './types';

/** What an unfinished output line asks for; 'username' is answered from the profile without asking. */
export type PromptClass = PromptRequest['kind'] | 'username';

export interface Dialect {
  /** Shown in messages: "OpenConnect", "strongSwan". */
  name: string;
  /** An unfinished line the program waits on, or null when it is not a question. */
  classify(text: string): PromptClass | null;
  /** What a finished line says about the tunnel: its address, its device, that it is up. */
  progress(line: string): { up?: boolean; address?: string; device?: string } | null;
  /** Worth keeping as the reason if the program exits. */
  isError(line: string): boolean;
  /** The message for the user when the program exits before the tunnel is up. */
  failure(lastError: string | undefined, code: number | null): string;
  /** A line saying sudo refused the computer password. */
  adminRefused?(line: string): boolean;
  /** The log level for a line whose words mislead (a "failed" that is not a failure); undefined: judge by its words. */
  level?(line: string): LogLine['level'] | undefined;
}

/** A running VPN program as ProcessTunnel sees it: a child process of ours, or one the VPN helper runs for us. */
export interface VpnProcess {
  /** Set for our own child (recorded for crash repair); the helper's ends with the pipe, so it needs none. */
  readonly pid: number | undefined;
  readonly exited: boolean;
  onData(cb: (d: Buffer) => void): void;
  onExit(cb: (code: number | null) => void): void;
  onError(cb: (e: Error) => void): void;
  write(text: string): void;
  /** Ask it to end (signal `signal` on POSIX); `hard` when it did not. */
  kill(hard: boolean, signal?: NodeJS.Signals): void;
}

/** `file` with `args` as our own child process. */
export function localProcess(file: string, args: string[], env?: NodeJS.ProcessEnv): VpnProcess {
  const child = spawn(file, args, { windowsHide: true, env: env ?? process.env, stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin?.on('error', () => undefined);
  return {
    pid: child.pid,
    get exited() {
      return child.exitCode !== null || child.signalCode !== null;
    },
    onData: (cb) => {
      child.stdout?.on('data', cb);
      child.stderr?.on('data', cb);
    },
    onExit: (cb) => void child.once('exit', (code) => cb(code)),
    onError: (cb) => void child.once('error', cb),
    write: (text) => void child.stdin?.write(text),
    kill: (hard, signal) => void child.kill(hard ? 'SIGKILL' : process.platform === 'win32' ? undefined : (signal ?? 'SIGTERM')),
  };
}

export interface ProcessSpec {
  file: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  /** Run it some other way than spawning file + args (through the VPN helper). */
  launch?: () => VpnProcess;
  username: string;
  secrets: ProfileSecrets;
  dialect: Dialect;
  hooks: TunnelHooks;
  /** The adapter the program was told to use, for traffic when the system has not shown its address yet. */
  device?: string;
  /** Names the process may show under, to recognise it after a crash. */
  names: string[];
  /** POSIX: SIGINT lets OpenConnect log out and undo its routes. Windows has no signals: the process is ended. */
  stopSignal?: NodeJS.Signals;
  /** How long the program may take between questions before connecting counts as failed. */
  connectTimeoutMs?: number;
}

/** How long an unfinished line has to stay unchanged before it counts as a question. */
const PROMPT_IDLE_MS = 150;

const LEVEL: [RegExp, LogLine['level']][] = [
  [/\b(error|fatal|failed|refused|denied)\b/i, 'error'],
  [/\b(warning|retransmit|retry|timed out)\b/i, 'warning'],
];

/** The address `ip` is on, from the system's own list: the adapter's name where a program does not print it. */
export function deviceFor(ip: string | null): string | null {
  if (!ip) return null;
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) if (addrs?.some((a) => a.address === ip)) return name;
  return null;
}

export class ProcessTunnel implements Tunnel {
  private child: VpnProcess | null = null;
  private stopping = false;
  private up = false;
  private lastError: string | undefined;
  private partial = '';
  private promptTimer: NodeJS.Timeout | null = null;
  private asking = false;
  private used = { password: false, psk: false, admin: false };
  private info: TunnelUp = { device: null, address: null };
  private recent: string[] = [];

  constructor(private readonly s: ProcessSpec) {}

  get running(): boolean {
    return !!this.child && !this.child.exited;
  }

  get leftover(): Leftover | null {
    return this.child?.pid ? { kind: 'process', pid: this.child.pid, names: this.s.names } : null;
  }

  start(): Promise<TunnelUp> {
    return new Promise<TunnelUp>((resolve, reject) => {
      let settled = false;
      let timer: NodeJS.Timeout | null = null;
      const fail = (message: string) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        void this.stop().then(() => reject(new Error(message)));
      };
      const arm = () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => fail(`${this.s.dialect.name} did not connect within ${Math.round((this.s.connectTimeoutMs ?? 60_000) / 1000)} seconds${this.lastError ? `: ${this.lastError}` : ''}`), this.s.connectTimeoutMs ?? 60_000);
      };
      this.onWaiting = (waiting) => (waiting ? timer && clearTimeout(timer) : arm());
      this.onUp = () => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        this.info.device ??= deviceFor(this.info.address) ?? this.s.device ?? null;
        resolve({ ...this.info });
      };
      this.onCancel = () => fail('Cancelled');

      let child: VpnProcess;
      try {
        child = this.s.launch ? this.s.launch() : localProcess(this.s.file, this.s.args, this.s.env);
      } catch (e) {
        return fail(`Could not run ${this.s.dialect.name}: ${errorMessage(e)}`);
      }
      this.child = child;
      arm();
      child.onData((d) => this.onData(d));
      // The helper's errors are already worded for the user; a spawn error is not.
      child.onError((e) => fail(this.s.launch ? e.message : `Could not run ${this.s.dialect.name}: ${errorMessage(e)}`));
      child.onExit((code) => {
        if (this.partial.trim()) this.line(this.partial);
        this.partial = '';
        if (this.child === child) this.child = null;
        if (!settled) return fail(this.s.dialect.failure(this.lastError, code));
        if (this.up && !this.stopping) this.s.hooks.dropped(this.lastError ? `${this.s.dialect.name} stopped: ${this.lastError}` : `${this.s.dialect.name} stopped (code ${code})`);
      });
    });
  }

  private onWaiting: (waiting: boolean) => void = () => undefined;
  private onUp: () => void = () => undefined;
  private onCancel: () => void = () => undefined;

  stop(): Promise<void> {
    const child = this.child;
    this.stopping = true;
    if (!child || child.exited) return Promise.resolve();
    return new Promise((resolve) => {
      const hard = setTimeout(() => {
        child.kill(true);
        resolve();
      }, 6000);
      child.onExit(() => {
        clearTimeout(hard);
        resolve();
      });
      child.kill(false, this.s.stopSignal);
    });
  }

  private onData(d: Buffer): void {
    const lines = (this.partial + d.toString()).split(/\r?\n|\r(?!\n)/);
    this.partial = lines.pop() ?? '';
    for (const l of lines) this.line(l);
    if (this.promptTimer) clearTimeout(this.promptTimer);
    // A question has no line break after it: an unfinished line that stays unchanged for a moment is one.
    if (this.partial.trim()) this.promptTimer = setTimeout(() => void this.maybePrompt(), PROMPT_IDLE_MS);
  }

  /** Never let a secret reach the log, even if a program echoes it. */
  private scrub(text: string): string {
    let out = text;
    for (const v of [this.s.secrets.password, this.s.secrets.psk]) if (v && v.length >= 3) out = out.split(v).join('•••');
    return out;
  }

  private line(raw: string): void {
    const text = this.scrub(raw.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '')).trimEnd();
    if (!text.trim()) return;
    this.recent.push(text);
    if (this.recent.length > 30) this.recent.shift();
    const d = this.s.dialect;
    if (d.isError(text)) this.lastError = text.trim();
    if (d.adminRefused?.(text)) this.used.admin = true;
    this.s.hooks.log({ t: Date.now(), level: d.level?.(text) ?? LEVEL.find(([re]) => re.test(text))?.[1] ?? 'info', text });
    const p = d.progress(text);
    if (p?.address) this.info.address = p.address;
    if (p?.device) this.info.device = p.device;
    if (p?.up && !this.up) {
      this.up = true;
      this.onUp();
    }
  }

  private async maybePrompt(): Promise<void> {
    if (this.asking) return;
    const text = this.partial.trim();
    const kind = this.s.dialect.classify(text);
    if (!kind) return;
    this.partial = '';
    this.s.hooks.log({ t: Date.now(), level: 'info', text: this.scrub(text) });
    this.asking = true;
    try {
      const answer = await this.answer(kind, text);
      if (answer === null) return this.onCancel();
      this.child?.write(`${answer}\n`);
    } finally {
      this.asking = false;
    }
  }

  private async answer(kind: PromptClass, text: string): Promise<string | null> {
    const { secrets, hooks } = this.s;
    const ask = async (p: PromptRequest) => {
      this.onWaiting(true);
      try {
        return await hooks.ask(p);
      } finally {
        this.onWaiting(false);
      }
    };
    switch (kind) {
      case 'username':
        return this.s.username;
      case 'password':
      case 'psk': {
        const saved = secrets[kind === 'psk' ? 'psk' : 'password'];
        if (saved && !this.used[kind]) {
          this.used[kind] = true;
          return saved;
        }
        const retry = this.used[kind];
        this.used[kind] = true;
        return ask({ kind, message: text, retry });
      }
      case 'admin': {
        const retry = this.used.admin;
        this.used.admin = true;
        return ask({ kind, message: 'Administrator rights are needed to set up the VPN adapter.', retry });
      }
      case 'cert': {
        const pin = [...this.recent].reverse().map((l) => /(pin-sha256:[A-Za-z0-9+/]{43}=)/.exec(l)?.[1]).find(Boolean);
        const reason = [...this.recent].reverse().find((l) => /^Reason:/i.test(l.trim()))?.trim();
        const v = await ask({ kind, message: reason ? `The gateway's certificate is not trusted (${reason.replace(/^Reason:\s*/i, '')}).` : "The gateway's certificate is not trusted.", detail: pin });
        if (v === null) return null;
        const yes = /^y(es)?$/i.test(v.trim());
        if (yes && pin) hooks.trustCert(pin);
        return yes ? 'yes' : 'no';
      }
      default:
        return ask({ kind, message: text });
    }
  }
}
