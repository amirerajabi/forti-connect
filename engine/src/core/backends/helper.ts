// The engine's side of the Windows VPN helper (helper-script.ts): is it there, install / update / remove it (one UAC
// prompt), and a VpnProcess that runs OpenConnect through it, so ProcessTunnel reads prompts and progress exactly as
// it does from an OpenConnect it started itself.
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import type { HelperInfo } from '../../../../shared/protocol';
import { powershell, run } from '../system';
import { errorMessage } from '../util';
import { HELPER_DIR_NAME, HELPER_PIPE, HELPER_VERSION, installScript, removeScript } from './helper-script';
import type { VpnProcess } from './process';

/**
 * Open the pipe, trying again for a moment while no instance is free (ENOENT in the gap between two clients, EBUSY when
 * all are taken): the helper keeps several waiting, but two clients can still meet in the gap.
 */
function openPipe(pipe: string, attempts = 6): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let tries = 0;
    const attempt = () => {
      const s = net.connect(pipe);
      const onError = (e: NodeJS.ErrnoException) => {
        s.destroy();
        if ((e.code === 'ENOENT' || e.code === 'EBUSY') && ++tries < attempts) setTimeout(attempt, 150);
        else reject(e);
      };
      s.once('error', onError);
      s.once('connect', () => {
        s.off('error', onError);
        resolve(s);
      });
    };
    attempt();
  });
}

function helperDir(): string {
  return path.join(process.env.ProgramFiles ?? 'C:\\Program Files', HELPER_DIR_NAME);
}

/** Ask the helper for its version: null when nobody answers, 'denied' when the pipe exists but is not ours to open. */
export async function helloHelper(pipe = HELPER_PIPE, timeoutMs = 2000): Promise<number | null | 'denied'> {
  let s: net.Socket;
  try {
    s = await openPipe(pipe);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === 'EACCES' || code === 'EPERM' ? 'denied' : null;
  }
  return new Promise((resolve) => {
    let buf = '';
    const done = (v: number | null | 'denied') => {
      clearTimeout(timer);
      s.destroy();
      resolve(v);
    };
    const timer = setTimeout(() => done(null), timeoutMs);
    s.write(`${JSON.stringify({ op: 'hello' })}\n`);
    s.on('data', (d: Buffer) => {
      buf += d.toString();
      const line = buf.split('\n')[0];
      if (!buf.includes('\n')) return;
      try {
        const m = JSON.parse(line) as { t?: string; version?: number };
        done(m.t === 'hello' && typeof m.version === 'number' ? m.version : null);
      } catch {
        done(null);
      }
    });
    s.on('error', () => done(null));
  });
}

export async function detectHelper(pipe = HELPER_PIPE): Promise<HelperInfo> {
  const v = await helloHelper(pipe);
  const files = fs.existsSync(path.join(helperDir(), 'fc-helper.ps1'));
  if (v === 'denied') return { state: 'other-user', version: null, current: HELPER_VERSION };
  if (typeof v === 'number') return { state: v < HELPER_VERSION ? 'outdated' : 'running', version: v, current: HELPER_VERSION };
  return { state: files ? 'stopped' : 'missing', version: null, current: HELPER_VERSION };
}

/** This Windows account's SID, read without elevation (the elevated copy may be another account: over-the-shoulder UAC). */
export async function currentUserSid(): Promise<string> {
  const r = await run('whoami', ['/user', '/fo', 'csv', '/nh'], 10_000);
  const sid = /"(S-1-[0-9-]+)"/.exec(r.out)?.[1];
  if (!sid) throw new Error('Could not read your Windows account id');
  return sid;
}

/**
 * Run a script elevated: Windows shows its UAC prompt, and the call returns when the elevated PowerShell has finished.
 * The script travels as -EncodedCommand. Throws 'Cancelled' when the user said no.
 */
async function runElevated(script: string): Promise<void> {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const outer = `try { $p = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','${encoded}'; exit $p.ExitCode } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1223 }`;
  const r = await powershell(outer, {}, 10 * 60_000);
  if (r.code === 1223) throw new Error(/cancel/i.test(r.err) ? 'Cancelled' : r.err.trim() || 'Could not get administrator rights');
  if (r.code !== 0) {
    let detail = '';
    try {
      detail = fs.readFileSync(path.join(helperDir(), 'work', 'install-error.txt'), 'utf8').trim();
    } catch {
      /* no detail written */
    }
    throw new Error(detail || `The elevated step failed (code ${r.code})`);
  }
}

/** Install or update the helper, then wait for it to answer (the task starts it within a few seconds). */
export async function installHelper(pipe = HELPER_PIPE): Promise<HelperInfo> {
  await runElevated(installScript(await currentUserSid()));
  const until = Date.now() + 30_000;
  let info = await detectHelper(pipe);
  // PowerShell compiles the helper when it starts: give it time.
  while (info.state !== 'running' && Date.now() < until) {
    await new Promise((r) => setTimeout(r, 1000));
    info = await detectHelper(pipe);
  }
  return info;
}

export async function removeHelper(pipe = HELPER_PIPE): Promise<HelperInfo> {
  await runElevated(removeScript());
  return detectHelper(pipe);
}

/** What OpenConnect should do, in the fields the helper checks (it builds the command line itself). */
export interface HelperStart {
  gateway: string;
  port: number;
  realm: string;
  user: string;
  servercert: string;
  verbose: boolean;
  /** A client certificate's bytes, base64: the helper (SYSTEM) must not read files at paths the user chose. */
  cert?: string;
}

/** OpenConnect running in the helper, seen through the pipe. Closing the pipe ends it. */
export function helperProcess(start: HelperStart, pipe = HELPER_PIPE): VpnProcess {
  const events = new EventEmitter();
  let exited = false;
  let stopped = false;
  let buf = '';
  let socket: net.Socket | null = null;
  const send = (m: object) => {
    if (socket && !socket.destroyed) socket.write(`${JSON.stringify(m)}\n`);
  };
  const exit = (code: number | null) => {
    if (exited) return;
    exited = true;
    events.emit('exit', code);
    socket?.destroy();
  };
  const onLine = (line: string) => {
    let m: { t?: string; d?: string; code?: number; message?: string };
    try {
      m = JSON.parse(line);
    } catch {
      return;
    }
    if ((m.t === 'out' || m.t === 'err') && typeof m.d === 'string') events.emit('data', Buffer.from(m.d, 'utf8'));
    else if (m.t === 'exit') exit(typeof m.code === 'number' ? m.code : null);
    else if (m.t === 'error') events.emit('error', new Error(`VPN helper: ${m.message ?? 'refused'}`));
  };
  openPipe(pipe).then(
    (s) => {
      socket = s;
      if (stopped) return void s.destroy();
      s.on('data', (d: Buffer) => {
        buf += d.toString('utf8');
        let i: number;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          onLine(line);
        }
      });
      s.on('error', () => undefined);
      s.on('close', () => exit(null));
      send({ op: 'start', ...start });
    },
    (e: NodeJS.ErrnoException) => {
      const reason =
        e.code === 'ENOENT'
          ? 'The FortiConnect VPN helper is not running'
          : e.code === 'EACCES' || e.code === 'EPERM'
            ? 'The VPN helper was installed for another Windows account: install it again from Settings → VPN programs'
            : errorMessage(e);
      events.emit('error', new Error(reason));
    },
  );
  return {
    pid: undefined,
    get exited() {
      return exited;
    },
    onData: (cb) => void events.on('data', cb),
    onExit: (cb) => void events.on('exit', cb),
    onError: (cb) => void events.on('error', cb),
    write: (text) => send({ op: 'stdin', d: text }),
    kill: () => {
      stopped = true;
      send({ op: 'stop' });
      socket?.end();
      // Never connected: nothing to wait for.
      if (!socket) exit(null);
    },
  };
}
