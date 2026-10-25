// What the engine asks the operating system: administrator rights, where a program is, a program's version output,
// whether a process from an earlier run is still alive, and PowerShell for Windows' own VPN client.
import { execFile, spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export type Platform = 'win32' | 'darwin' | 'linux';

/**
 * A program from Windows' own System32, by full path: a bare name follows the PATH, where another 'whoami' or 'net'
 * (Git's, MSYS2's) may come first and not understand Windows' options.
 */
export function sys32(name: string): string {
  return path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', name);
}

export function powershellExe(): string {
  return sys32(path.join('WindowsPowerShell', 'v1.0', 'powershell.exe'));
}

export function currentPlatform(): Platform {
  return process.platform === 'win32' ? 'win32' : process.platform === 'darwin' ? 'darwin' : 'linux';
}

let elevatedCache: boolean | null = null;

/**
 * Administrator (Windows) or root (macOS / Linux). On Windows "net session" only succeeds in an elevated process; it is
 * the check installers use, and it needs no PowerShell.
 */
export function isElevated(): boolean {
  if (elevatedCache !== null) return elevatedCache;
  if (process.platform === 'win32') {
    const r = spawnSync(sys32('net.exe'), ['session'], { windowsHide: true, stdio: 'ignore', timeout: 5000 });
    elevatedCache = r.status === 0;
  } else {
    elevatedCache = process.getuid?.() === 0;
  }
  return elevatedCache;
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

export function firstFile(candidates: string[]): string | null {
  return candidates.find((c) => c && isFile(c)) ?? null;
}

/** The first of `candidates` that exists, then `name` on the PATH. */
export function findProgram(name: string, candidates: string[]): string | null {
  const found = firstFile(candidates);
  if (found) return found;
  const exts = process.platform === 'win32' ? ['.exe', ''] : [''];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const p = path.join(dir.replace(/^"|"$/g, ''), name + ext);
      if (isFile(p)) return p;
    }
  }
  return null;
}

/** stdout + stderr of a short command, '' when it cannot run. */
export function commandOutput(file: string, args: string[], timeoutMs = 5000): Promise<string> {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, timeout: timeoutMs }, (_err, stdout, stderr) => resolve(`${stdout ?? ''}${stderr ?? ''}`));
  });
}

/** The name of the program running as `pid`, null when there is none. */
export function processName(pid: number): Promise<string | null> {
  if (!Number.isInteger(pid) || pid <= 0) return Promise.resolve(null);
  return new Promise((resolve) => {
    if (process.platform === 'win32') {
      execFile(sys32('tasklist.exe'), ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { windowsHide: true, timeout: 5000 }, (err, out) => {
        const name = /^"([^"]+)"/.exec(String(out ?? '').trim())?.[1];
        resolve(err || !name ? null : name);
      });
    } else {
      execFile('ps', ['-p', String(pid), '-o', 'comm='], { timeout: 5000 }, (err, out) => resolve(err ? null : String(out).trim() || null));
    }
  });
}

/** Run a PowerShell script; values go in through the environment so nothing from a profile is ever parsed as code. */
/**
 * The script goes as -EncodedCommand: PowerShell quits without running a multi-line script piped to its stdin. `oneLine`
 * sends it on stdin instead, for a single-line script too long for a command line (Windows caps those at 32767
 * characters), such as the one carrying the elevated install script.
 */
export function powershell(script: string, env: Record<string, string> = {}, timeoutMs = 30_000, oneLine = false): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    if (oneLine && /[\r\n]/.test(script.trim())) throw new Error('powershell(oneLine): the script has more than one line');
    const how = oneLine ? ['-Command', '-'] : ['-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
    const child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', ...how], {
      windowsHide: true,
      env: { ...process.env, ...env },
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => (out += d.toString()));
    child.stderr.on('data', (d: Buffer) => (err += d.toString()));
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ code: null, out, err: err || e.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(oneLine ? `${script.trim()}\n` : undefined);
  });
}

/** Run a program and collect its output and exit code (rasdial, charon-cmd --version, …). */
export function run(file: string, args: string[], timeoutMs = 60_000): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(file, args, { windowsHide: true });
    let out = '';
    child.stdout.on('data', (d: Buffer) => (out += d.toString()));
    child.stderr.on('data', (d: Buffer) => (out += d.toString()));
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ code: null, out: out || e.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out });
    });
  });
}
