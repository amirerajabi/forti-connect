// Bytes through the VPN adapter, read from the system once a second: /sys on Linux, netstat on macOS, and on Windows one
// long-running PowerShell that prints .NET's interface statistics (starting PowerShell every second would cost more
// than the reading). Tunnels without an adapter of their own (strongSwan's kernel IPsec on Linux) have no counters.
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import { powershellExe, type Platform } from './system';

export interface Counters {
  rx: number;
  tx: number;
}

/** The byte counters in `netstat -ibn -I <dev>` (macOS): Ibytes and Obytes, counted from the end of the row. */
export function parseNetstat(out: string): Counters | null {
  const row = out.split(/\r?\n/).find((l) => /<Link#\d+>/.test(l));
  if (!row) return null;
  const f = row.trim().split(/\s+/);
  const rx = Number(f[f.length - 5]);
  const tx = Number(f[f.length - 2]);
  return Number.isFinite(rx) && Number.isFinite(tx) ? { rx, tx } : null;
}

const WIN_LOOP = `
$n = $env:FC_DEVICE
while ($true) {
  $i = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.Name -eq $n } | Select-Object -First 1
  if ($i) { $s = $i.GetIPStatistics(); [Console]::Out.WriteLine("$($s.BytesReceived) $($s.BytesSent)") }
  Start-Sleep -Seconds 1
}
`;

export class CounterWatcher {
  private timer: NodeJS.Timeout | null = null;
  private ps: ChildProcess | null = null;

  constructor(private readonly platform: Platform) {}

  start(device: string, onSample: (c: Counters) => void): void {
    this.stop();
    if (this.platform === 'win32') {
      // -EncodedCommand, not the script on stdin: PowerShell quits without running a multi-line script piped to it.
      const ps = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(WIN_LOOP, 'utf16le').toString('base64')], { windowsHide: true, env: { ...process.env, FC_DEVICE: device } });
      this.ps = ps;
      let buf = '';
      ps.stdout.on('data', (d: Buffer) => {
        buf += d.toString();
        const lines = buf.split(/\r?\n/);
        buf = lines.pop() ?? '';
        for (const l of lines) {
          const [rx, tx] = l.trim().split(' ').map(Number);
          if (Number.isFinite(rx) && Number.isFinite(tx)) onSample({ rx, tx });
        }
      });
      ps.on('error', () => undefined);
      return;
    }
    const read = this.platform === 'linux' ? () => readSys(device) : () => readNetstat(device);
    this.timer = setInterval(() => void read().then((c) => c && onSample(c)), 1000);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.ps?.kill();
    this.ps = null;
  }
}

async function readSys(device: string): Promise<Counters | null> {
  try {
    const base = `/sys/class/net/${device}/statistics`;
    const [rx, tx] = await Promise.all([fs.promises.readFile(`${base}/rx_bytes`, 'utf8'), fs.promises.readFile(`${base}/tx_bytes`, 'utf8')]);
    return { rx: Number(rx), tx: Number(tx) };
  } catch {
    return null;
  }
}

function readNetstat(device: string): Promise<Counters | null> {
  return new Promise((resolve) => execFile('netstat', ['-ibn', '-I', device], { timeout: 900 }, (err, out) => resolve(err ? null : parseNetstat(String(out)))));
}
