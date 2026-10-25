// The FortiConnect VPN helper for Windows, as text the engine installs. Windows only lets administrators create the
// adapter and routes OpenConnect needs, so, like FortiClient's own service, a helper runs as SYSTEM (a scheduled task
// started at boot) and FortiConnect runs as a normal user and asks it over a named pipe to start OpenConnect.
//
// Security, because anything this helper runs runs as SYSTEM:
// - It lives in C:\Program Files\FortiConnect Helper, which only administrators can change (a copy the user can write
//   to would hand SYSTEM to any program running as the user).
// - Only the Windows accounts listed in users.txt next to it (plus SYSTEM and administrators) can open the pipe.
// - It builds OpenConnect's command line itself from checked fields; it never takes a path or a raw argument from the
//   client, only runs an OpenConnect installed under Program Files, and uses the vpnc-script shipped next to it.
// - The tunnel ends when the client's connection does, so a VPN nobody controls never stays up.
//
// Written in C# compiled by PowerShell at start (Add-Type): both ship with every Windows 10 / 11, nothing to install.
// Lines on the pipe are JSON. Client → helper: {op:'hello'} | {op:'start', ...} | {op:'stdin', d} | {op:'stop'}.
// Helper → client: {t:'hello', version} | {t:'out'|'err', d} | {t:'exit', code} | {t:'error', message}.

import { gzipSync } from 'node:zlib';

/** Bump when the helper changes: an older one installed on a computer is offered as an update. */
export const HELPER_VERSION = 1;
export const HELPER_PIPE = '\\\\.\\pipe\\forticonnect-helper';
export const HELPER_TASK = 'FortiConnect VPN helper';
export const HELPER_DIR_NAME = 'FortiConnect Helper';

const CSHARP = `
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

public static class FcHelper {
  public const int Version = ${HELPER_VERSION};
  static string pipeName;
  static string workDir;
  static string testCommand;
  static List<SecurityIdentifier> allowed = new List<SecurityIdentifier>();
  static readonly object busy = new object();
  static Process current;

  public static void Run(string pipe, string users, string test, string work) {
    pipeName = pipe;
    testCommand = test;
    workDir = work;
    Directory.CreateDirectory(workDir);
    foreach (string s in users.Split(new[] { ',', ';', ' ', '\\r', '\\n' }, StringSplitOptions.RemoveEmptyEntries)) {
      try { allowed.Add(new SecurityIdentifier(s.Trim())); } catch (Exception e) { Log("bad SID " + s + ": " + e.Message); }
    }
    if (allowed.Count == 0) allowed.Add(WindowsIdentity.GetCurrent().User);
    Log("helper " + Version + " started, pipe " + pipeName);
    // Several pipe instances wait at once: a connection being served (a tunnel can last hours) never leaves the next
    // client without one to open.
    for (int i = 0; i < 4; i++) {
      Thread t = new Thread(Accept);
      t.IsBackground = true;
      t.Start();
    }
    Thread.Sleep(Timeout.Infinite);
  }

  static void Accept() {
    while (true) {
      NamedPipeServerStream server = null;
      try {
        server = Create();
        server.WaitForConnection();
        Serve(server);
      } catch (Exception e) {
        Log("accept: " + e.Message);
        if (server != null) try { server.Dispose(); } catch { }
        Thread.Sleep(1000);
      }
    }
  }

  static NamedPipeServerStream Create() {
    PipeSecurity sec = new PipeSecurity();
    sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
    sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
    foreach (SecurityIdentifier sid in allowed) sec.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
    return new NamedPipeServerStream(pipeName, PipeDirection.InOut, 8, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536, sec);
  }

  static void Log(string text) {
    try {
      string file = Path.Combine(workDir, "helper.log");
      if (File.Exists(file) && new FileInfo(file).Length > 1000000) File.Delete(file);
      File.AppendAllText(file, DateTime.Now.ToString("s") + " " + text + "\\r\\n");
    } catch { }
  }

  class Conn {
    public Stream Pipe;
    readonly object gate = new object();
    readonly JavaScriptSerializer json = new JavaScriptSerializer();
    public void Send(Dictionary<string, object> msg) {
      byte[] bytes = Encoding.UTF8.GetBytes(json.Serialize(msg) + "\\n");
      lock (gate) {
        try { Pipe.Write(bytes, 0, bytes.Length); Pipe.Flush(); } catch { }
      }
    }
    public void Send(string t, string key, object value) {
      Dictionary<string, object> m = new Dictionary<string, object>();
      m["t"] = t;
      if (key != null) m[key] = value;
      Send(m);
    }
  }

  static void Serve(NamedPipeServerStream pipe) {
    Conn conn = new Conn();
    conn.Pipe = pipe;
    Process mine = null;
    string certFile = null;
    JavaScriptSerializer json = new JavaScriptSerializer();
    try {
      StreamReader reader = new StreamReader(pipe, new UTF8Encoding(false));
      string line;
      while ((line = reader.ReadLine()) != null) {
        if (line.Length > 2000000) break;
        Dictionary<string, object> msg;
        try { msg = json.Deserialize<Dictionary<string, object>>(line); } catch { conn.Send("error", "message", "Bad request"); continue; }
        string op = Str(msg, "op");
        if (op == "hello") {
          conn.Send("hello", "version", Version);
        } else if (op == "start") {
          if (mine != null) { conn.Send("error", "message", "Already started"); continue; }
          try {
            mine = Start(msg, conn, out certFile);
          } catch (Exception e) {
            conn.Send("error", "message", e.Message);
            break;
          }
        } else if (op == "stdin") {
          string d = Str(msg, "d");
          if (mine != null && d != null && d.Length < 10000) {
            try { mine.StandardInput.Write(d); mine.StandardInput.Flush(); } catch { }
          }
        } else if (op == "stop") {
          break;
        }
      }
    } catch (Exception e) {
      Log("serve: " + e.Message);
    } finally {
      // The client is gone or asked to stop: end its tunnel.
      if (mine != null) {
        try { if (!mine.HasExited) mine.Kill(); } catch { }
        try { mine.WaitForExit(5000); } catch { }
        lock (busy) { if (current == mine) current = null; }
      }
      if (certFile != null) try { File.Delete(certFile); } catch { }
      try { pipe.Dispose(); } catch { }
    }
  }

  static string Str(Dictionary<string, object> m, string k) {
    object v;
    return m.TryGetValue(k, out v) && v != null ? v.ToString() : null;
  }

  static string Need(string v, string pattern, string what) {
    if (v == null || !Regex.IsMatch(v, pattern)) throw new Exception("Invalid " + what);
    return v;
  }

  static string FindOpenConnect() {
    List<string> dirs = new List<string>();
    foreach (string env in new[] { "ProgramFiles", "ProgramW6432", "ProgramFiles(x86)" }) {
      string d = Environment.GetEnvironmentVariable(env);
      if (!string.IsNullOrEmpty(d) && !dirs.Contains(d)) dirs.Add(d);
    }
    foreach (string d in dirs) {
      foreach (string sub in new[] { "OpenConnect", "OpenConnect-GUI" }) {
        string p = Path.Combine(Path.Combine(d, sub), "openconnect.exe");
        if (File.Exists(p)) return p;
      }
    }
    throw new Exception("OpenConnect is not installed under Program Files (the VPN helper only runs a copy there)");
  }

  static Process Start(Dictionary<string, object> m, Conn conn, out string certFile) {
    certFile = null;
    string gateway = Need(Str(m, "gateway"), @"^([A-Za-z0-9.-]{1,253}|[0-9A-Fa-f:.]{2,45})$", "gateway");
    string portText = Need(Str(m, "port"), @"^[0-9]{1,5}$", "port");
    int port = int.Parse(portText);
    if (port < 1 || port > 65535) throw new Exception("Invalid port");
    string realm = Str(m, "realm") ?? "";
    Need(realm, @"^[A-Za-z0-9._~%!$&'()*+,;=:@/-]{0,200}$", "realm");
    if (realm.Contains("..")) throw new Exception("Invalid realm");
    string user = Str(m, "user") ?? "";
    if (user.Length > 200 || Regex.IsMatch(user, @"[\\x00-\\x1f]")) throw new Exception("Invalid user name");
    string pin = Str(m, "servercert") ?? "";
    if (pin != "") Need(pin, @"^pin-sha256:[A-Za-z0-9+/]{43}=$", "certificate pin");
    bool verbose = Str(m, "verbose") == "True" || Str(m, "verbose") == "true";
    string cert = Str(m, "cert");

    List<string> args = new List<string>();
    string exe;
    if (!string.IsNullOrEmpty(testCommand)) {
      string[] parts = testCommand.Split('|');
      exe = parts[0];
      for (int i = 1; i < parts.Length; i++) args.Add(parts[i]);
    } else {
      exe = FindOpenConnect();
    }
    args.Add("--protocol=fortinet");
    args.Add("--no-proxy");
    if (user != "") { args.Add("--user"); args.Add(user); }
    if (pin != "") { args.Add("--servercert"); args.Add(pin); }
    if (!string.IsNullOrEmpty(cert)) {
      if (cert.Length > 1400000) throw new Exception("The client certificate is too large");
      byte[] data = Convert.FromBase64String(cert);
      certFile = Path.Combine(workDir, "cert-" + Guid.NewGuid().ToString("N") + ".p12");
      File.WriteAllBytes(certFile, data);
      args.Add("--certificate");
      args.Add(certFile);
    }
    args.Add("--interface");
    args.Add("FortiConnect");
    if (verbose) args.Add("--verbose");
    string host = gateway.Contains(":") ? "[" + gateway + "]" : gateway;
    args.Add("https://" + host + ":" + port + (realm != "" ? "/" + realm : ""));

    lock (busy) {
      if (current != null && !current.HasExited) throw new Exception("Another FortiConnect connection is already running through the helper");
      ProcessStartInfo psi = new ProcessStartInfo(exe);
      List<string> quoted = new List<string>();
      foreach (string a in args) quoted.Add(Quote(a));
      psi.Arguments = string.Join(" ", quoted.ToArray());
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      psi.RedirectStandardInput = true;
      psi.RedirectStandardOutput = true;
      psi.RedirectStandardError = true;
      psi.StandardOutputEncoding = Encoding.UTF8;
      psi.StandardErrorEncoding = Encoding.UTF8;
      psi.WorkingDirectory = Path.GetDirectoryName(exe);
      Process p = Process.Start(psi);
      current = p;
      Log("started " + exe + " for " + gateway + ":" + port);
      Thread o = Pump(p.StandardOutput, "out", conn);
      Thread e = Pump(p.StandardError, "err", conn);
      Thread w = new Thread(() => {
        p.WaitForExit();
        o.Join(3000);
        e.Join(3000);
        Log("exited " + p.ExitCode);
        conn.Send("exit", "code", p.ExitCode);
      });
      w.IsBackground = true;
      w.Start();
      return p;
    }
  }

  static Thread Pump(StreamReader r, string tag, Conn conn) {
    Thread t = new Thread(() => {
      char[] buf = new char[4096];
      int n;
      try {
        while ((n = r.Read(buf, 0, buf.Length)) > 0) conn.Send(tag, "d", new string(buf, 0, n));
      } catch { }
    });
    t.IsBackground = true;
    t.Start();
    return t;
  }

  /** One argument for the Windows command line (the rules CommandLineToArgvW and the C runtime read it by). */
  static string Quote(string a) {
    if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\\t', '"' }) < 0) return a;
    StringBuilder sb = new StringBuilder("\\"");
    int slashes = 0;
    foreach (char c in a) {
      if (c == '\\\\') { slashes++; continue; }
      if (c == '"') { sb.Append('\\\\', slashes * 2 + 1); sb.Append('"'); }
      else { sb.Append('\\\\', slashes); sb.Append(c); }
      slashes = 0;
    }
    sb.Append('\\\\', slashes * 2);
    sb.Append('"');
    return sb.ToString();
  }
}
`;

/** The helper itself: fc-helper.ps1. users.txt beside it lists the Windows accounts (SIDs) allowed to use it. */
export const HELPER_PS1 = `param([string]$PipeName = 'forticonnect-helper', [string]$TestCommand = '', [string]$WorkDir = '')
$ErrorActionPreference = 'Stop'
if (-not $WorkDir) { $WorkDir = Join-Path $PSScriptRoot 'work' }
$usersFile = Join-Path $PSScriptRoot 'users.txt'
$users = ''
if (Test-Path $usersFile) { $users = Get-Content $usersFile -Raw }
Add-Type -ReferencedAssemblies System.Core, System.Web.Extensions -TypeDefinition @'
${CSHARP}
'@
[FcHelper]::Run($PipeName, $users, $TestCommand, $WorkDir)
`;

/**
 * What runs elevated (one UAC prompt) to install or update the helper: copy it to Program Files, add the user to
 * users.txt, and (re)register the SYSTEM task that starts it at boot. Sent as -EncodedCommand, not as a file, so nothing
 * on disk can be swapped between the user's consent and the copy. Errors land in work\install-error.txt.
 */
export function installScript(userSid: string): string {
  if (!/^S-1-[0-9-]+$/.test(userSid)) throw new Error('Could not read your Windows account id');
  // Gzipped: the whole script travels as -EncodedCommand, and Windows caps a command line at 32767 characters.
  const b64 = gzipSync(Buffer.from(HELPER_PS1, 'utf8'), { level: 9 }).toString('base64');
  return `$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:ProgramFiles '${HELPER_DIR_NAME}'
$work = Join-Path $dir 'work'
try {
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  Remove-Item (Join-Path $work 'install-error.txt') -ErrorAction SilentlyContinue
  $name = '${HELPER_TASK}'
  Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -like '*fc-helper.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  $script = Join-Path $dir 'fc-helper.ps1'
  $gz = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String('${b64}'))), [IO.Compression.CompressionMode]::Decompress)
  $text = (New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)).ReadToEnd()
  [IO.File]::WriteAllText($script, $text, (New-Object Text.UTF8Encoding $true))
  $usersFile = Join-Path $dir 'users.txt'
  $users = @()
  if (Test-Path $usersFile) { $users = @(Get-Content $usersFile | Where-Object { $_ -match '^S-1-[0-9-]+$' }) }
  if ($users -notcontains '${userSid}') { $users += '${userSid}' }
  Set-Content -Path $usersFile -Value $users -Encoding ASCII
  $ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  $action = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script + '"')
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Start-ScheduledTask -TaskName $name
  exit 0
} catch {
  try { Set-Content -Path (Join-Path $work 'install-error.txt') -Value $_.Exception.Message } catch { }
  exit 1
}
`;
}

/** Undo installScript: stop and unregister the task, end the helper, delete its folder. */
export function removeScript(): string {
  return `$ErrorActionPreference = 'SilentlyContinue'
$name = '${HELPER_TASK}'
Stop-ScheduledTask -TaskName $name
Unregister-ScheduledTask -TaskName $name -Confirm:$false
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -like '*fc-helper.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Milliseconds 500
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles '${HELPER_DIR_NAME}')
exit 0
`;
}
