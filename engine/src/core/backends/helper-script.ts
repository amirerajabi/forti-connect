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
// For FortiConnect's own IPsec engine: {op:'tun', address, netmask, dns, gateway, split, mtu} makes the helper open its
// "FortiConnect IPsec" Wintun adapter and set its address, DNS and routes; it answers {t:'tun-ready', index}, and from then on both
// sides send IP packets as frames (two bytes of length, big-endian, then the packet) until the client closes the pipe.
// The client sends no frame before tun-ready, so nothing binary is ever read as a line.

import { gzipSync } from 'node:zlib';

/** Bump when the helper changes: an older one installed on a computer is offered as an update. */
export const HELPER_VERSION = 5;
export const HELPER_PIPE = '\\\\.\\pipe\\forticonnect-helper';
export const HELPER_TASK = 'FortiConnect VPN helper';
export const HELPER_DIR_NAME = 'FortiConnect Helper';

const CSHARP = `
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
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
  static string home;
  static string testCommand;
  static List<SecurityIdentifier> allowed = new List<SecurityIdentifier>();
  static readonly object busy = new object();
  static Process current;
  static bool tunActive;

  public static void Run(string pipe, string users, string test, string work, string helperHome) {
    home = helperHome;
    pipeName = pipe;
    testCommand = test;
    workDir = work;
    Directory.CreateDirectory(workDir);
    foreach (string s in users.Split(new[] { ',', ';', ' ', '\\r', '\\n' }, StringSplitOptions.RemoveEmptyEntries)) {
      try { allowed.Add(new SecurityIdentifier(s.Trim())); } catch (Exception e) { Log("bad SID " + s + ": " + e.Message); }
    }
    if (allowed.Count == 0) allowed.Add(WindowsIdentity.GetCurrent().User);
    // A process started with Ctrl+C ignored passes that on to every program it starts, and OpenConnect would then
    // never hear the Ctrl+C that ends it cleanly (see End). Whoever started the helper may have set it: clear it.
    SetConsoleCtrlHandler(IntPtr.Zero, false);
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
    /** One IP packet as a frame: two bytes of length, then the packet. */
    public bool Frame(byte[] packet, int length) {
      lock (gate) {
        try {
          Pipe.Write(new byte[] { (byte)(length >> 8), (byte)length }, 0, 2);
          Pipe.Write(packet, 0, length);
          Pipe.Flush();
          return true;
        } catch { return false; }
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
        } else if (op == "tun") {
          if (mine != null) { conn.Send("error", "message", "Already started"); continue; }
          try {
            RunTun(msg, conn, pipe);
          } catch (Exception e) {
            Log("tun: " + e.Message);
            conn.Send("error", "message", e.Message);
          }
          break;
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
        End(mine);
        lock (busy) { if (current == mine) current = null; }
      }
      if (certFile != null) try { File.Delete(certFile); } catch { }
      try { pipe.Dispose(); } catch { }
    }
  }

  [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GenerateConsoleCtrlEvent(uint ctrlEvent, uint group);

  // Ctrl+C first: OpenConnect then logs out, runs its script's "disconnect" (removing the gateway route) and deletes
  // its Wintun adapter. Killed outright it leaves that adapter half-removed, and the next OpenConnect fails to open it
  // ("Could not open Wintun adapter"): every connect after a disconnect needed a second try. Killed only if Ctrl+C does
  // not end it in time (a logout to a gateway that cannot be reached).
  static void End(Process p) {
    try { if (p.HasExited) return; } catch { return; }
    bool interrupted = false;
    // The helper has one console at a time, and a program started while it ignores Ctrl+C would inherit that: hold
    // the same lock Start does.
    lock (busy) {
      try {
        FreeConsole();
        if (AttachConsole((uint)p.Id)) {
          SetConsoleCtrlHandler(IntPtr.Zero, true);
          interrupted = GenerateConsoleCtrlEvent(0, 0);
          // The event reaches every process on that console, the helper too: keep ignoring it until it has passed.
          Thread.Sleep(300);
          FreeConsole();
          SetConsoleCtrlHandler(IntPtr.Zero, false);
        }
      } catch (Exception e) { Log("ctrl+c: " + e.Message); }
    }
    bool ended = false;
    try { ended = interrupted && p.WaitForExit(8000); } catch { }
    if (!ended) {
      Log(interrupted ? "did not end after Ctrl+C, killing it" : "could not send Ctrl+C, killing it");
      try { if (!p.HasExited) p.Kill(); } catch { }
      try { p.WaitForExit(5000); } catch { }
    }
  }

  // ---------------------------------------------------------------- the adapter for FortiConnect's own IPsec engine

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr LoadLibraryW(string path);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
  [DllImport("iphlpapi.dll")] static extern int ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);
  [DllImport("wintun.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr WintunCreateAdapter(string name, string tunnelType, IntPtr guid);
  [DllImport("wintun.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr WintunOpenAdapter(string name);
  [DllImport("wintun.dll")] static extern void WintunCloseAdapter(IntPtr adapter);
  [DllImport("wintun.dll")] static extern void WintunGetAdapterLUID(IntPtr adapter, out ulong luid);
  [DllImport("wintun.dll", SetLastError = true)] static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);
  [DllImport("wintun.dll")] static extern void WintunEndSession(IntPtr session);
  [DllImport("wintun.dll")] static extern IntPtr WintunGetReadWaitEvent(IntPtr session);
  [DllImport("wintun.dll", SetLastError = true)] static extern IntPtr WintunReceivePacket(IntPtr session, out uint size);
  [DllImport("wintun.dll")] static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);
  [DllImport("wintun.dll", SetLastError = true)] static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint size);
  [DllImport("wintun.dll")] static extern void WintunSendPacket(IntPtr session, IntPtr packet);

  const string IPV4 = @"^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$";

  static string MaskOf(int len) {
    uint m = len == 0 ? 0 : 0xffffffffu << (32 - len);
    return (m >> 24) + "." + ((m >> 16) & 255) + "." + ((m >> 8) & 255) + "." + (m & 255);
  }

  static bool ReadFull(Stream s, byte[] buf, int len) {
    int got = 0;
    while (got < len) {
      int n = s.Read(buf, got, len - got);
      if (n <= 0) return false;
      got += n;
    }
    return true;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct ForwardRow { public uint Dest, Mask, Policy, NextHop, IfIndex, Type, Proto, Age, NextHopAS, Metric1, Metric2, Metric3, Metric4, Metric5; }
  [DllImport("iphlpapi.dll")] static extern int GetBestRoute(uint dest, uint source, out ForwardRow row);

  static uint ToAddr(string ip) { return BitConverter.ToUInt32(System.Net.IPAddress.Parse(ip).GetAddressBytes(), 0); }
  static string FromAddr(uint a) { return new System.Net.IPAddress(BitConverter.GetBytes(a)).ToString(); }

  /** netsh by full path, arguments built only from checked values. A failure is logged, the setup goes on. */
  static bool Netsh(string args) {
    ProcessStartInfo psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"), args);
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    using (Process p = Process.Start(psi)) {
      string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
      if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return false; }
      if (p.ExitCode != 0) Log("netsh " + args + " -> " + p.ExitCode + ": " + output.Trim());
      return p.ExitCode == 0;
    }
  }

  class TunConfig {
    public uint Index;
    public string Address;
    public string Netmask;
    public string Gateway;
    public string GatewayNextHop;
    public uint GatewayIf;
    public int Mtu;
    public List<string> Dns = new List<string>();
    /** Networks through the tunnel: address and prefix length. */
    public List<string[]> Routes = new List<string[]>();
  }

  /**
   * The adapter's address, MTU, priority and DNS, a route to the gateway through the network it is reached by now (so
   * the encrypted packets themselves do not loop into the tunnel), and the tunnel's networks. "All traffic" is two
   * halves, 0.0.0.0/1 and 128.0.0.0/1: more specific than any default route, whatever its metric.
   */
  static void Configure(TunConfig c) {
    ForwardRow best;
    if (GetBestRoute(ToAddr(c.Gateway), 0, out best) == 0 && best.NextHop != 0 && best.IfIndex != c.Index) {
      c.GatewayNextHop = FromAddr(best.NextHop);
      c.GatewayIf = best.IfIndex;
      Netsh("interface ipv4 add route prefix=" + c.Gateway + "/32 interface=" + c.GatewayIf + " nexthop=" + c.GatewayNextHop + " metric=1 store=active");
    }
    Netsh("interface ipv4 set address name=" + c.Index + " source=static address=" + c.Address + " mask=" + c.Netmask);
    Netsh("interface ipv4 set subinterface " + c.Index + " mtu=" + c.Mtu + " store=active");
    Netsh("interface ipv4 set interface " + c.Index + " metric=1 store=active");
    if (c.Dns.Count > 0) {
      Netsh("interface ipv4 set dnsservers name=" + c.Index + " source=static address=" + c.Dns[0] + " register=none validate=no");
      for (int i = 1; i < c.Dns.Count; i++) Netsh("interface ipv4 add dnsservers name=" + c.Index + " address=" + c.Dns[i] + " index=" + (i + 1) + " validate=no");
    }
    foreach (string[] r in c.Routes) Netsh("interface ipv4 add route prefix=" + r[0] + "/" + r[1] + " interface=" + c.Index + " nexthop=0.0.0.0 metric=1 store=active");
  }

  /** Everything Configure did, undone; the adapter itself stays for the next connection. */
  static void Unconfigure(TunConfig c) {
    foreach (string[] r in c.Routes) Netsh("interface ipv4 delete route prefix=" + r[0] + "/" + r[1] + " interface=" + c.Index + " nexthop=0.0.0.0 store=active");
    if (c.GatewayNextHop != null) Netsh("interface ipv4 delete route prefix=" + c.Gateway + "/32 interface=" + c.GatewayIf + " nexthop=" + c.GatewayNextHop + " store=active");
    Netsh("interface ipv4 set dnsservers name=" + c.Index + " source=static address=none validate=no");
    Netsh("interface ipv4 delete address name=" + c.Index + " address=" + c.Address);
  }

  /**
   * The adapter, created once and kept while the helper runs: creating it again right after Windows removed the last
   * one can take a long time or fail. Its own name, so OpenConnect's "FortiConnect" adapter for SSL-VPN never meets it.
   */
  static IntPtr ipsecAdapter = IntPtr.Zero;
  static uint ipsecIndex;

  static void OpenAdapter() {
    if (ipsecAdapter != IntPtr.Zero) return;
    string dir = Path.Combine(home ?? "", "openconnect");
    if (LoadLibraryW(Path.Combine(dir, "wintun.dll")) == IntPtr.Zero) throw new Exception("wintun.dll could not be loaded from " + dir);
    IntPtr a = WintunOpenAdapter("FortiConnect IPsec");
    if (a == IntPtr.Zero) a = WintunCreateAdapter("FortiConnect IPsec", "FortiConnect", IntPtr.Zero);
    if (a == IntPtr.Zero) throw new Exception("Could not create the VPN adapter (error " + Marshal.GetLastWin32Error() + ")");
    ulong luid;
    WintunGetAdapterLUID(a, out luid);
    ConvertInterfaceLuidToIndex(ref luid, out ipsecIndex);
    ipsecAdapter = a;
  }

  /**
   * Open the IPsec adapter, give it the address, routes and DNS the gateway handed out, and carry packets between it and
   * the client until the client closes the pipe; then undo the setup. Every field is checked: nothing from the client
   * reaches a command line unchecked.
   */
  static void RunTun(Dictionary<string, object> m, Conn conn, Stream pipe) {
    TunConfig c = new TunConfig();
    c.Address = Need(Str(m, "address"), IPV4, "address");
    c.Netmask = Str(m, "netmask");
    if (string.IsNullOrEmpty(c.Netmask)) c.Netmask = "255.255.255.255";
    Need(c.Netmask, IPV4, "netmask");
    c.Gateway = Need(Str(m, "gateway"), IPV4, "gateway");
    foreach (string d in (Str(m, "dns") ?? "").Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) c.Dns.Add(Need(d, IPV4, "DNS server"));
    if (c.Dns.Count > 4) throw new Exception("Too many DNS servers");
    foreach (string net in (Str(m, "split") ?? "").Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) {
      string[] parts = net.Split('/');
      if (parts.Length != 2) throw new Exception("Invalid network");
      Need(parts[0], IPV4, "network");
      int len = int.Parse(Need(parts[1], @"^[0-9]{1,2}$", "prefix length"));
      if (len > 32) throw new Exception("Invalid prefix length");
      c.Routes.Add(new[] { parts[0], len.ToString() });
    }
    if (c.Routes.Count > 100) throw new Exception("Too many networks");
    if (c.Routes.Count == 0) {
      c.Routes.Add(new[] { "0.0.0.0", "1" });
      c.Routes.Add(new[] { "128.0.0.0", "1" });
    }
    c.Mtu = int.Parse(Need(Str(m, "mtu") ?? "1400", @"^[0-9]{3,4}$", "MTU"));
    if (c.Mtu < 576 || c.Mtu > 1500) throw new Exception("Invalid MTU");
    // Test mode: no adapter and no setup, packets come straight back.
    bool echo = testCommand == "tun-echo";

    lock (busy) {
      if (tunActive || (current != null && !current.HasExited)) throw new Exception("Another FortiConnect connection is already running through the helper");
      tunActive = true;
    }
    IntPtr session = IntPtr.Zero;
    bool configured = false;
    bool stop = false;
    Thread fromAdapter = null;
    try {
      if (!echo) {
        OpenAdapter();
        c.Index = ipsecIndex;
        session = WintunStartSession(ipsecAdapter, 0x400000);
        if (session == IntPtr.Zero) throw new Exception("Could not start the VPN adapter (error " + Marshal.GetLastWin32Error() + ")");
        configured = true;
        Configure(c);
        IntPtr readEvent = WintunGetReadWaitEvent(session);
        IntPtr sess = session;
        fromAdapter = new Thread(() => {
          while (!stop) {
            uint size;
            IntPtr p = WintunReceivePacket(sess, out size);
            if (p == IntPtr.Zero) {
              int err = Marshal.GetLastWin32Error();
              if (err == 259) { WaitForSingleObject(readEvent, 250); continue; }
              Log("adapter read ended (" + err + ")");
              break;
            }
            byte[] b = new byte[size];
            Marshal.Copy(p, b, 0, (int)size);
            WintunReleaseReceivePacket(sess, p);
            if (!conn.Frame(b, (int)size)) break;
          }
        });
        fromAdapter.IsBackground = true;
        fromAdapter.Start();
      }
      Log("tun up: " + c.Address + " on interface " + c.Index + ", routes " + c.Routes.Count + (c.GatewayNextHop != null ? ", gateway via " + c.GatewayNextHop : ""));
      conn.Send("tun-ready", "index", (int)c.Index);
      byte[] head = new byte[2];
      byte[] packet = new byte[65535];
      while (ReadFull(pipe, head, 2)) {
        int len = (head[0] << 8) | head[1];
        if (len == 0 || !ReadFull(pipe, packet, len)) break;
        if (echo) { if (!conn.Frame(packet, len)) break; continue; }
        IntPtr p = WintunAllocateSendPacket(session, (uint)len);
        if (p == IntPtr.Zero) continue;
        Marshal.Copy(packet, 0, p, len);
        WintunSendPacket(session, p);
      }
    } finally {
      stop = true;
      if (fromAdapter != null) fromAdapter.Join(2000);
      if (configured) { try { Unconfigure(c); } catch (Exception e) { Log("unconfigure: " + e.Message); } }
      if (session != IntPtr.Zero) WintunEndSession(session);
      lock (busy) { tunActive = false; }
      Log("tun down");
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
    // The copy FortiConnect ships, put next to the helper when it was installed (as admin-only as the helper itself).
    if (!string.IsNullOrEmpty(home)) {
      string own = Path.Combine(Path.Combine(home, "openconnect"), "openconnect.exe");
      if (File.Exists(own)) return own;
    }
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
    throw new Exception("OpenConnect was not found: neither the copy FortiConnect ships nor one under Program Files");
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
      if (tunActive || (current != null && !current.HasExited)) throw new Exception("Another FortiConnect connection is already running through the helper");
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

/**
 * The C# as it is installed: without comment lines and indentation. The install script carries it inside a command
 * line, which Windows caps at 32767 characters; the comments stay here in the source. Only whole comment lines go, so
 * nothing inside a string (like "//nologo") is touched.
 */
function compact(source: string): string {
  return source
    .replace(/^\s*\/\*\*[\s\S]*?\*\/\s*$/gm, '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('//'))
    .join('\n');
}

/** The helper itself: fc-helper.ps1. users.txt beside it lists the Windows accounts (SIDs) allowed to use it. */
export const HELPER_PS1 = `param([string]$PipeName = 'forticonnect-helper', [string]$TestCommand = '', [string]$WorkDir = '')
$ErrorActionPreference = 'Stop'
if (-not $WorkDir) { $WorkDir = Join-Path $PSScriptRoot 'work' }
$usersFile = Join-Path $PSScriptRoot 'users.txt'
$users = ''
if (Test-Path $usersFile) { $users = Get-Content $usersFile -Raw }
Add-Type -ReferencedAssemblies System.Core, System.Web.Extensions -TypeDefinition @'
${compact(CSHARP)}
'@
[FcHelper]::Run($PipeName, $users, $TestCommand, $WorkDir, $PSScriptRoot)
`;

/**
 * What runs elevated (one UAC prompt) to install or update the helper: copy it to Program Files, add the user to
 * users.txt, and (re)register the SYSTEM task that starts it at boot. Sent as -EncodedCommand, not as a file, so nothing
 * on disk can be swapped between the user's consent and the copy. Errors land in work\install-error.txt.
 */
export function installScript(userSid: string, bundledOpenConnect: string | null = null): string {
  if (!/^S-1-[0-9-]+$/.test(userSid)) throw new Error('Could not read your Windows account id');
  if (bundledOpenConnect !== null && !/^[^'"`$\r\n]+$/.test(bundledOpenConnect)) throw new Error('Unusual characters in the OpenConnect folder path');
  // The OpenConnect FortiConnect ships: copied next to the helper, where only administrators can change it.
  const copyOpenConnect = bundledOpenConnect
    ? `  $from = '${bundledOpenConnect}'
  if (Test-Path (Join-Path $from 'openconnect.exe')) {
    $oc = Join-Path $dir 'openconnect'
    if (Test-Path $oc) { Remove-Item -Recurse -Force $oc }
    New-Item -ItemType Directory -Force -Path $oc | Out-Null
    Get-ChildItem -Path $from -File | Where-Object { $_.Extension -in '.exe', '.dll', '.js', '.txt' } | Copy-Item -Destination $oc
  }
`
    : '';
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
${copyOpenConnect}  $ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
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
