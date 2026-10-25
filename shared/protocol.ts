/**
 * Wire types shared by the engine, the UI and the desktop shell (types only, imported with `import type`).
 * The engine owns all state; the UI reads GET /api/state once and then follows the events on /ws.
 * Secrets (passwords, pre-shared keys) never leave the engine: profiles only say whether one is saved.
 */

/** SSL-VPN (FortiGate's tunnel over TLS, via OpenConnect) or IPsec (IKE, via the OS or strongSwan). */
export type VpnType = 'ssl' | 'ipsec';

/**
 * How an IPsec profile talks to the FortiGate:
 * - ikev1: IKEv1 with a pre-shared key and XAuth (FortiGate's dial-up default; strongSwan on macOS / Linux).
 * - ikev2: IKEv2 with EAP user name and password (Windows' own client, or strongSwan).
 * - l2tp: L2TP over IPsec with a pre-shared key (Windows' own client).
 */
export type IkeMode = 'ikev1' | 'ikev2' | 'l2tp';

/** Everything needed to reach one FortiGate, without the secrets. */
export interface ProfileConfig {
  type: VpnType;
  /** Host name or IP address of the FortiGate. */
  gateway: string;
  /** SSL-VPN port (443, 10443, …). IPsec always uses 500 / 4500 and ignores it. */
  port: number;
  username: string;

  // ---- SSL-VPN
  /** FortiGate realm (the part after the address in https://vpn.example.com/realm). */
  realm?: string;
  /** The server certificate the user chose to trust: "pin-sha256:<base64>" (OpenConnect's --servercert). */
  trustedCert?: string;
  /** A client certificate file (PEM or PKCS#12) for gateways that ask for one. */
  clientCert?: string;

  // ---- IPsec
  ike?: IkeMode;
  /** IKEv1 aggressive mode (FortiGate's default for dial-up with a peer ID). */
  aggressive?: boolean;
  /** IKEv1 local ID / peer ID the FortiGate matches the dial-up tunnel on. */
  localId?: string;
  /**
   * Networks to send through the tunnel ("10.0.0.0/8"); empty sends everything. SSL-VPN always uses the routes the
   * FortiGate pushes, so this is IPsec only.
   */
  routes?: string[];
}

export interface Profile extends ProfileConfig {
  id: string;
  name: string;
  /** Keep the password (encrypted) so connecting does not ask for it. */
  savePassword: boolean;
  hasPassword: boolean;
  /** IPsec pre-shared key saved (ikev1 / l2tp need one). */
  hasPsk: boolean;
  /** Last gateway check in ms (TLS handshake for SSL-VPN, DNS lookup for IPsec), -1 failed, null never checked. */
  delay: number | null;
  addedAt: number;
  lastConnectedAt: number | null;
}

/** What the add / edit dialog sends. Secrets: a string sets it, '' clears it, undefined keeps what is saved. */
export interface ProfileInput extends ProfileConfig {
  name: string;
  savePassword: boolean;
  password?: string;
  psk?: string;
}

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'disconnecting';

/**
 * A question the VPN backend asked while connecting, put to the user. The connection waits until it is answered
 * (POST /api/connect/answer) or cancelled (POST /api/disconnect).
 * - password: the VPN password (when it is not saved, or the saved one was refused)
 * - otp: a FortiToken / e-mail / SMS code
 * - psk: the IPsec pre-shared key (when it is not saved)
 * - cert: the gateway's certificate is not trusted; `detail` holds its pin, the answer is "yes" or "no"
 * - admin: the computer's own password, for administrator rights (sudo on macOS and Linux)
 * - text: anything else the gateway asks
 */
export type PromptKind = 'password' | 'otp' | 'psk' | 'cert' | 'admin' | 'text';

export interface Prompt {
  id: string;
  kind: PromptKind;
  /** The backend's own words (English). */
  message: string;
  detail?: string;
}

export interface ConnectionState {
  status: ConnectionStatus;
  profileId: string | null;
  /** When the current connection came up (ms). */
  since: number | null;
  /** The address the FortiGate gave this computer inside the VPN. */
  address: string | null;
  /** The network adapter the tunnel uses (tun0, utun4, "FortiConnect"). */
  device: string | null;
  prompt: Prompt | null;
  /** Why the last connect failed or the tunnel dropped. */
  error?: string;
  /** Reconnecting after the tunnel dropped: which attempt (1-based). */
  retry?: number;
}

export interface Traffic {
  /** Bytes per second through the VPN adapter. */
  up: number;
  down: number;
  /** Bytes since connecting. */
  totalUp: number;
  totalDown: number;
}

/** A program FortiConnect connects with. */
export interface BackendInfo {
  /** Usable on this computer right now. */
  available: boolean;
  /** openconnect: OpenConnect; charon: strongSwan's charon-cmd; ras: Windows' own VPN client (nothing to install). */
  kind: 'openconnect' | 'charon' | 'ras';
  path: string | null;
  version: string | null;
  /** Why it is not available, or what is limited (English). */
  note?: string;
  /** IPsec modes this backend can do. */
  modes?: IkeMode[];
}

export interface Backends {
  ssl: BackendInfo;
  ipsec: BackendInfo;
  /** The engine runs with administrator / root rights (SSL-VPN on Windows needs them). */
  elevated: boolean;
  platform: 'win32' | 'darwin' | 'linux';
}

export type ThemePref = 'system' | 'light' | 'dark';
export type LogLevel = 'normal' | 'verbose';
export type Language = 'en' | 'fa';

export interface Settings {
  /** A user-chosen OpenConnect executable; '' finds one automatically. */
  openconnectPath: string;
  /** A user-chosen charon-cmd executable (macOS / Linux); '' finds one automatically. */
  charonPath: string;
  /** The vpnc-script OpenConnect sets up addresses and routes with; '' uses the one found next to it or its default. */
  vpncScript: string;
  /** Connect again (up to 5 times) when the tunnel drops; a code the gateway asks for is asked again. */
  reconnect: boolean;
  logLevel: LogLevel;
  /** Connect to the last profile when the app starts. */
  autoConnect: boolean;
  theme: ThemePref;
  /** UI language; Persian also turns the layout right-to-left. */
  language: Language;
  minimizeToTray: boolean;
  launchAtLogin: boolean;
  autoUpdate: boolean;
}

export interface LogLine {
  t: number;
  level: 'info' | 'warning' | 'error' | 'app';
  text: string;
}

export interface EngineState {
  version: string;
  settings: Settings;
  profiles: Profile[];
  /** The profile Connect uses. */
  selectedId: string | null;
  connection: ConnectionState;
  traffic: Traffic;
  backends: Backends;
  logs: LogLine[];
  testing: boolean;
}

export type EngineEvent =
  | { type: 'profiles'; profiles: Profile[]; selectedId: string | null }
  | { type: 'settings'; settings: Settings }
  | { type: 'connection'; connection: ConnectionState }
  | { type: 'traffic'; traffic: Traffic }
  | { type: 'backends'; backends: Backends }
  | { type: 'log'; lines: LogLine[] }
  | { type: 'delay'; results: { id: string; delay: number }[] }
  | { type: 'testing'; testing: boolean }
  | { type: 'notify'; level: 'info' | 'success' | 'warning' | 'error'; text: string; detail?: string };

export interface ImportResult {
  added: number;
  /** Already in the list. */
  duplicates: number;
  /** Lines that were not a forticonnect:// link. */
  skipped: number;
}

/** The result of checking a gateway (Profiles → Check gateway). */
export interface GatewayCheck {
  ok: boolean;
  /** TLS handshake time (SSL-VPN) or DNS lookup time (IPsec), ms. */
  ms: number;
  /** SSL-VPN: the certificate's pin, its subject, and whether the system's CAs trust it. */
  certPin?: string;
  certSubject?: string;
  certTrusted?: boolean;
  /** The answer looked like a FortiGate SSL-VPN portal. */
  fortigate?: boolean;
  error?: string;
}

/** In-app updates (desktop shell, electron-updater). */
export type UpdateMode = 'install' | 'notify' | 'disabled';
export type UpdateState = 'idle' | 'checking' | 'up-to-date' | 'available' | 'downloading' | 'ready' | 'error' | 'disabled';

export interface UpdateStatus {
  state: UpdateState;
  mode: UpdateMode;
  currentVersion: string;
  version?: string;
  percent?: number;
  releaseUrl?: string;
  message?: string;
}
