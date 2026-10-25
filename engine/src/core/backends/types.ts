import type { LogLine, PromptKind } from '../../../../shared/protocol';

export interface PromptRequest {
  kind: PromptKind;
  message: string;
  detail?: string;
  /** The same question again: the previous answer was not accepted (so a remembered answer must not be reused). */
  retry?: boolean;
}

/** How a tunnel reports back to the Manager. */
export interface TunnelHooks {
  log(line: LogLine): void;
  /** Put a question to the user; null when they cancelled. */
  ask(p: PromptRequest): Promise<string | null>;
  /** The user trusted the gateway's certificate: remember its pin in the profile. */
  trustCert(pin: string): void;
  /** The tunnel was up and went down without being asked to. */
  dropped(error: string): void;
}

export interface TunnelUp {
  device: string | null;
  address: string | null;
}

/** What a crash can leave behind, kept in runtime.json and cleaned up on the next start. */
export type Leftover = { kind: 'process'; pid: number; names: string[] } | { kind: 'ras'; name: string };

/** One VPN connection being made or up. */
export interface Tunnel {
  /** Resolves once traffic can flow; rejects with a message for the user. */
  start(): Promise<TunnelUp>;
  stop(): Promise<void>;
  readonly running: boolean;
  readonly leftover: Leftover | null;
}
