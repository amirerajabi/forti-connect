// Saved passwords and pre-shared keys, encrypted with AES-256-GCM. The key comes from the desktop shell, which keeps it
// in the OS keychain (Electron safeStorage) and hands it over as FORTICONNECT_SECRET_KEY; without it (browser
// development, Linux without a keyring) a random key in <data>/secret.key is used, which only keeps the secrets out of
// plain sight. Secrets never leave the engine: the API only tells whether one is saved.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { atomicWrite, readJson } from './util';

export interface ProfileSecrets {
  password?: string;
  psk?: string;
}

interface Sealed {
  iv: string;
  tag: string;
  data: string;
}

interface SecretsFile {
  v: 1;
  items: Record<string, Sealed>;
}

/** The 32-byte key: from the environment (hex or base64), else from <data>/secret.key, created on first use. */
export function secretKey(dataDir: string, env = process.env.FORTICONNECT_SECRET_KEY): Buffer {
  if (env) {
    const k = /^[0-9a-f]{64}$/i.test(env) ? Buffer.from(env, 'hex') : Buffer.from(env, 'base64');
    if (k.length === 32) return k;
  }
  const file = path.join(dataDir, 'secret.key');
  try {
    const k = fs.readFileSync(file);
    if (k.length === 32) return k;
  } catch {
    /* first run */
  }
  const k = randomBytes(32);
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(file, k, { mode: 0o600 });
  return k;
}

export function seal(key: Buffer, value: ProfileSecrets): Sealed {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final()]);
  return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
}

/** null when the key does not fit (the keychain was reset, the file was copied from another computer). */
export function unseal(key: Buffer, s: Sealed): ProfileSecrets | null {
  try {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(s.iv, 'base64'));
    d.setAuthTag(Buffer.from(s.tag, 'base64'));
    const json = Buffer.concat([d.update(Buffer.from(s.data, 'base64')), d.final()]).toString('utf8');
    const v = JSON.parse(json) as ProfileSecrets;
    return { password: typeof v.password === 'string' ? v.password : undefined, psk: typeof v.psk === 'string' ? v.psk : undefined };
  } catch {
    return null;
  }
}

export class SecretStore {
  private items = new Map<string, ProfileSecrets>();
  private saving: Promise<void> = Promise.resolve();
  /** Entries the key could not open, reported once by the Manager. */
  unreadable = 0;

  constructor(private readonly file: string, private readonly key: Buffer) {}

  load(): void {
    const f = readJson<SecretsFile>(this.file);
    this.items.clear();
    this.unreadable = 0;
    for (const [id, sealed] of Object.entries(f?.items ?? {})) {
      const v = unseal(this.key, sealed);
      if (v) this.items.set(id, v);
      else this.unreadable++;
    }
  }

  get(id: string): ProfileSecrets {
    return { ...this.items.get(id) };
  }

  /** A string sets the secret, '' or null clears it, undefined keeps it. */
  set(id: string, patch: { password?: string | null; psk?: string | null }): void {
    const next = { ...this.items.get(id) };
    for (const k of ['password', 'psk'] as const) {
      const v = patch[k];
      if (v === undefined) continue;
      if (v) next[k] = v;
      else delete next[k];
    }
    if (next.password || next.psk) this.items.set(id, next);
    else this.items.delete(id);
    this.save();
  }

  delete(id: string): void {
    if (this.items.delete(id)) this.save();
  }

  flush(): Promise<void> {
    return this.saving;
  }

  private save(): void {
    const items: Record<string, Sealed> = {};
    for (const [id, v] of this.items) items[id] = seal(this.key, v);
    const json = JSON.stringify({ v: 1, items } satisfies SecretsFile);
    this.saving = this.saving.then(() => atomicWrite(this.file, json)).catch(() => undefined);
  }
}
