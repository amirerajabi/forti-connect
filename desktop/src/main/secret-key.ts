// The key the engine encrypts saved VPN passwords with. It is kept encrypted by the OS (Electron safeStorage: DPAPI
// on Windows, the Keychain on macOS, the secret service on Linux) and handed to the engine at start, so a copy of the
// data folder alone does not reveal the passwords. Without safeStorage the engine falls back to its own key file.
import { app, safeStorage } from 'electron';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export function engineSecretKey(): string | null {
  if (!safeStorage.isEncryptionAvailable()) return null;
  const file = path.join(app.getPath('userData'), 'secret-key.bin');
  try {
    const key = safeStorage.decryptString(fs.readFileSync(file));
    if (/^[0-9a-f]{64}$/.test(key)) return key;
  } catch {
    /* first start, or the OS forgot its key: start over (the engine asks for the passwords again) */
  }
  const key = randomBytes(32).toString('hex');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, safeStorage.encryptString(key));
  return key;
}
