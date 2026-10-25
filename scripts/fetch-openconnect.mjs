// Puts OpenConnect for Windows into desktop/core, so the Windows installer ships it and FortiConnect's users never have
// to install it themselves (the engine looks there first; the VPN helper copies it to Program Files when installed).
//
// Source: the OpenConnect project's own Windows build (its GitLab CI job MinGW64/GnuTLS on a release tag). The
// installer inside is pinned by SHA-256, so a changed or replaced download fails the build instead of shipping.
//
//   node scripts/fetch-openconnect.mjs [target-dir]      (Windows; needs 7-Zip, which GitHub's Windows runners have)
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = 'v9.21';
const ARTIFACTS = `https://gitlab.com/api/v4/projects/openconnect%2Fopenconnect/jobs/artifacts/${VERSION}/download?job=MinGW64/GnuTLS`;
const INSTALLER = `openconnect-installer-MinGW64-GnuTLS-${VERSION}.exe`;
const INSTALLER_SHA256 = '6ee9e8eb9bc59ef70bb0717df7f99703f8a2ccd11d8e45d58a61f9a2e6ef7d00';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.resolve(process.argv[2] ?? path.join(root, 'desktop', 'core'));

if (process.platform !== 'win32') {
  console.error('fetch-openconnect: the bundled OpenConnect is for Windows builds; run this on Windows');
  process.exit(1);
}

function sevenZip() {
  for (const p of ['7z', 'C:\\Program Files\\7-Zip\\7z.exe', 'C:\\Program Files (x86)\\7-Zip\\7z.exe']) {
    try {
      execFileSync(p, ['i'], { stdio: 'ignore' });
      return p;
    } catch {
      /* next */
    }
  }
  throw new Error('7-Zip is needed to unpack the OpenConnect installer');
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-openconnect-'));
try {
  console.log(`downloading OpenConnect ${VERSION} (GitLab CI, MinGW64/GnuTLS)`);
  // curl (part of Windows) rather than fetch: it follows HTTPS_PROXY where a network needs one to reach GitLab.
  const zip = path.join(work, 'artifacts.zip');
  execFileSync('curl', ['-fsSL', '--retry', '3', '-o', zip, ARTIFACTS], { stdio: 'inherit' });

  // Windows' own tar reads zip archives.
  execFileSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe'), ['-xf', zip, '-C', work, INSTALLER], { stdio: 'inherit' });
  const installer = path.join(work, INSTALLER);
  const sha = createHash('sha256').update(fs.readFileSync(installer)).digest('hex');
  if (sha !== INSTALLER_SHA256) throw new Error(`${INSTALLER} has SHA-256 ${sha}, expected ${INSTALLER_SHA256}: not shipping it`);

  const unpacked = path.join(work, 'unpacked');
  execFileSync(sevenZip(), ['x', '-y', `-o${unpacked}`, installer], { stdio: 'ignore' });
  if (!fs.existsSync(path.join(unpacked, 'openconnect.exe'))) throw new Error('openconnect.exe is not in the installer');

  fs.mkdirSync(target, { recursive: true });
  let n = 0;
  for (const name of fs.readdirSync(unpacked)) {
    // $PLUGINSDIR is NSIS's own; the uninstaller belongs to OpenConnect's installer, not to this copy.
    if (name.startsWith('$') || /^uninstall/i.test(name)) continue;
    const from = path.join(unpacked, name);
    if (!fs.statSync(from).isFile()) continue;
    fs.copyFileSync(from, path.join(target, name));
    n++;
  }
  fs.writeFileSync(
    path.join(target, 'OPENCONNECT-NOTICE.txt'),
    [
      `OpenConnect ${VERSION} for Windows, unmodified, from the OpenConnect project's build:`,
      `  ${ARTIFACTS}`,
      `  ${INSTALLER} (SHA-256 ${INSTALLER_SHA256})`,
      '',
      'OpenConnect is free software under the GNU Lesser General Public License 2.1; its source is at',
      '  https://gitlab.com/openconnect/openconnect',
      'The libraries next to it keep their own licences: GnuTLS, Nettle, GMP, libtasn1, stoken and libiconv (LGPL), libxml2',
      '(MIT), zlib, LZ4 (BSD), and Wintun (https://www.wintun.net, redistributable prebuilt binary).',
      'FortiConnect runs OpenConnect as a separate program and does not link to it.',
      '',
    ].join('\r\n'),
  );
  console.log(`OpenConnect ${VERSION}: ${n} files in ${target}`);
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
