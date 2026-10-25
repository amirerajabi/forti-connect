// A stand-in for OpenConnect in the engine tests: asks the same questions in the same way (no line break after them),
// prints the line OpenConnect prints once the tunnel is up, and stays running until it is stopped.
//   node fake-vpn.mjs <mode>   mode: ok | cert | drop | otp-wrong
import * as readline from 'node:readline';

const mode = process.argv[2] ?? 'ok';
const rl = readline.createInterface({ input: process.stdin });
const lines = rl[Symbol.asyncIterator]();
const ask = async (q) => {
  process.stdout.write(q);
  const r = await lines.next();
  return r.done ? null : r.value;
};
const fail = (msg) => {
  console.error(msg);
  process.exit(1);
};

process.on('SIGINT', () => {
  console.log('Logged out');
  process.exit(0);
});

console.log('Connected to 127.0.0.1:443');
if (mode === 'cert') {
  console.log('Server certificate verify failed: signer not found');
  console.log('Reason: signer not found');
  console.log('To trust this server in future, perhaps add this to your command line:');
  console.log('    --servercert pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
  const a = await ask("Enter 'yes' to accept, 'no' to abort; anything else to view: ");
  if (a !== 'yes') fail('User rejected certificate');
}
const user = await ask('Username:');
const pass = await ask('Password:');
// A careless program echoing a secret: the engine must scrub it from the log.
console.log(`debug: user=${user} password=${pass}`);
if (pass !== 'secret') fail('Login failed.');
const code = await ask('Please enter your token code:');
if (code !== '123456') fail('Login failed.');
console.log('Configured as 10.10.0.5, with SSL connected and DTLS in progress');
if (mode === 'drop') {
  setTimeout(() => {
    console.error('Error: connection to the gateway lost');
    process.exit(2);
  }, 300);
}
setInterval(() => undefined, 1000);
