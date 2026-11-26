#!/usr/bin/env node
// End-to-end check of remote passkey approval in a real Chromium browser.
//
// What runs: the relay, a test site (webauthn-rs), the phone simulator, the
// `signet-passkey` program as Chrome's native-messaging host, and Chrome with
// the extension loaded. The site's page calls the standard
// navigator.credentials API. The test passes when the site's own server has
// verified a registration and a sign-in that the phone simulator approved,
// when a denial reaches the page as NotAllowedError, and when calls that are
// not for the phone still reach the browser's own passkey support.
//
// Everything is local and temporary: random ports, a throwaway browser
// profile, keys generated for the run. Needs Node 22+, a Chromium-family
// browser that accepts --load-extension (Chrome for Testing or Chromium), and
// the binaries built:
//
//     cargo build -p signet-passkey-relay -p signet-passkey-desktop --bins --examples
//     node scripts/passkey_browser_e2e.mjs [--chrome /path/to/chrome]
//
// No dependencies: it speaks the DevTools protocol over Node's own WebSocket.
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bin = name => join(root, 'target', 'debug', name);
const extension = join(root, 'extensions', 'passkey-chromium');
const args = process.argv.slice(2);
const flag = name => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const chrome =
  flag('--chrome') ||
  process.env.CHROME ||
  ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'].find(existsSync);

const children = [];
const work = mkdtempSync(join(tmpdir(), 'signet-passkey-e2e-'));
let failed = false;

function cleanup() {
  for (const child of children) {
    try {
      child.kill('SIGKILL');
    } catch {
      // Already gone.
    }
  }
  try {
    rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    // The browser may still be letting go of its profile; the folder is in
    // the system's temporary directory either way.
  }
}
process.on('exit', cleanup);

const sleep = ms => new Promise(done => setTimeout(done, ms));

function check(condition, what, detail) {
  if (condition) {
    console.log(`  ok    ${what}`);
  } else {
    failed = true;
    console.log(`  FAIL  ${what}${detail === undefined ? '' : `\n        ${JSON.stringify(detail)}`}`);
  }
}

// Start a program and collect its output by line.
function start(name, command, argv, options = {}) {
  const child = spawn(command, argv, { stdio: ['pipe', 'pipe', 'pipe'], ...options });
  children.push(child);
  const lines = [];
  const waiters = [];
  let buffer = '';
  const feed = chunk => {
    buffer += chunk;
    let cut;
    while ((cut = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, cut);
      buffer = buffer.slice(cut + 1);
      lines.push(line);
      if (process.env.E2E_VERBOSE) console.log(`    [${name}] ${line}`);
      for (const waiter of [...waiters]) waiter();
    }
  };
  child.stdout.setEncoding('utf8').on('data', feed);
  child.stderr.setEncoding('utf8').on('data', feed);
  const exited = new Promise(done => child.on('exit', code => done(code)));
  // Resolve with the first line matching `pattern` at or after `from`.
  const line = (pattern, { from = 0, timeout = 20000 } = {}) =>
    new Promise((done, fail) => {
      const look = () => {
        const index = lines.findIndex((text, at) => at >= from && pattern.test(text));
        if (index < 0) return false;
        clearTimeout(timer);
        waiters.splice(waiters.indexOf(look), 1);
        done(lines[index]);
        return true;
      };
      const timer = setTimeout(() => {
        waiters.splice(waiters.indexOf(look), 1);
        fail(new Error(`${name}: no line matching ${pattern} within ${timeout} ms\n${lines.join('\n')}`));
      }, timeout);
      waiters.push(look);
      look();
    });
  return { child, lines, line, exited };
}

function run(command, argv) {
  return execFileSync(command, argv, { encoding: 'utf8' });
}

// A minimal DevTools protocol client.
class Devtools {
  constructor(socket) {
    this.socket = socket;
    this.next = 0;
    this.calls = new Map();
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      const call = this.calls.get(message.id);
      if (!call) return;
      this.calls.delete(message.id);
      if (message.error) call.fail(new Error(`${call.method}: ${message.error.message}`));
      else call.done(message.result);
    });
  }

  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((done, fail) => {
      socket.addEventListener('open', done, { once: true });
      socket.addEventListener('error', () => fail(new Error('cannot reach the browser')), { once: true });
    });
    return new Devtools(socket);
  }

  send(method, params = {}, sessionId) {
    const id = ++this.next;
    return new Promise((done, fail) => {
      this.calls.set(id, { done, fail, method });
      this.socket.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }
}

// Run an expression in the page as if the person had just clicked, and wait
// for the promise it returns.
async function inPage(devtools, session, expression, timeout = 60000) {
  const evaluation = devtools.send(
    'Runtime.evaluate',
    { expression, awaitPromise: true, returnByValue: true, userGesture: true },
    session
  );
  const result = await Promise.race([
    evaluation,
    sleep(timeout).then(() => {
      throw new Error(`page did not answer within ${timeout} ms: ${expression}`);
    }),
  ]);
  if (result.exceptionDetails) {
    throw new Error(`page threw: ${JSON.stringify(result.exceptionDetails.exception || result.exceptionDetails)}`);
  }
  return result.result.value;
}

async function main() {
  if (!chrome) throw new Error('no Chromium browser found; pass --chrome /path/to/chrome');
  for (const name of ['signet-passkey', 'signet-passkey-relay', 'examples/phone_sim', 'examples/test_site']) {
    if (!existsSync(bin(name))) throw new Error(`${bin(name)} is missing; build first (see the top of this file)`);
  }
  console.log(`Browser: ${run(chrome, ['--version']).trim()}`);

  // The relay and the site.
  const relay = start('relay', bin('signet-passkey-relay'), ['--listen', '127.0.0.1:0']);
  const relayAddress = `http://${(await relay.line(/^listening /)).split(' ')[1]}`;
  const site = start('site', bin('examples/test_site'), []);
  const siteUrl = (await site.line(/^listening /)).split(' ')[1];

  // The computer: set up, then pair with the simulated phone the way a person
  // would, by ticket and typed code.
  const settings = join(work, 'settings');
  const cli = (...argv) => run(bin('signet-passkey'), ['--dir', settings, ...argv]);
  cli('init', '--name', 'E2E computer', '--relay', relayAddress);
  const pairing = start('pair', bin('signet-passkey'), ['--dir', settings, 'pair']);
  const ticket = await pairing.line(/^signet-pair:/);
  const phone = start('phone', bin('examples/phone_sim'), [
    '--ticket', ticket, '--name', 'E2E phone',
    '--decisions', 'approve,approve,deny', '--then', 'deny',
  ]);
  const code = (await phone.line(/^code \d{6}$/)).split(' ')[1];
  await pairing.line(/answered/);
  pairing.child.stdin.write(`${code}\n`);
  check((await pairing.exited) === 0, 'the computer and the phone pair by ticket and typed code', pairing.lines);

  // The browser, with the extension and a throwaway profile.
  const profile = join(work, 'profile');
  const browser = start('chrome', chrome, [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--no-proxy-server', `--user-data-dir=${profile}`, '--remote-debugging-port=0',
    `--load-extension=${extension}`, `--disable-extensions-except=${extension}`, 'about:blank',
  ]);
  const portFile = join(profile, 'DevToolsActivePort');
  for (let tries = 0; !existsSync(portFile); tries++) {
    if (tries > 100) throw new Error(`the browser did not start\n${browser.lines.join('\n')}`);
    await sleep(100);
  }
  const [port, path] = readFileSync(portFile, 'utf8').trim().split('\n');
  const devtools = await Devtools.connect(`ws://127.0.0.1:${port}${path}`);

  // The extension's id. Chrome derives an unpacked extension's id from its
  // folder: the first 32 hex digits of SHA-256 of the path, written a to p.
  // The browser has service workers of its own, so look for this one by id.
  const extensionId = [...createHash('sha256').update(extension).digest('hex').slice(0, 32)]
    .map(digit => String.fromCharCode(97 + parseInt(digit, 16)))
    .join('');
  let loaded = false;
  for (let tries = 0; tries < 50 && !loaded; tries++) {
    const { targetInfos } = await devtools.send('Target.getTargets');
    loaded = targetInfos.some(t => t.url === `chrome-extension://${extensionId}/background.js`);
    if (!loaded) await sleep(100);
  }
  check(loaded, 'the extension is loaded', { extensionId });
  // Tell this browser profile where the program is.
  cli('browser', 'install', '--extension-id', extensionId, '--manifest-dir', join(profile, 'NativeMessagingHosts'));

  const { targetId } = await devtools.send('Target.createTarget', { url: siteUrl });
  const { sessionId } = await devtools.send('Target.attachToTarget', { targetId, flatten: true });
  await devtools.send('Runtime.enable', {}, sessionId);
  for (let tries = 0; ; tries++) {
    const ready = await inPage(devtools, sessionId, 'typeof window.site === "object"').catch(() => false);
    if (ready) break;
    if (tries > 100) throw new Error('the test site did not load');
    await sleep(100);
  }

  console.log('Through the phone:');
  const available = await inPage(
    devtools, sessionId, 'PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()');
  check(available === true, 'a paired computer reports a built-in authenticator');

  let seen = phone.lines.length;
  const registered = await inPage(devtools, sessionId, 'window.site.register("ada")');
  check(registered.verified === true, 'the site verified a passkey created on the phone', registered);
  const created = registered.client || {};
  check(
    created.isPublicKeyCredential && created.isAttestationResponse && created.idMatchesRawId &&
      created.rawIdIsBuffer && created.clientDataIsBuffer && created.algorithm === -7 &&
      created.publicKeyBytes === 91 && created.authenticatorDataBytes > 37 &&
      created.extensions && created.extensions.credProps && created.extensions.credProps.rk === true,
    'the page received a standard credential object', created);
  const createLine = await phone.line(/^request create /, { from: seen });
  check(
    createLine.includes(`origin=${siteUrl}`) && createLine.includes('site=localhost') &&
      createLine.includes('from="E2E computer"') && createLine.includes('-> approved'),
    'the phone was shown the site, the page and the computer', createLine);
  check(cli('sites', 'list').trim() === 'localhost', 'the site is recorded as using the phone');

  seen = phone.lines.length;
  const signedIn = await inPage(devtools, sessionId, 'window.site.login()');
  check(signedIn.verified === true && signedIn.userVerified === true,
    'the site verified a sign-in approved on the phone', signedIn);
  const used = signedIn.client || {};
  check(used.isPublicKeyCredential && used.isAssertionResponse && used.signatureIsBuffer,
    'the page received a standard assertion object', used);
  await phone.line(/^request sign-in .*-> approved/, { from: seen });

  seen = phone.lines.length;
  const denied = await inPage(devtools, sessionId, 'window.site.login()');
  check(denied.error === 'NotAllowedError', 'a denial on the phone reaches the page as NotAllowedError', denied);
  await phone.line(/^request sign-in .*-> denied/, { from: seen });

  console.log('Left to the browser:');
  // A virtual authenticator stands in for the browser's own passkey support,
  // so a call the extension hands back has somewhere to go.
  await devtools.send('WebAuthn.enable', {}, sessionId);
  await devtools.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    },
  }, sessionId);
  seen = phone.lines.length;
  cli('new-passkeys', 'off');
  const local = await inPage(devtools, sessionId, 'window.site.register("grace")');
  check(local.verified === true, "with new passkeys off, creation goes to the browser's authenticator", local);
  cli('sites', 'remove', 'localhost');
  const localSignIn = await inPage(devtools, sessionId, 'window.site.login()');
  check(localSignIn.verified === true, "a site not listed signs in with the browser's authenticator", localSignIn);
  await sleep(300);
  check(phone.lines.length === seen, 'the phone was not asked for either', phone.lines.slice(seen));

  console.log(failed ? 'FAILED' : 'All checks passed.');
}

main()
  .catch(error => {
    failed = true;
    console.error(error.message || error);
  })
  .finally(() => process.exit(failed ? 1 : 0));
