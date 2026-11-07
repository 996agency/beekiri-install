#!/usr/bin/env node
/**
 * Beekiri installer: downloads the latest Beekiri release into a new folder, installs its
 * dependencies and starts it, so the setup wizard opens in the browser.
 *
 *   npx github:996agency/beekiri-install my-site
 *   npx create-beekiri my-site            (once published to npm)
 *
 * No dependencies: Node 20+ only (fetch, zlib). Free to use — see LICENSE (Beekiri License).
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize, resolve, sep } from 'node:path';
import { inflateRawSync } from 'node:zlib';

const LATEST_URL = process.env.BEEKIRI_LATEST_URL || 'https://raw.githubusercontent.com/996agency/beekiri-install/main/latest.json';
const MIN_NODE = 20;

/** 996agency's release signing keys: only a package signed by one of them is installed. */
const RELEASE_KEYS = ['dL0loV7jwSJ1bKW62LZfLyO6kPiaxR55565WvqceXT0='];
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[22m`,
  dim: (s) => `\x1b[2m${s}\x1b[22m`,
  green: (s) => `\x1b[32m${s}\x1b[39m`,
  yellow: (s) => `\x1b[33m${s}\x1b[39m`,
  red: (s) => `\x1b[31m${s}\x1b[39m`,
  orange: (s) => `\x1b[38;5;208m${s}\x1b[39m`,
};
const say = (s = '') => process.stdout.write(`${s}\n`);
const fail = (msg) => {
  say(`\n${c.red('✖')} ${msg}\n`);
  process.exit(1);
};

function help() {
  say(`
${c.bold('Create a Beekiri site')}

  ${c.bold('npx github:996agency/beekiri-install')} ${c.dim('[folder] [options]')}

${c.bold('Options')}
  --no-install   Download only; do not run npm install
  --no-start     Do not start Beekiri at the end
  -h, --help     Show this help

${c.bold('Needs')}
  Node.js ${MIN_NODE}+. No database? The setup wizard can install one for you
  ("Set it up for me"), or connect your own PostgreSQL 14+ (local or hosted).
  PHP 8+ is optional (PHP theme layouts and the Shopping storefront).

Beekiri is free to use. See LICENSE and TRADEMARKS.md in the new folder.
`);
}

/* ── Arguments ───────────────────────────────────────────────────────── */

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) {
  help();
  process.exit(0);
}
const flags = new Set(args.filter((a) => a.startsWith('--')));
const folderArg = args.find((a) => !a.startsWith('-')) || 'beekiri';
const target = resolve(process.cwd(), folderArg);

/* ── Checks ──────────────────────────────────────────────────────────── */

function checkNode() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < MIN_NODE) fail(`Beekiri needs Node.js ${MIN_NODE} or newer (you have ${process.versions.node}). Install it from https://nodejs.org and run this again.`);
}

function has(cmd, argv = ['--version']) {
  try {
    const r = spawnSync(cmd, argv, { stdio: 'ignore', shell: process.platform === 'win32' });
    return r.status === 0;
  } catch {
    return false;
  }
}

function checkFolder() {
  if (existsSync(target)) {
    const entries = readdirSync(target).filter((n) => n !== '.DS_Store');
    if (entries.length) fail(`The folder ${c.bold(folderArg)} already exists and is not empty. Choose a new folder name, e.g. ${c.bold('npx github:996agency/beekiri-install my-new-site')}`);
  }
}

/* ── Download + unzip ────────────────────────────────────────────────── */

async function fetchLatest() {
  // GitHub caches raw files for a few minutes after a release; its API is always current.
  if (!process.env.BEEKIRI_LATEST_URL) {
    try {
      const api = await fetch('https://api.github.com/repos/996agency/beekiri-install/contents/latest.json', {
        headers: { Accept: 'application/vnd.github.raw', 'User-Agent': 'create-beekiri' },
      });
      if (api.ok) {
        const latest = await api.json();
        if (latest?.downloadUrl) return latest;
      }
    } catch {
      // Fall back to the raw file below.
    }
  }
  let res;
  try {
    res = await fetch(`${LATEST_URL}${LATEST_URL.includes('?') ? '&' : '?'}t=${Date.now()}`, { headers: { 'Cache-Control': 'no-cache' } });
  } catch (error) {
    fail(`Could not reach GitHub to find the latest Beekiri release (${error.message}). Check your internet connection.`);
  }
  if (!res.ok) fail(`Could not read the latest Beekiri release (${res.status}).`);
  const latest = await res.json();
  if (!latest?.downloadUrl) fail('The release information is incomplete. Try again in a few minutes.');
  return latest;
}

async function download(url, soft = false) {
  const res = await fetch(url);
  if (!res.ok || !res.body) {
    if (soft) throw new Error(`HTTP ${res.status}`);
    fail(`Download failed (${res.status}).`);
  }
  const total = Number(res.headers.get('content-length')) || 0;
  const chunks = [];
  let got = 0;
  for await (const chunk of res.body) {
    chunks.push(chunk);
    got += chunk.length;
    if (total && process.stdout.isTTY) process.stdout.write(`\r  Downloading… ${Math.round((100 * got) / total)}%   `);
  }
  if (process.stdout.isTTY) process.stdout.write('\r                         \r');
  return Buffer.concat(chunks);
}

/** Checks the package against its .sig (version, sha256, Ed25519 signature) before anything is unpacked. */
async function verifyPackage(zip, zipUrl, version) {
  let sig;
  try {
    const res = await fetch(`${zipUrl.split('?')[0]}.sig`);
    sig = res.ok ? await res.json() : null;
  } catch {
    sig = null;
  }
  if (!sig) fail('The downloaded package has no 996agency signature, so it was not installed.');
  const sha256 = createHash('sha256').update(zip).digest('hex');
  const signature = Buffer.from(String(sig.signature || ''), 'base64');
  const message = Buffer.from(`beekiri-core:v1\n${sig.version}\n${sha256}`, 'utf8');
  const signed =
    signature.length === 64 &&
    RELEASE_KEYS.some((b64) => {
      try {
        const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(b64, 'base64')]), format: 'der', type: 'spki' });
        return verify(null, message, key, signature);
      } catch {
        return false;
      }
    });
  if (!signed || sig.sha256 !== sha256 || (version && sig.version !== version)) {
    fail('The downloaded package is not signed by 996agency (or was altered), so it was not installed.');
  }
}

/** Minimal ZIP reader (stored + deflate, no ZIP64), enough for the Beekiri release package. */
function unzip(buf, dest) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) fail('The downloaded package is not a valid ZIP file.');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) fail('The downloaded package is damaged.');
    const method = buf.readUInt16LE(p + 10);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const attr = buf.readUInt32LE(p + 38);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    entries.push({ method, size, attr, local, name });
    p += 46 + nameLen + extraLen + commentLen;
  }
  // The package wraps everything in one top folder (beekiri-install-vX.Y.Z-date/): drop it.
  const tops = new Set(entries.map((e) => e.name.split('/')[0]));
  const strip = tops.size === 1 && entries.every((e) => e.name.includes('/')) ? [...tops][0].length + 1 : 0;
  const root = resolve(dest);
  let files = 0;
  for (const e of entries) {
    const rel = e.name.slice(strip);
    if (!rel) continue;
    const out = resolve(root, normalize(rel));
    if (isAbsolute(rel) || (out !== root && !out.startsWith(root + sep))) fail(`Refusing unsafe path in package: ${e.name}`);
    if (rel.endsWith('/')) {
      mkdirSync(out, { recursive: true });
      continue;
    }
    const nl = buf.readUInt16LE(e.local + 26);
    const xl = buf.readUInt16LE(e.local + 28);
    const start = e.local + 30 + nl + xl;
    const data = buf.subarray(start, start + e.size);
    const content = e.method === 0 ? data : e.method === 8 ? inflateRawSync(data) : fail(`Unsupported compression in ${e.name}.`);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, content);
    const mode = (e.attr >>> 16) & 0o777;
    if (mode && process.platform !== 'win32') chmodSync(out, mode);
    files++;
  }
  return files;
}

/* ── Run ─────────────────────────────────────────────────────────────── */

function run(cmd, argv, cwd) {
  return new Promise((done) => {
    const child = spawn(cmd, argv, { cwd, stdio: 'inherit', shell: process.platform === 'win32' });
    child.on('close', (code) => done(code ?? 1));
  });
}

async function main() {
  say(`\n${c.orange('🐝')} ${c.bold('Beekiri')} ${c.dim('— free CMS by 996agency')}\n`);
  checkNode();
  checkFolder();

  const latest = await fetchLatest();
  say(`  Latest release: ${c.bold(latest.name || latest.tag || latest.version)}`);
  // The release asset is versioned (never stale); the raw ZIP link is the fallback.
  const repo = (latest.releaseUrl || '').match(/^https:\/\/github\.com\/(996agency\/[^/]+)\/releases\//)?.[1];
  const assetUrl = repo && latest.tag ? `https://github.com/${repo}/releases/download/${latest.tag}/beekiri-install.zip` : '';
  // Only GitHub over https: latest.json can't send the download anywhere else.
  if (!/^https:\/\/github\.com\/996agency\//.test(String(latest.downloadUrl)) && !process.env.BEEKIRI_LATEST_URL) {
    fail('The release information points outside 996agency on GitHub. Not installing.');
  }
  let zip;
  let zipUrl = assetUrl;
  try {
    zip = assetUrl ? await download(assetUrl, true) : null;
  } catch {
    zip = null;
  }
  if (!zip) {
    zipUrl = latest.downloadUrl;
    zip = await download(latest.downloadUrl);
  }
  await verifyPackage(zip, zipUrl, latest.version);
  say(`  ${c.green('✔')} Signature verified`);
  mkdirSync(target, { recursive: true });
  const files = unzip(zip, target);
  say(`  ${c.green('✔')} Downloaded into ${c.bold(folderArg)} ${c.dim(`(${files} files)`)}`);

  const pg = has('psql') || has('pg_isready');
  const php = has('php', ['-v']);
  if (!pg) {
    say(`\n  ${c.dim('No PostgreSQL on this computer: that is fine. In the setup wizard choose')} ${c.bold('Set it up for me')}`);
    say(`  ${c.dim('and Beekiri installs its own database inside this site folder.')}`);
  }
  if (!php) say(`\n  ${c.dim('PHP 8+ was not found. That is fine unless you use PHP theme layouts or the Shopping storefront.')}`);

  if (flags.has('--no-install')) {
    say(`\n  Next: ${c.bold(`cd ${folderArg} && npm install && npm start`)}\n`);
    return;
  }
  say(`\n  Installing dependencies ${c.dim('(npm install, takes a minute or two)')}…\n`);
  const code = await run('npm', ['install'], target);
  if (code !== 0) fail(`npm install failed. Fix the error above, then run: cd ${folderArg} && npm install && npm start`);
  say(`\n  ${c.green('✔')} Installed.`);

  if (flags.has('--no-start')) {
    say(`\n  Start it with: ${c.bold(`cd ${folderArg} && npm start`)}, then open the setup address it prints.\n`);
    return;
  }
  say(`\n  Starting Beekiri. The first start builds the app, then prints a ${c.bold('setup link')}.`);
  say(`  Open it in your browser, let Beekiri set up the database (or enter your own), and create your site.\n`);
  say(c.dim(`  Later: cd ${folderArg} && npm start   ·   Stop: Ctrl+C\n`));
  process.exit(await run('npm', ['start'], target));
}

main().catch((error) => fail(error?.message || String(error)));
