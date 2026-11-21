// SPDX-License-Identifier: Apache-2.0
/**
 * The quick start in README.md is executed here, not described here.
 *
 * Why: a hand-written test with its own copy of the five lines would drift away from the README
 * the first time somebody edits the README, and the drift would be silent — the test keeps passing
 * while the documentation shows code that no longer runs. So this file has no copy of the snippet:
 * it reads README.md, takes the ```js block under "## Quick start", packs the package, installs the
 * tarball in a temp directory, and runs the block exactly as written.
 *
 * The install step is the point. `require('fibemate-core')` from inside the repo would test the
 * source tree; a reader runs the tarball. If `files` in package.json ever stops shipping something
 * the block needs, this test fails and the README keeps its promise.
 *
 * Two negative controls run at the end, because a test that cannot fail is decoration:
 *   - a typo'd API name must make the block exit non-zero;
 *   - swapping the two arguments of `decapsulate` must stop it printing `true`.
 *
 * Run: node --test test/quickstart.test.js   (or `npm test`, which runs both files)
 */
'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const README = path.join(ROOT, 'README.md');

function quickstartBlock() {
  const text = fs.readFileSync(README, 'utf8');
  const heading = text.indexOf('## Quick start');
  assert.notEqual(heading, -1, 'README.md has no "## Quick start" section');
  const m = text.slice(heading).match(/```js\r?\n([\s\S]*?)```/);
  assert.ok(m, 'no ```js block directly under "## Quick start"');
  return m[1];
}

function npm(args, cwd) {
  const r = spawnSync('npm', args, {
    cwd,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    env: { ...process.env, npm_config_audit: 'false', npm_config_fund: 'false' },
  });
  assert.equal(r.status, 0, 'npm ' + args.join(' ') + ' failed:\n' + (r.stderr || ''));
  return r.stdout;
}

let block;
let tmp;
let installed;

before(() => {
  block = quickstartBlock();
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fibemate-quickstart-'));
  const pkgDir = path.join(tmp, 'pkg');
  fs.mkdirSync(pkgDir);
  const packed = JSON.parse(npm(['pack', '--json', '--pack-destination', pkgDir], ROOT));
  installed = path.join(pkgDir, packed[0].filename);
  assert.ok(fs.existsSync(installed), 'npm pack did not produce ' + installed);
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'quickstart-check', private: true }), 'utf8');
  npm(['install', '--no-audit', '--no-fund', installed], tmp);
});

after(() => {
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

test('the block is short, uses the public entry point, and names the three operations', () => {
  const lines = block.split(/\r?\n/).filter((l) => l.trim() !== '');
  assert.ok(lines.length <= 10, 'the "5 lines" claim now needs ' + lines.length + ' non-empty lines');
  for (const name of ['generateKeypair', 'encapsulate', 'decapsulate']) {
    assert.ok(block.includes(name), 'the block no longer calls ' + name);
  }
  assert.ok(block.includes("require('fibemate-core')"), 'the block no longer requires the package by name');
  assert.ok(!block.includes("require('../"), 'the block reaches into the source tree instead of the package');
});

test('the block prints true when run from the packed tarball', () => {
  const run = path.join(tmp, 'run.js');
  fs.writeFileSync(run, block, 'utf8');
  const r = spawnSync(process.execPath, [run], { cwd: tmp, encoding: 'utf8' });
  assert.equal(r.status, 0, 'the README block exited ' + r.status + ':\n' + (r.stderr || ''));
  assert.equal(r.stdout.trim(), 'true', 'the block ran but did not agree on the shared secret');
});

test('negative control: a typo in an API name makes the block fail', () => {
  const broken = block.replace('generateKeypair', 'generateKeyPair');
  assert.notEqual(broken, block, 'could not build the negative control: generateKeypair not found');
  const run = path.join(tmp, 'broken.js');
  fs.writeFileSync(run, broken, 'utf8');
  const r = spawnSync(process.execPath, [run], { cwd: tmp, encoding: 'utf8' });
  assert.notEqual(r.status, 0, 'a typo\'d API name still ran successfully, so this test proves nothing');
});

test('negative control: swapped decapsulate arguments stop the block from printing true', () => {
  const m = block.match(/decapsulate\(\s*(\w+)\s*,\s*(\w+)\s*\)/);
  assert.ok(m, 'could not find a two-argument decapsulate(...) call to swap');
  const swapped = block.replace(m[0], 'decapsulate(' + m[2] + ', ' + m[1] + ')');
  assert.notEqual(swapped, block, 'the swap produced identical code');
  const run = path.join(tmp, 'swapped.js');
  fs.writeFileSync(run, swapped, 'utf8');
  const r = spawnSync(process.execPath, [run], { cwd: tmp, encoding: 'utf8' });
  assert.notEqual(r.stdout.trim(), 'true', 'the swapped call still printed true, so it is not testing the argument order');
});
