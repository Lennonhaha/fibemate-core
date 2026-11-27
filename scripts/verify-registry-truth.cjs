// SPDX-License-Identifier: Apache-2.0
/**
 * Registry truth — an assertion that does not trust the workflow's own exit code.
 *
 * The 2026-11-15 incident: `npm publish` succeeded, the "confirm" step read a
 * 404 (npm staged publishing), the run went red, and the package sat on the
 * registry as `latest` for eleven days. A red run was treated as "not
 * published" because nothing independently asked the registry.
 *
 * This script asks the registry. It is deliberately separate from the confirm
 * step: it polls for the exact version, records the registry's own fields
 * (time, shasum, integrity, attestation URL), and exits non-zero only when the
 * version genuinely is not there.
 *
 * Usage:
 *   node scripts/verify-registry-truth.cjs --package fibemate-core --version 0.1.1   (JSON on stdout)
 *   node scripts/verify-registry-truth.cjs --package x --version y --timeout 900
 *   node scripts/verify-registry-truth.cjs --self-test
 *
 * Exit codes:
 *   0  version is present on the registry
 *   1  version did not appear within the timeout (staged-only counts as absent)
 *   2  bad usage / self-test failure
 */

'use strict';

const fs = require('fs');

function parseArgs(argv) {
  const out = { timeout: 900, interval: 10, selfTest: false, tarball: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--self-test') out.selfTest = true;
    else if (a === '--package') out.package = argv[++i];
    else if (a === '--version') out.version = argv[++i];
    else if (a === '--timeout') out.timeout = Number(argv[++i]);
    else if (a === '--interval') out.interval = Number(argv[++i]);
    else if (a === '--tarball') out.tarball = argv[++i];
    else if (a === '--strict-sha') out.strictSha = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error('unknown argument: ' + a);
  }
  return out;
}

function packumentUrl(name) {
  return 'https://registry.npmjs.org/' + String(name).split('/').join('%2f');
}

/**
 * Pure decision function so the interesting cases can be tested without network.
 * Returns { status, detail } where status is one of:
 *   found | staged | missing
 */
function evaluatePackument(packument, name, version) {
  if (!packument || typeof packument !== 'object') {
    return { status: 'missing', detail: 'empty packument' };
  }
  const versions = packument.versions || {};
  const v = versions[version];
  if (v) {
    return {
      status: 'found',
      detail: {
        version,
        time: packument.time ? packument.time[version] || null : null,
        tarball: v.dist && v.dist.tarball ? v.dist.tarball : null,
        shasum: v.dist && v.dist.shasum ? v.dist.shasum : null,
        integrity: v.dist && v.dist.integrity ? v.dist.integrity : null,
        attestations: v.dist && v.dist.attestations ? v.dist.attestations : null,
        latest: packument['dist-tags'] ? packument['dist-tags'].latest || null : null,
      },
    };
  }
  const tags = packument['dist-tags'] || {};
  const staged = Object.keys(tags).some((t) => t === '0.0.0-stage' || t.indexOf('stage') !== -1);
  if (staged) {
    return {
      status: 'staged',
      detail: {
        version,
        note: 'registry holds a staged placeholder; the real version is not installable yet',
        distTags: tags,
      },
    };
  }
  return { status: 'missing', detail: { version, distTags: tags } };
}

async function fetchPackument(name) {
  const res = await fetch(packumentUrl(name), {
    headers: { accept: 'application/json', 'user-agent': 'fibemate-registry-truth/1.0' },
  });
  if (res.status === 404) return { packument: null, http: 404 };
  if (!res.ok) throw new Error('registry HTTP ' + res.status);
  return { packument: await res.json(), http: res.status };
}

function shasumOfFile(file) {
  const crypto = require('crypto');
  return crypto.createHash('sha1').update(fs.readFileSync(file)).digest('hex');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    console.log('usage: verify-registry-truth.cjs --package <name> --version <semver> [--timeout 900] [--json-out file] [--tarball file]');
    return 0;
  }

  if (args.selfTest) {
    const cases = [
      [{ versions: { '1.2.3': { dist: { shasum: 'a', integrity: 'sha512-x', tarball: 't', attestations: { url: 'u' } } } }, time: { '1.2.3': '2026-01-01T00:00:00.000Z' }, 'dist-tags': { latest: '1.2.3' } }, '1.2.3', 'found'],
      [{ versions: {}, 'dist-tags': { '0.0.0-stage': '0.0.0-stage' } }, '1.2.3', 'staged'],
      [{ versions: {}, 'dist-tags': { latest: '1.0.0' } }, '1.2.3', 'missing'],
      [null, '1.2.3', 'missing'],
    ];
    let failed = 0;
    for (const [packument, version, want] of cases) {
      const got = evaluatePackument(packument, 'x', version);
      const ok = got.status === want;
      console.log((ok ? 'PASS' : 'FAIL') + ' expected=' + want + ' got=' + got.status);
      if (!ok) failed++;
    }
    console.log('self-test: ' + (cases.length - failed) + '/' + cases.length + ' passed');
    return failed === 0 ? 0 : 2;
  }

  if (!args.package || !args.version) throw new Error('--package and --version are required');

  const deadline = Date.now() + args.timeout * 1000;
  let attempt = 0;
  let last = null;
  while (Date.now() < deadline) {
    attempt++;
    last = await fetchPackument(args.package);
    const verdict = evaluatePackument(last.packument, args.package, args.version);
    const stamp = new Date().toISOString();
    if (verdict.status === 'found') {
      const d = verdict.detail;
      let shaCheck = null;
      if (args.tarball) {
        const local = shasumOfFile(args.tarball);
        shaCheck = { local, registry: d.shasum, equal: local === d.shasum };
        if (!shaCheck.equal) {
          const level = args.strictSha ? '::error::' : '::warning::';
          console.error(level + 'tarball shasum differs: local=' + local + ' registry=' + d.shasum);
        }
      }
      const result = {
        found: true,
        package: args.package,
        version: args.version,
        registryTime: d.time,
        tarball: d.tarball,
        shasum: d.shasum,
        integrity: d.integrity,
        attestations: d.attestations,
        latest: d.latest,
        shasumCheck: shaCheck,
        attempts: attempt,
        checkedAt: stamp,
      };
      console.log(JSON.stringify(result, null, 2));
      if (shaCheck && !shaCheck.equal && args.strictSha) return 3;
      return 0;
    }
    const state = verdict.status === 'staged' ? 'staged (not installable yet)' : 'not visible';
    console.error('attempt ' + attempt + ': ' + args.package + '@' + args.version + ' ' + state + ' at ' + stamp);
    await new Promise((r) => setTimeout(r, args.interval * 1000));
  }

  const result = {
    found: false,
    package: args.package,
    version: args.version,
    reason: last && last.http === 404 ? 'package-not-found' : 'version-not-visible',
    attempts: attempt,
    checkedAt: new Date().toISOString(),
  };
  console.log(JSON.stringify(result, null, 2));
  return 1;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error('::error::' + err.message);
      process.exit(2);
    });
}

module.exports = { evaluatePackument, parseArgs };
