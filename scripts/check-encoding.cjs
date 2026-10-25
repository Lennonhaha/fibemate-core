'use strict';
// SPDX-License-Identifier: GPL-3.0-only
// 编码闸门：遍历 git 跟踪的文件，拒绝 BOM / CRLF / U+FFFD / NUL。
// 用字节判定，不依赖终端显示层（Windows 控制台的 GBK 显示不是判据）。
const { execFileSync } = require('child_process');
const fs = require('fs');

const BINARY_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.wasm', '.gz', '.zip', '.woff', '.woff2', '.ttf']);

const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' })
  .split('\0')
  .filter(Boolean);

const problems = [];
let scanned = 0;
let skipped = 0;

for (const file of files) {
  if (BINARY_EXT.has(require('path').extname(file).toLowerCase())) {
    skipped += 1;
    continue;
  }
  const buf = fs.readFileSync(file);
  scanned += 1;

  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    problems.push(`${file}: BOM (EF BB BF)`);
  }
  if (buf.includes(0x00)) {
    problems.push(`${file}: NUL byte`);
  }
  const text = buf.toString('utf8');
  const fffd = text.split('\uFFFD').length - 1;
  if (fffd > 0) {
    problems.push(`${file}: ${fffd} U+FFFD (invalid UTF-8)`);
  }
  const crlf = text.split('\r\n').length - 1;
  if (crlf > 0) {
    problems.push(`${file}: ${crlf} CRLF line ending(s)`);
  }
}

console.log(`scanned=${scanned} skipped_binary=${skipped} problems=${problems.length}`);
for (const p of problems) console.log('FAIL ' + p);

if (problems.length > 0) {
  console.error('\nencoding gate failed');
  process.exit(1);
}
console.log('encoding gate passed');
