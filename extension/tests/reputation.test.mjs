// Checks the extension's reputation client against the real compiled data
// (dist/rep) produced by the Python compiler.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { decodePrefixes, expressions, parseShard, Reputation } from '../src/lib/reputation.js';

const REP = new URL('../../dist/rep/', import.meta.url);
const have = existsSync(new URL('prefixes.rice', REP));
const feed = new URL('../../compiler/.cache/rep-1.txt', import.meta.url);
const shardFile = name => readFileSync(new URL(`shards/${name}.bin`, REP));

test('decodes the shipped prefix set', { skip: !have }, () => {
  const meta = JSON.parse(readFileSync(new URL('meta.json', REP)));
  const p = decodePrefixes(readFileSync(new URL('prefixes.rice', REP)));
  assert.equal(p.length, meta.prefixes);
  for (let i = 1; i < p.length; i += 9973) assert.ok(p[i] > p[i - 1]);
});

test('expressions match the compiler', () => {
  assert.deepEqual(expressions('A.b.Evil.com.'), ['a.b.evil.com', 'b.evil.com', 'evil.com']);
  assert.deepEqual(expressions('localhost'), []);
});

test('finds real feed entries, clears essential sites, fails open on bad shards', { skip: !have || !existsSync(feed) }, async () => {
  const prefixes = decodePrefixes(readFileSync(new URL('prefixes.rice', REP)));
  let fetches = 0;
  const rep = new Reputation(prefixes, async n => { fetches++; return shardFile(n); });
  const sample = readFileSync(feed, 'utf8').split('\n').filter(l => l && !l.startsWith('#')).filter((_, i) => i % 97 === 0).slice(0, 30);
  let found = 0;
  for (const d of sample) if ((await rep.check(d)).verdict === 'listed') found++;
  assert.ok(found >= sample.length * 0.9, `found ${found}/${sample.length}`);
  const sub = await rep.check('login.' + sample[0]);
  assert.equal(sub.verdict, 'listed');

  fetches = 0;
  const canaries = readFileSync(new URL('../../compiler/data/canaries.txt', import.meta.url), 'utf8').split(/\s+/).filter(Boolean);
  for (const c of canaries) assert.equal((await rep.check(c)).verdict, 'clean', c);
  assert.ok(fetches <= 2, `clean sites should almost never contact the server (${fetches})`);

  const broken = new Reputation(prefixes, async n => shardFile(n).subarray(0, 5));
  assert.equal((await broken.check(sample[0])).verdict, 'unavailable');
  const offline = new Reputation(prefixes, async () => null);
  assert.equal((await offline.check(sample[0])).verdict, 'unavailable');
});

test('shard structure is enforced', () => {
  const ok = new Uint8Array([0xab, 0xc0, 0, 0, 0, 0, 0, 1, 0xab, 0xc0, 0, 0, 0, 0, 0, 2]);
  assert.equal(parseShard(0xabc, ok).size, 2);
  assert.equal(parseShard(0xabd, ok), null);                       // wrong bucket
  assert.equal(parseShard(0xabc, ok.slice(0, 15)), null);          // truncated
  assert.equal(parseShard(0xabc, new Uint8Array([...ok.slice(8), ...ok.slice(0, 8)])), null); // unsorted
});
