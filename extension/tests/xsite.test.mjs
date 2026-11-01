import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CrossSiteDetector, extractIds, isIdLike, siteOf } from '../src/lib/xsite.js';

const NOW = Date.UTC(2026, 10, 1);

test('identifier shape', () => {
  for (const id of ['GA1.2.1234567890.1699999999', 'a8f3c2d1e9b74f60', '4f9c2b7e-1d3a-4b8e-9f0a-2c6d8e1b3a5f', 'u_8Zk2LmQ9xW3pR7'])
    assert.ok(isIdLike(id, NOW), id);
  for (const no of [String(NOW), String(Math.floor(NOW / 1000)), '1.2.3', 'true', 'checkout-success-page',
                    'aaaaaaaaaaaaaaaa', 'short1', 'ababababababab12'])
    assert.ok(!isIdLike(no, NOW), no);
});

test('extracts IDs, skips benign params and values copied from the page', () => {
  const ids = extractIds('https://px.tracker.example/p?uid=a8f3c2d1e9b74f60&v=9f8e7d6c5b4a3210&cb=1730419200000&page=home&sid=x7Y2kQ9mL3pR8tW1|b2',
    'https://shop.example/item/x7Y2kQ9mL3pR8tW1', NOW);
  assert.deepEqual(ids, ['a8f3c2d1e9b74f60']);
  assert.deepEqual(extractIds('not a url'), []);
});

test('sites group hosts the way the detector needs', () => {
  assert.equal(siteOf('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(siteOf('cdn.tracker.com'), 'tracker.com');
  assert.equal(siteOf('me.github.io'), 'me.github.io');
  assert.equal(siteOf('localhost'), null);
});

test('flags a third party only when one ID arrives from two different sites', async () => {
  const d = new CrossSiteDetector({ salt: 'test' });
  assert.equal(await d.observe('sync.example', 'news.example', ['a8f3c2d1e9b74f60']), null);
  assert.equal(await d.observe('sync.example', 'news.example', ['a8f3c2d1e9b74f60']), null, 'same site twice is not cross-site');
  assert.equal(await d.observe('sync.example', 'blog.example', ['ffffeeee11112222']), null, 'different IDs are not linkable');
  const hit = await d.observe('sync.example', 'shop.example', ['a8f3c2d1e9b74f60']);
  assert.deepEqual(hit.sites, ['news.example', 'shop.example']);
  assert.equal(await d.observe('sync.example', 'third.example', ['a8f3c2d1e9b74f60']), null, 'reported once');
  // Persisted state holds only salted hashes, never the identifier itself.
  assert.ok(!JSON.stringify(d.toJSON()).includes('a8f3c2d1e9b74f60'));
  const restored = new CrossSiteDetector(JSON.parse(JSON.stringify(d.toJSON())));
  assert.ok(restored.flagged['sync.example']);
});
