// Unit tests for the per-site controls model.  Run: node --test extension/tests
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildShieldsRules, DEFAULT_GLOBALS, effective, fingerprintRegistration, overrideFor,
  RULE_AGGRESSIVE, RULE_COOKIES, scriptSettings, setOverride, shredOrigins,
} from '../src/lib/shields.js';

test('effective = site override, else global default; subdomains inherit', () => {
  const overrides = { 'news.com': { trackers: 'aggressive' }, 'm.news.com': { blockScripts: true } };
  assert.equal(effective('news.com', {}, overrides).trackers, 'aggressive');
  assert.equal(effective('a.news.com', {}, overrides).trackers, 'aggressive');
  // Closest override wins and doesn't merge with the parent's.
  assert.deepEqual(effective('m.news.com', {}, overrides),
    { ...DEFAULT_GLOBALS, blockScripts: true });
  assert.deepEqual(effective('other.com', { fingerprinting: false }, overrides),
    { ...DEFAULT_GLOBALS, fingerprinting: false });
  assert.deepEqual(overrideFor('x.news.com', overrides), { site: 'news.com', trackers: 'aggressive' });
});

test('invalid stored values fall back to defaults', () => {
  assert.equal(effective('a.com', { trackers: 'nuclear' }, { 'a.com': { cookies: 7 } }).trackers, 'standard');
  assert.equal(effective('a.com', {}, { 'a.com': { cookies: 7 } }).cookies, 'allow3p');
});

test('setOverride adds, replaces and removes; rejects bad values', () => {
  let o = setOverride({}, 'a.com', 'blockScripts', true);
  o = setOverride(o, 'a.com', 'trackers', 'aggressive');
  assert.deepEqual(o, { 'a.com': { blockScripts: true, trackers: 'aggressive' } });
  o = setOverride(o, 'a.com', 'blockScripts', null);
  o = setOverride(o, 'a.com', 'trackers', null);
  assert.deepEqual(o, {});
  assert.throws(() => setOverride({}, 'a.com', 'trackers', 'max'));
});

test('aggressive: per-site opt-in vs global with exclusions', () => {
  let rules = buildShieldsRules({}, { 'a.com': { trackers: 'aggressive' } });
  const agg = rules.find(r => r.id === RULE_AGGRESSIVE);
  assert.deepEqual(agg.condition, { domainType: 'thirdParty', resourceTypes: ['script', 'sub_frame'], initiatorDomains: ['a.com'] });
  assert.ok(agg.priority > 3 && agg.priority < 100, 'above list rules, below shields-down');

  rules = buildShieldsRules({ trackers: 'aggressive' }, { 'bank.com': { trackers: 'standard' } });
  assert.deepEqual(rules.find(r => r.id === RULE_AGGRESSIVE).condition.excludedInitiatorDomains, ['bank.com']);
  assert.deepEqual(buildShieldsRules({}, {}), []);
});

test('cookie blocking strips Cookie and Set-Cookie on third-party requests only', () => {
  const [rule] = buildShieldsRules({}, { 'a.com': { cookies: 'block3p' } });
  assert.equal(rule.id, RULE_COOKIES);
  assert.equal(rule.action.type, 'modifyHeaders');
  assert.deepEqual(rule.action.requestHeaders, [{ header: 'cookie', operation: 'remove' }]);
  assert.deepEqual(rule.action.responseHeaders, [{ header: 'set-cookie', operation: 'remove' }]);
  assert.equal(rule.condition.domainType, 'thirdParty');
  assert.ok(!rule.condition.resourceTypes.includes('main_frame'));
});

test('script settings: most specific pattern wins; shields-down sites always allowed', () => {
  assert.deepEqual(scriptSettings({}, { 'a.com': { blockScripts: true } }),
    [{ primaryPattern: '*://*.a.com/*', setting: 'block' }]);
  assert.deepEqual(scriptSettings({ blockScripts: true }, { 'b.com': { blockScripts: false } }, ['c.com']), [
    { primaryPattern: '<all_urls>', setting: 'block' },
    { primaryPattern: '*://*.b.com/*', setting: 'allow' },
    { primaryPattern: '*://*.c.com/*', setting: 'allow' },
  ]);
  // A shields-down site never gets a per-site block.
  assert.deepEqual(scriptSettings({}, { 'c.com': { blockScripts: true } }, ['c.com']), []);
});

test('fingerprint script registration follows defaults, overrides and shields-down', () => {
  const on = fingerprintRegistration({}, { 'game.com': { fingerprinting: false } }, ['bank.com']);
  assert.deepEqual(on.matches, ['http://*/*', 'https://*/*']);
  assert.deepEqual(on.excludeMatches.sort(), ['*://*.bank.com/*', '*://*.game.com/*']);
  const off = fingerprintRegistration({ fingerprinting: false }, { 'a.com': { fingerprinting: true } }, []);
  assert.deepEqual(off.matches, ['*://*.a.com/*']);
  assert.equal(fingerprintRegistration({ fingerprinting: false }, {}, []), null);
});

test('shred origins cover the site, www, and open subdomain origins only', () => {
  assert.deepEqual(shredOrigins('shop.com', ['https://cdn.shop.com/x', 'https://evilshop.com/', 'chrome://newtab']), [
    'http://shop.com', 'http://www.shop.com', 'https://cdn.shop.com', 'https://shop.com', 'https://www.shop.com',
  ]);
});
