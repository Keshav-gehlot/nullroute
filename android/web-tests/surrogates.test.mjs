// The NullRoute Browser serves these files in place of ad loaders. Each must
// look loaded to page code and to ad-blocker detectors, and request no ads.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const dir = new URL('../app/src/main/assets/web/surrogates/', import.meta.url);
function run(file, pre = {}) {
  const calls = [];
  const els = [{ attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } }];
  const ctx = vm.createContext({
    ...pre,
    setTimeout: (fn) => { calls.push('timeout'); fn(); },
    document: { querySelectorAll: () => els },
    fetch: () => { calls.push('network'); },
    XMLHttpRequest: function () { calls.push('network'); },
  });
  ctx.window = ctx;
  vm.runInContext(readFileSync(new URL(file, dir), 'utf8'), ctx);
  return { ctx, calls, els };
}

test('adsbygoogle: queued pushes are consumed and slots marked done', () => {
  const { ctx, calls, els } = run('adsbygoogle.js', { adsbygoogle: [{}] });
  assert.equal(ctx.adsbygoogle.loaded, true);
  ctx.adsbygoogle.push({});
  assert.equal(els[0].attrs['data-adsbygoogle-status'], 'done');
  assert.deepEqual(calls, []);
});

test('gpt: queued commands run, slots chain, slotRenderEnded reports empty', () => {
  let ran = 0;
  const { ctx } = run('gpt.js', { googletag: { cmd: [() => ran++] } });
  const gt = ctx.googletag;
  assert.equal(ran, 1);
  gt.cmd.push(() => ran++);
  assert.equal(ran, 2);
  const slot = gt.defineSlot('/1/a', [300, 250], 'div-a').addService(gt.pubads()).setTargeting('k', 'v');
  assert.equal(slot.getSlotElementId(), 'div-a');
  const ended = [];
  gt.pubads().addEventListener('slotRenderEnded', e => ended.push(e.isEmpty));
  gt.enableServices();
  gt.display('div-a');
  assert.deepEqual(ended, [true]);
});

test('ima3: SDK present, every ad request ends in an AD_ERROR the player can handle', () => {
  const { ctx, calls } = run('ima3.js');
  const ima = ctx.google.ima;
  const loader = new ima.AdsLoader(new ima.AdDisplayContainer());
  let err = null;
  loader.addEventListener(ima.AdErrorEvent.Type.AD_ERROR, e => { err = e.getError(); });
  loader.getSettings().setVpaidMode(ima.ImaSdkSettings.VpaidMode.ENABLED);
  loader.requestAds(new ima.AdsRequest());
  assert.equal(err.getErrorCode(), 1009);
  assert.ok(!calls.includes('network'));
});
