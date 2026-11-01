// NullRoute service worker.
//
// All network blocking is done by Chrome's declarativeNetRequest engine from
// precompiled static rulesets, so the worker never sees request URLs and is
// free to be suspended. The worker only:
//   * reconciles user settings (pause, per-site allowlist, custom filters,
//     enabled lists) into dynamic DNR rules + content-script registrations
//   * injects site-specific element-hiding CSS on navigation
//   * runs the element picker
//   * checks top-level navigations against the phishing/malware reputation
//     data, locally first (see lib/reputation.js)

import { CosmeticEngine } from './lib/cosmetic.js';
import { hostOf, isValidDomain, matchesAny, matchPatternFor, normalizeDomain } from './lib/domains.js';
import { parseUserFilters } from './lib/userfilters.js';
import { decodePrefixes, Reputation } from './lib/reputation.js';
import { CrossSiteDetector, extractIds, siteOf, TRACKING_TYPES } from './lib/xsite.js';
import {
  buildShieldsRules, effective, fingerprintRegistration, isValidControl, normalizeGlobals,
  overrideFor, RULE_AGGRESSIVE, RULE_COOKIES, scriptSettings, setOverride, shredOrigins,
} from './lib/shields.js';

const ALLOWLIST_RULE_ID = 1;
const XSITE_RULE_ID = 900;
const USER_RULE_BASE = 1000;
const GENERIC_SCRIPT_ID = 'nr-generic-css';
const SCRIPTLET_SCRIPT_ID = 'nr-scriptlets';
const SCRIPTLET_RULESET = 'ublock'; // scriptlets ship with the uBlock filters list
const MENU_PICKER = 'nr-picker';
const FARBLE_SCRIPT_ID = 'nr-farble';
const REP_ALARM = 'nr-rep-update';
const REP_CACHE = 'nullroute-rep';
// Cache API keys must be http(s); this one is never fetched.
const REP_CACHE_KEY = 'https://nullroute.invalid/rep/prefixes.rice';
// The lists branch CI publishes compiled lists to (.github/workflows/lists.yml).
export const LISTS_BASE_DEFAULT = 'https://raw.githubusercontent.com/Keshav-gehlot/nullroute/lists/';

const DEFAULTS = {
  paused: false,
  allowlist: [],          // user-allowlisted domains
  userFilters: '',        // raw "My filters" text
  enabledRulesets: null,  // null = manifest defaults
  globalDefaults: {},     // shields defaults for every site (see lib/shields.js)
  siteOverrides: {},      // per-site shields overrides
  phishingProtection: true, // warn before opening sites on phishing/malware feeds
  crossSiteDetection: true, // spot unlisted third parties receiving one ID from several sites
  blockCrossSite: false,    // ...and block them (opt-in)
  xsiteFlagged: {},         // domain -> { sites, at }
  listsBaseUrl: LISTS_BASE_DEFAULT,
};

// ---------------------------------------------------------------- state
async function getState() {
  const s = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...s };
}

let rulesetMeta = null;
async function getRulesetMeta() {
  rulesetMeta ||= await fetch(chrome.runtime.getURL('rulesets/rulesets.json')).then(r => r.json());
  return rulesetMeta;
}

let enginePromise = null;
function engine() {
  enginePromise ||= CosmeticEngine.load().catch(err => { enginePromise = null; throw err; });
  return enginePromise;
}

let genericExcludedCache = null;
async function genericExcluded() {
  genericExcludedCache ||= await fetch(chrome.runtime.getURL('rulesets/generic-excluded.json')).then(r => r.json());
  return genericExcludedCache;
}

// ---------------------------------------------------------------- reconcile
// Idempotently pushes stored settings into Chrome. Called on install,
// browser start and after every settings change.
let reconcileChain = Promise.resolve();
function reconcile() {
  reconcileChain = reconcileChain.then(doReconcile).catch(err => console.error('[NullRoute] reconcile failed', err));
  return reconcileChain;
}

async function doReconcile() {
  const state = await getState();
  await applyRulesets(state);
  await applyDynamicRules(state);
  await applyGenericStylesheet(state);
  await applyScriptlets(state);
  await applyScriptBlocking(state);
  await applyFingerprinting(state);
  await chrome.action.setBadgeBackgroundColor({ color: state.paused ? '#b7790a' : '#2f5bea' });
  await chrome.action.setTitle({ title: state.paused ? 'NullRoute (paused)' : 'NullRoute' });
}

async function applyRulesets(state) {
  const meta = await getRulesetMeta();
  const all = meta.rulesets.map(r => r.id);
  const wanted = state.paused ? [] : (state.enabledRulesets ?? meta.rulesets.filter(r => r.enabled).map(r => r.id));
  const current = await chrome.declarativeNetRequest.getEnabledRulesets();
  const enable = wanted.filter(id => !current.includes(id));
  const disable = all.filter(id => current.includes(id) && !wanted.includes(id));
  if (enable.length || disable.length) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: enable, disableRulesetIds: disable });
  }
}

async function applyDynamicRules(state) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const addRules = [];
  if (!state.paused) {
    if (state.allowlist.length) {
      addRules.push({
        id: ALLOWLIST_RULE_ID,
        priority: 100, // beats every list rule, including $important
        action: { type: 'allowAllRequests' },
        condition: { requestDomains: state.allowlist, resourceTypes: ['main_frame', 'sub_frame'] },
      });
    }
    addRules.push(...buildShieldsRules(state.globalDefaults, state.siteOverrides));
    const xsite = Object.keys(state.xsiteFlagged).filter(isValidDomain);
    if (state.blockCrossSite && xsite.length) {
      addRules.push({
        id: XSITE_RULE_ID,
        priority: 1, // below every allow rule: allowlisted sites and list exceptions still win
        action: { type: 'block' },
        condition: { requestDomains: xsite, domainType: 'thirdParty' },
      });
    }
    const { rules } = parseUserFilters(state.userFilters);
    rules.forEach((r, i) => addRules.push({ id: USER_RULE_BASE + i, ...r }));
  }
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map(r => r.id),
    addRules,
  });
}

async function applyGenericStylesheet(state) {
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [GENERIC_SCRIPT_ID] });
  if (registered.length) await chrome.scripting.unregisterContentScripts({ ids: [GENERIC_SCRIPT_ID] });
  if (state.paused) return;
  const excluded = new Set([...(await genericExcluded()), ...state.allowlist]);
  await chrome.scripting.registerContentScripts([{
    id: GENERIC_SCRIPT_ID,
    css: ['rulesets/generic.css'],
    matches: ['http://*/*', 'https://*/*'],
    // One malformed pattern would make Chrome reject the whole registration.
    excludeMatches: [...excluded].filter(isValidDomain).map(matchPatternFor),
    allFrames: true,
    runAt: 'document_start',
    persistAcrossSessions: true,
  }]);
}

let scriptletDomainsCache = null;
async function applyScriptlets(state) {
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPTLET_SCRIPT_ID] });
  if (registered.length) await chrome.scripting.unregisterContentScripts({ ids: [SCRIPTLET_SCRIPT_ID] });
  if (state.paused) return;
  const enabled = await chrome.declarativeNetRequest.getEnabledRulesets();
  if (!enabled.includes(SCRIPTLET_RULESET)) return;
  scriptletDomainsCache ||= await fetch(chrome.runtime.getURL('rulesets/scriptlet-domains.json')).then(r => r.json());
  const domains = scriptletDomainsCache.filter(isValidDomain);
  if (!domains.length) return;
  await chrome.scripting.registerContentScripts([{
    id: SCRIPTLET_SCRIPT_ID,
    js: ['rulesets/scriptlets-main.js'],
    // MAIN world: shares window with the page, so it can trap properties
    // before the page's own scripts run (document_start).
    world: 'MAIN',
    matches: domains.map(matchPatternFor),
    excludeMatches: state.allowlist.filter(isValidDomain).map(matchPatternFor),
    allFrames: true,
    runAt: 'document_start',
    persistAcrossSessions: true,
  }]);
}

// Per-site JavaScript blocking uses Chrome's own content settings, which also
// stop inline scripts and event handlers — DNR can only block script files.
async function applyScriptBlocking(state) {
  await chrome.contentSettings.javascript.clear({});
  if (state.paused) return;
  for (const s of scriptSettings(state.globalDefaults, state.siteOverrides, state.allowlist)) {
    await chrome.contentSettings.javascript.set(s);
  }
}

async function applyFingerprinting(state) {
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [FARBLE_SCRIPT_ID] });
  if (registered.length) await chrome.scripting.unregisterContentScripts({ ids: [FARBLE_SCRIPT_ID] });
  if (state.paused) return;
  const reg = fingerprintRegistration(state.globalDefaults, state.siteOverrides, state.allowlist);
  if (!reg) return;
  await chrome.scripting.registerContentScripts([{
    id: FARBLE_SCRIPT_ID,
    js: ['src/shields/farble.js'],
    world: 'MAIN',
    matches: reg.matches,
    excludeMatches: reg.excludeMatches,
    allFrames: true,
    // Also run in about:blank / srcdoc frames, a classic trick for grabbing
    // untouched canvas prototypes from a fresh iframe.
    matchOriginAsFallback: true,
    runAt: 'document_start',
    persistAcrossSessions: true,
  }]);
}

// ---------------------------------------------------------------- site data ("shred")
async function shredSite(site) {
  const tabs = await chrome.tabs.query({});
  const origins = shredOrigins(site, tabs.map(t => t.url).filter(Boolean));
  await chrome.browsingData.remove({ origins }, {
    cookies: true, localStorage: true, indexedDB: true, cacheStorage: true,
    serviceWorkers: true, fileSystems: true, cache: true,
  });
  return origins;
}

// Auto-shred: remember each tab's site (session storage survives worker
// restarts) and clear the site's data when its last tab closes.
async function rememberTabSite(tabId, url) {
  const host = hostOf(url);
  const { tabSites = {} } = await chrome.storage.session.get('tabSites');
  if (host) tabSites[tabId] = normalizeDomain(host) || host; else delete tabSites[tabId];
  await chrome.storage.session.set({ tabSites });
}

async function onTabClosed(tabId) {
  const { tabSites = {} } = await chrome.storage.session.get('tabSites');
  const site = tabSites[tabId];
  delete tabSites[tabId];
  await chrome.storage.session.set({ tabSites });
  if (!site) return;
  const state = await getState();
  if (state.paused || !effective(site, state.globalDefaults, state.siteOverrides).autoShred) return;
  const stillOpen = Object.values(tabSites).some(s => s === site || s.endsWith(`.${site}`) || site.endsWith(`.${s}`));
  if (!stillOpen) await shredSite(site).catch(e => console.warn('[NullRoute] auto-shred failed', e));
}

// ---------------------------------------------------------------- cosmetic injection
const topHosts = new Map(); // tabId -> top-level hostname (rebuilt lazily after restarts)

async function topHostOf(tabId, frameId, url) {
  if (frameId === 0) return hostOf(url);
  if (topHosts.has(tabId)) return topHosts.get(tabId);
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null);
  return frame ? hostOf(frame.url) : null;
}

async function injectCosmetic(tabId, frameId, url) {
  const host = hostOf(url);
  if (!host) return;
  const state = await getState();
  if (state.paused) return;
  const top = await topHostOf(tabId, frameId, url);
  if (frameId === 0) topHosts.set(tabId, host);
  if (top && matchesAny(top, new Set(state.allowlist))) return;

  const user = parseUserFilters(state.userFilters).cosmetic;
  const eng = await engine();
  const listSelectors = eng.selectorsFor(host, { generic: [], specific: {} });
  const userSelectors = eng.selectorsFor(host, user).filter(s => !listSelectors.includes(s));

  // List selectors were validated at build time and can be grouped. User
  // selectors are injected one rule each so a typo can't disable the rest.
  let css = CosmeticEngine.toCss(listSelectors);
  if (userSelectors.length) css += '\n' + userSelectors.map(s => `${s}{display:none!important}`).join('\n');
  if (!css.trim()) return;
  await chrome.scripting.insertCSS({ target: { tabId, frameIds: [frameId] }, css, origin: 'USER' })
    .catch(() => { /* frame went away, or a restricted page */ });
}

chrome.webNavigation.onCommitted.addListener(({ tabId, frameId, url }) => {
  if (tabId < 0) return;
  injectCosmetic(tabId, frameId, url);
  if (frameId === 0) rememberTabSite(tabId, url);
});
chrome.tabs.onRemoved.addListener(tabId => {
  topHosts.delete(tabId);
  onTabClosed(tabId);
});

// ---------------------------------------------------------------- reputation
// Bundled prefix set (rulesets/rep-prefixes.rice), replaced by a verified daily
// download kept in the Cache API (too big for chrome.storage).
let repPromise = null;
function reputation() {
  repPromise ||= loadReputation().catch(err => { repPromise = null; throw err; });
  return repPromise;
}

async function loadReputation() {
  const cached = await (await caches.open(REP_CACHE)).match(REP_CACHE_KEY);
  const buf = cached ? await cached.arrayBuffer()
    : await fetch(chrome.runtime.getURL('rulesets/rep-prefixes.rice')).then(r => r.arrayBuffer());
  return new Reputation(decodePrefixes(buf), async name => {
    const { listsBaseUrl } = await getState();
    const r = await fetch(`${listsBaseUrl}rep/shards/${name}.bin`, { cache: 'no-store', credentials: 'omit' });
    return r.ok ? r.arrayBuffer() : null;
  });
}

const toHex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');

async function updateReputation() {
  const { listsBaseUrl } = await getState();
  const res = await fetch(`${listsBaseUrl}report.json`, { cache: 'no-store', credentials: 'omit' });
  if (!res.ok) throw new Error(`report.json: HTTP ${res.status}`);
  const expected = (await res.json()).files?.['rep/prefixes.rice'];
  if (!expected) throw new Error('No reputation data in report.json');
  const { repVersion } = await chrome.storage.local.get('repVersion');
  if (repVersion === expected) return { changed: false };
  const r = await fetch(`${listsBaseUrl}rep/prefixes.rice`, { cache: 'no-store', credentials: 'omit' });
  if (!r.ok) throw new Error(`prefixes.rice: HTTP ${r.status}`);
  const buf = await r.arrayBuffer();
  if (toHex(await crypto.subtle.digest('SHA-256', buf)) !== expected) throw new Error('Checksum mismatch');
  const count = decodePrefixes(buf).length;   // throws on a malformed file
  await (await caches.open(REP_CACHE)).put(REP_CACHE_KEY, new Response(buf));
  await chrome.storage.local.set({ repVersion: expected, repUpdatedAt: Date.now(), repCount: count });
  repPromise = null;
  return { changed: true, prefixes: count };
}

// Hosts the user already passed this session ('clean' after a check, or
// 'proceed' after choosing to continue), so each is checked at most once.
async function repPasses() {
  return (await chrome.storage.session.get('repPass')).repPass || {};
}
async function setRepPass(host, value) {
  const repPass = await repPasses();
  repPass[host] = value;
  await chrome.storage.session.set({ repPass });
}

async function guardNavigation(tabId, url) {
  if (!/^https?:/i.test(url)) return;
  const host = hostOf(url);
  if (!host) return;
  const state = await getState();
  if (state.paused || !state.phishingProtection) return;
  if (matchesAny(host, new Set(state.allowlist))) return;
  if ((await repPasses())[host]) return;
  const rep = await reputation();
  // Purely local: SHA-256 of the host and its parents against the prefix set.
  if (!(await rep.localHits(host)).length) return;
  // Possible match: stop this navigation and confirm on the interstitial.
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`src/warning.html?url=${encodeURIComponent(url)}`) });
}

chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, frameId, url }) => {
  if (tabId >= 0 && frameId === 0) guardNavigation(tabId, url).catch(e => console.warn('[NullRoute] reputation', e));
});

// ---------------------------------------------------------------- cross-site trackers
// Requests that got past the lists are observed (never blocked or modified
// here); see lib/xsite.js. Detector state lives in session storage only.
let xsiteDetector = null;
let xsiteChain = Promise.resolve();

async function detector() {
  if (!xsiteDetector) {
    const { xsite } = await chrome.storage.session.get('xsite');
    xsiteDetector = new CrossSiteDetector(xsite || { salt: crypto.randomUUID() });
  }
  return xsiteDetector;
}

async function observeRequest({ url, initiator, documentUrl, type, tabId }) {
  if (tabId < 0 || !TRACKING_TYPES.has(type)) return;
  const fpUrl = documentUrl || initiator || '';
  const tp = siteOf(hostOf(url));
  const fp = siteOf(hostOf(fpUrl));
  if (!tp || !fp || tp === fp) return;
  const ids = extractIds(url, fpUrl);
  if (!ids.length) return;
  const state = await getState();
  if (state.paused || !state.crossSiteDetection || matchesAny(hostOf(fpUrl), new Set(state.allowlist))) return;
  const det = await detector();
  const flagged = await det.observe(tp, fp, ids);
  await chrome.storage.session.set({ xsite: det.toJSON() });
  if (flagged) {
    await chrome.storage.local.set({ xsiteFlagged: { ...state.xsiteFlagged, [tp]: flagged } });
    if (state.blockCrossSite) await reconcile();
  }
}

chrome.webRequest.onBeforeRequest.addListener(details => {
  xsiteChain = xsiteChain.then(() => observeRequest(details)).catch(e => console.warn('[NullRoute] xsite', e));
}, { urls: ['http://*/*', 'https://*/*'] });

// ---------------------------------------------------------------- element picker
async function startPicker(tabId) {
  await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ['src/picker.js'] });
}

async function addUserCosmetic(host, selector) {
  const state = await getState();
  const line = `${host}##${selector}`;
  const text = state.userFilters.trim() ? `${state.userFilters.trimEnd()}\n${line}` : line;
  const parsed = parseUserFilters(line);
  if (parsed.errors.length) throw new Error(parsed.errors[0].msg);
  await chrome.storage.local.set({ userFilters: text });
}

// ---------------------------------------------------------------- messages
const handlers = {
  async getStatus({ tabId, url }) {
    const state = await getState();
    const host = hostOf(url);
    const site = host ? (normalizeDomain(host) || host) : null;
    const allowlisted = !!host && matchesAny(host, new Set(state.allowlist));
    const meta = await getRulesetMeta();
    const enabled = await chrome.declarativeNetRequest.getEnabledRulesets();

    let counts = null;
    let badge = '';
    if (tabId >= 0) try {
      const { rulesMatchedInfo } = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
      counts = {};
      for (const m of rulesMatchedInfo) {
        let key = m.rule.rulesetId;
        if (key === '_dynamic') {
          const id = m.rule.ruleId;
          if (id === ALLOWLIST_RULE_ID) continue;
          key = id === RULE_AGGRESSIVE ? 'aggressive' : id === RULE_COOKIES ? 'cookies'
            : id === XSITE_RULE_ID ? 'crosssite' : 'custom';
        }
        counts[key] = (counts[key] || 0) + 1;
      }
    } catch { /* quota exceeded: fall back to the badge counter */ }
    if (tabId >= 0) badge = await chrome.action.getBadgeText({ tabId }).catch(() => '');

    const globals = normalizeGlobals(state.globalDefaults);
    const shields = site ? {
      effective: effective(site, globals, state.siteOverrides),
      override: overrideFor(site, state.siteOverrides),
    } : null;
    return { paused: state.paused, host, site, allowlisted, counts, badge, globals, shields,
             siteOverrides: state.siteOverrides,
             rulesets: meta.rulesets.map(r => ({ ...r, enabled: enabled.includes(r.id) })) };
  },

  /** value === null resets the site to the global default. */
  async setSiteControl({ site, key, value }) {
    const d = normalizeDomain(site);
    if (!d) throw new Error('Not a website');
    if (value !== null && !isValidControl(key, value)) throw new Error(`Invalid value for ${key}`);
    const state = await getState();
    await chrome.storage.local.set({ siteOverrides: setOverride(state.siteOverrides, d, key, value) });
    await reconcile();
    return { ok: true };
  },

  async resetSite({ site }) {
    const d = normalizeDomain(site);
    const state = await getState();
    const next = { ...state.siteOverrides };
    delete next[d];
    await chrome.storage.local.set({ siteOverrides: next });
    await reconcile();
    return { ok: true };
  },

  async setGlobalDefault({ key, value }) {
    if (!isValidControl(key, value)) throw new Error(`Invalid value for ${key}`);
    const state = await getState();
    await chrome.storage.local.set({ globalDefaults: { ...normalizeGlobals(state.globalDefaults), [key]: value } });
    await reconcile();
    return { ok: true };
  },

  async shredSite({ site }) {
    const d = normalizeDomain(site);
    if (!d) throw new Error('Not a website');
    return { ok: true, origins: await shredSite(d) };
  },

  async setSiteAllowed({ site, allowed }) {
    const d = normalizeDomain(site);
    if (!d) throw new Error('Not a website');
    const state = await getState();
    const set = new Set(state.allowlist);
    if (allowed) set.add(d); else {
      // Remove the domain and any parent entry that covers it.
      for (const entry of [...set]) if (d === entry || d.endsWith('.' + entry)) set.delete(entry);
    }
    await chrome.storage.local.set({ allowlist: [...set].sort() });
    await reconcile();
    return { ok: true };
  },

  async setPaused({ paused }) {
    await chrome.storage.local.set({ paused: !!paused });
    await reconcile();
    return { ok: true };
  },

  async setRulesetEnabled({ id, enabled }) {
    const meta = await getRulesetMeta();
    const state = await getState();
    const current = new Set(state.enabledRulesets ?? meta.rulesets.filter(r => r.enabled).map(r => r.id));
    if (enabled) current.add(id); else current.delete(id);
    if (enabled && !state.paused) {
      // Surface Chrome's rule-budget error instead of silently failing.
      try {
        await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: [id] });
      } catch (e) {
        throw new Error(`Chrome refused to enable this list: ${e.message}`);
      }
    }
    await chrome.storage.local.set({ enabledRulesets: [...current] });
    await reconcile();
    return { ok: true };
  },

  async saveSettings({ allowlist, userFilters }) {
    const errors = [];
    const clean = new Set();
    for (const [i, raw] of (allowlist || []).entries()) {
      if (!raw.trim()) continue;
      const d = normalizeDomain(raw);
      if (d) clean.add(d); else errors.push({ field: 'allowlist', line: i + 1, msg: `"${raw}" is not a domain` });
    }
    const parsed = parseUserFilters(userFilters);
    for (const e of parsed.errors) errors.push({ field: 'userFilters', ...e });
    await chrome.storage.local.set({ allowlist: [...clean].sort(), userFilters: userFilters || '' });
    await reconcile();
    return { ok: true, errors, counts: parsed.counts };
  },

  async startPicker({ tabId }) {
    await startPicker(tabId);
    return { ok: true };
  },

  async pickerBlock({ selector }, sender) {
    const host = hostOf(sender.tab?.url);
    if (!host) throw new Error('Not a website');
    const site = normalizeDomain(host) || host;
    await addUserCosmetic(site, selector);
    await chrome.scripting.insertCSS({
      target: { tabId: sender.tab.id, frameIds: [0] },
      css: `${selector}{display:none!important}`,
      origin: 'USER',
    });
    return { ok: true, site };
  },

  /** From the interstitial: full check (may fetch one shard). */
  async repCheck({ url }) {
    const host = hostOf(url);
    if (!host) throw new Error('Not a website');
    const result = await (await reputation()).check(host);
    // 'unavailable' fails open: never strand the user because a shard didn't load.
    if (result.verdict !== 'listed') await setRepPass(host, result.verdict);
    return result;
  },

  async repProceed({ url }) {
    const host = hostOf(url);
    if (!host) throw new Error('Not a website');
    await setRepPass(host, 'proceed');
    return { ok: true };
  },

  async repUpdate() {
    return updateReputation();
  },

  async getReputationStatus() {
    const s = await getState();
    const { repUpdatedAt = null } = await chrome.storage.local.get('repUpdatedAt');
    const rep = await reputation().catch(() => null);
    return { enabled: s.phishingProtection, listsBaseUrl: s.listsBaseUrl, prefixes: rep?.size ?? 0, updatedAt: repUpdatedAt };
  },

  async setReputationSettings({ enabled, listsBaseUrl }) {
    const patch = {};
    if (typeof enabled === 'boolean') patch.phishingProtection = enabled;
    if (listsBaseUrl !== undefined) {
      const u = String(listsBaseUrl || LISTS_BASE_DEFAULT).trim();
      if (!/^https?:\/\/[^/]+\/.*\/$/.test(u)) throw new Error('List source must be an http(s) URL ending in /');
      patch.listsBaseUrl = u;
    }
    await chrome.storage.local.set(patch);
    return { ok: true };
  },

  async getCrossSiteStatus() {
    const s = await getState();
    return { enabled: s.crossSiteDetection, block: s.blockCrossSite, flagged: s.xsiteFlagged };
  },

  async setCrossSiteSettings({ enabled, block, forget }) {
    const s = await getState();
    const patch = {};
    if (typeof enabled === 'boolean') patch.crossSiteDetection = enabled;
    if (typeof block === 'boolean') patch.blockCrossSite = block;
    if (forget) {
      const next = { ...s.xsiteFlagged };
      delete next[forget];
      patch.xsiteFlagged = next;
    }
    await chrome.storage.local.set(patch);
    await reconcile();
    return { ok: true };
  },

  async getAvailableRuleCount() {
    return { available: await chrome.declarativeNetRequest.getAvailableStaticRuleCount() };
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false;
  handler(msg, sender)
    .then(result => sendResponse({ ok: true, ...result }))
    .catch(err => sendResponse({ ok: false, error: err.message || String(err) }));
  return true; // async response
});

// ---------------------------------------------------------------- lifecycle
chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  await chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: true });
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU_PICKER, title: 'Block an element…', contexts: ['page', 'image', 'frame', 'link'] });
  });
  await reconcile();
  chrome.alarms.create(REP_ALARM, { delayInMinutes: 5, periodInMinutes: 24 * 60 });
  if (reason === 'install') chrome.runtime.openOptionsPage();
});

chrome.runtime.onStartup.addListener(() => {
  reconcile();
  chrome.alarms.create(REP_ALARM, { delayInMinutes: 5, periodInMinutes: 24 * 60 });
});

chrome.alarms.onAlarm.addListener(({ name }) => {
  if (name === REP_ALARM) updateReputation().catch(e => console.warn('[NullRoute] reputation update failed', e));
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_PICKER && tab?.id >= 0) startPicker(tab.id).catch(() => {});
});
