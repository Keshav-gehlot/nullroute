// Per-site controls on top of global defaults (the Brave Shields model).
//
// Storage schema (chrome.storage.local):
//   globalDefaults: { trackers, blockScripts, cookies, fingerprinting, autoShred }
//   siteOverrides:  { "example.com": { blockScripts: true, ... }, ... }
//   allowlist:      [ "example.com", ... ]   // "shields down" for a site
//
// A site's effective setting is its own override if one exists, else the
// global default. Overrides apply to the site and all its subdomains.
//
// Everything here is pure (no chrome.* calls) so it is unit-tested in Node.

import { isValidDomain, matchPatternFor, parents } from './domains.js';

export const CONTROLS = {
  trackers: { values: ['standard', 'aggressive'], default: 'standard' },
  blockScripts: { values: [true, false], default: false },
  cookies: { values: ['allow3p', 'block3p'], default: 'allow3p' },
  fingerprinting: { values: [true, false], default: true },
  autoShred: { values: [true, false], default: false },
};

export const DEFAULT_GLOBALS = Object.fromEntries(Object.entries(CONTROLS).map(([k, c]) => [k, c.default]));

// Dynamic DNR rule ids used by shields (allowlist = 1, user filters = 1000+).
export const RULE_AGGRESSIVE = 10;
export const RULE_AGGRESSIVE_EXCEPT = 11;
export const RULE_COOKIES = 20;
export const RULE_COOKIES_EXCEPT = 21;

// Below the allowlist (100) so "shields down" still wins; above every list
// rule (<= 3) so list exceptions can't re-enable a third-party script the user
// chose to block in aggressive mode.
const PRIORITY = 50;

const ALL_SUBRESOURCES = ['sub_frame', 'stylesheet', 'script', 'image', 'font', 'object',
  'xmlhttprequest', 'ping', 'media', 'websocket', 'webtransport', 'other'];

export function isValidControl(key, value) {
  return Object.prototype.hasOwnProperty.call(CONTROLS, key) && CONTROLS[key].values.includes(value);
}

export function normalizeGlobals(g) {
  const out = { ...DEFAULT_GLOBALS };
  for (const [k, v] of Object.entries(g || {})) if (isValidControl(k, v)) out[k] = v;
  return out;
}

/** The override entry that applies to host (closest matching parent wins). */
export function overrideFor(host, overrides) {
  if (!host) return {};
  for (const d of parents(host)) if (overrides?.[d]) return { site: d, ...overrides[d] };
  return {};
}

export function effective(host, globals, overrides) {
  const g = normalizeGlobals(globals);
  const o = overrideFor(host, overrides);
  const out = {};
  for (const k of Object.keys(CONTROLS)) out[k] = isValidControl(k, o[k]) ? o[k] : g[k];
  return out;
}

/** Sites whose override for `key` differs from the global default, split by value. */
function sitesBy(key, globals, overrides) {
  const g = normalizeGlobals(globals);
  const differ = [];
  for (const [site, o] of Object.entries(overrides || {})) {
    if (isValidDomain(site) && isValidControl(key, o[key]) && o[key] !== g[key]) differ.push(site);
  }
  return { global: g[key], differ: differ.sort() };
}

/**
 * Dynamic DNR rules for aggressive mode and cross-site cookie blocking.
 * Each control yields at most one rule: global-on with excluded sites, or
 * global-off with the opted-in sites.
 */
export function buildShieldsRules(globals, overrides) {
  const rules = [];

  // Aggressive: block every third-party script and frame on the site
  // (uBlock Origin's "medium mode").
  const agg = sitesBy('trackers', globals, overrides);
  const aggCondition = { domainType: 'thirdParty', resourceTypes: ['script', 'sub_frame'] };
  if (agg.global === 'aggressive') {
    rules.push({ id: RULE_AGGRESSIVE, priority: PRIORITY, action: { type: 'block' },
      condition: { ...aggCondition, ...(agg.differ.length ? { excludedInitiatorDomains: agg.differ } : {}) } });
  } else if (agg.differ.length) {
    rules.push({ id: RULE_AGGRESSIVE, priority: PRIORITY, action: { type: 'block' },
      condition: { ...aggCondition, initiatorDomains: agg.differ } });
  }

  // Cross-site cookies: strip Cookie on third-party requests and Set-Cookie on
  // their responses, so embedded trackers can't read or plant identifiers.
  const ck = sitesBy('cookies', globals, overrides);
  const strip = { type: 'modifyHeaders',
    requestHeaders: [{ header: 'cookie', operation: 'remove' }],
    responseHeaders: [{ header: 'set-cookie', operation: 'remove' }] };
  const ckCondition = { domainType: 'thirdParty', resourceTypes: ALL_SUBRESOURCES };
  if (ck.global === 'block3p') {
    rules.push({ id: RULE_COOKIES, priority: PRIORITY, action: strip,
      condition: { ...ckCondition, ...(ck.differ.length ? { excludedInitiatorDomains: ck.differ } : {}) } });
  } else if (ck.differ.length) {
    rules.push({ id: RULE_COOKIES, priority: PRIORITY, action: strip,
      condition: { ...ckCondition, initiatorDomains: ck.differ } });
  }
  return rules;
}

/**
 * Content-settings patterns for per-site JavaScript blocking. Chrome resolves
 * the most specific pattern, so a site override beats the global default.
 */
export function scriptSettings(globals, overrides, allowlist = []) {
  const s = sitesBy('blockScripts', globals, overrides);
  const shieldsDown = new Set((allowlist || []).filter(isValidDomain));
  const out = [];
  if (s.global) out.push({ primaryPattern: '<all_urls>', setting: 'block' });
  // Content-settings host "*.example.com" matches example.com and its subdomains.
  for (const site of s.differ) {
    if (shieldsDown.has(site)) continue;
    out.push({ primaryPattern: `*://*.${site}/*`, setting: s.global ? 'allow' : 'block' });
  }
  if (s.global) {
    for (const site of shieldsDown) out.push({ primaryPattern: `*://*.${site}/*`, setting: 'allow' });
  }
  return out;
}

/** Registration for the fingerprint-noise MAIN-world script, or null. */
export function fingerprintRegistration(globals, overrides, allowlist) {
  const s = sitesBy('fingerprinting', globals, overrides);
  const shieldsDown = (allowlist || []).filter(isValidDomain);
  if (s.global) {
    return { matches: ['http://*/*', 'https://*/*'],
      excludeMatches: [...new Set([...s.differ, ...shieldsDown])].map(matchPatternFor) };
  }
  const sites = s.differ.filter(d => !shieldsDown.includes(d));
  return sites.length ? { matches: sites.map(matchPatternFor), excludeMatches: shieldsDown.map(matchPatternFor) } : null;
}

/** Origins to clear for a site: the site itself, www, and any open origins under it. */
export function shredOrigins(site, openUrls = []) {
  const out = new Set();
  for (const host of [site, `www.${site}`]) {
    out.add(`https://${host}`);
    out.add(`http://${host}`);
  }
  for (const u of openUrls) {
    try {
      const url = new URL(u);
      if ((url.protocol === 'http:' || url.protocol === 'https:') &&
          (url.hostname === site || url.hostname.endsWith(`.${site}`))) out.add(url.origin);
    } catch { /* ignore */ }
  }
  return [...out].sort();
}

/** Applies one change to the overrides map; null value removes the override. */
export function setOverride(overrides, site, key, value) {
  const next = structuredClone(overrides || {});
  if (value === null || value === undefined) {
    if (next[site]) {
      delete next[site][key];
      if (!Object.keys(next[site]).length) delete next[site];
    }
    return next;
  }
  if (!isValidControl(key, value)) throw new Error(`Invalid value for ${key}`);
  next[site] = { ...(next[site] || {}), [key]: value };
  return next;
}
