// On-device detection of cross-site trackers the filter lists missed.
//
// A third party that receives the *same* identifier from two unrelated sites
// can link your visits across them: that's what makes it a cross-site tracker,
// whatever its name. This is the test used to measure UID smuggling (Randall
// et al., IMC 2022) and link decoration (PURL, USENIX Security 2024), applied
// live: NullRoute watches the query strings of third-party requests that got
// past the lists, and flags the receiving domain once one ID-like value has
// reached it from >= 2 different sites. Only salted hashes of values are kept,
// in session storage, so the detector itself never stores an identifier.
//
// A learned classifier was evaluated for this job first and rejected; see
// compiler/nullroute_compiler/trackers.py for the numbers.

// Request types that carry tracking data. Scripts, styles, fonts and media are
// excluded: their query strings hold content hashes and versions that are
// legitimately identical on every site.
export const TRACKING_TYPES = new Set(['xmlhttprequest', 'ping', 'image', 'sub_frame', 'other', 'beacon', 'csp_report']);

// Parameter names whose values are versions, cache-busters or presentation.
const BENIGN_PARAMS = new Set([
  'v', 'ver', 'version', 'hash', 'h', 'cb', 'cachebuster', 'cache', 'bust', '_', 'rnd', 'rand', 'random', 'r', 'z',
  'ts', 't', 'time', 'timestamp', 'nocache', 'lang', 'locale', 'hl', 'callback', 'jsonp', 'format', 'w', 'h', 'width',
  'height', 'size', 'q', 'query', 'url', 'u', 'ref', 'referrer', 'dl', 'dr', 'page', 'title', 'dt', 'domain', 'origin',
]);

// Two-label public suffixes common enough to matter for grouping hosts into sites.
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'net.in', 'org.in', 'ac.in',
  'gov.in', 'com.br', 'co.jp', 'ne.jp', 'co.kr', 'com.cn', 'com.tw', 'com.mx', 'com.ar', 'com.tr', 'co.za',
  'com.sg', 'com.my', 'co.id', 'com.vn', 'com.ph', 'com.pk', 'co.nz', 'com.hk', 'co.il', 'co.th',
  'github.io', 'herokuapp.com', 'vercel.app', 'netlify.app', 'pages.dev', 'blogspot.com', 'appspot.com',
]);

/** Registrable site of a hostname: "a.b.example.co.uk" -> "example.co.uk". */
export function siteOf(host) {
  const parts = String(host || '').toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length < 2) return null;
  const n = parts.length >= 3 && MULTI_PART_SUFFIXES.has(parts.slice(-2).join('.')) ? 3 : 2;
  return parts.slice(-n).join('.');
}

const ID_RE = /^[A-Za-z0-9._~-]{12,96}$/;

function looksLikeTimestamp(v, now) {
  if (!/^\d{9,16}(\.\d+)?$/.test(v)) return false;
  const n = Number(v.split('.')[0]);
  const ms = v.length >= 13 ? n : n * 1000;
  return Math.abs(ms - now) < 3 * 365 * 86400e3;
}

/** Is [v] shaped like a per-user identifier rather than a word, version or URL? */
export function isIdLike(v, now = Date.now()) {
  if (!ID_RE.test(v)) return false;
  if (looksLikeTimestamp(v, now)) return false;
  if (/^\d+(\.\d+){1,3}$/.test(v)) return false;                // version numbers
  if (/^(true|false|null|undefined|none)$/i.test(v)) return false;
  const letters = (v.match(/[A-Za-z]/g) || []).length;
  const digits = (v.match(/\d/g) || []).length;
  if (!digits && /^[a-z]+([-_.][a-z]+)*$/i.test(v)) return false; // words and slugs
  // Mostly-repeated characters are not identifiers.
  if (new Set(v).size < Math.min(8, v.length / 3)) return false;
  return letters + digits >= 10;
}

/**
 * ID-like values in a third-party request's query string.
 * @param {string} url the request URL
 * @param {string} firstPartyUrl the page that caused it (values copied from it are not IDs)
 */
export function extractIds(url, firstPartyUrl = '', now = Date.now()) {
  let u;
  try { u = new URL(url); } catch { return []; }
  const page = String(firstPartyUrl);
  const out = new Set();
  for (const [name, raw] of u.searchParams) {
    if (BENIGN_PARAMS.has(name.toLowerCase())) continue;
    // Tracking params often pack several fields: "GA1.2.12345678.1699999999".
    for (const part of raw.split(/[|,;:&]/)) {
      const v = part.trim();
      if (v && isIdLike(v, now) && !page.includes(v)) out.add(v);
    }
  }
  return [...out];
}

/**
 * Remembers which first-party sites sent each (third party, ID) pair and
 * reports third parties that received one ID from two different sites.
 * State is plain JSON so the service worker can persist it in storage.session.
 */
export class CrossSiteDetector {
  constructor(state = {}, { salt = 'nullroute', maxEntries = 20000, minSites = 2 } = {}) {
    this.seen = state.seen || {};          // "tp|hash" -> [site, site]
    this.flagged = state.flagged || {};    // tp -> { sites: [...], at }
    this.salt = state.salt || salt;
    this.maxEntries = maxEntries;
    this.minSites = minSites;
  }

  toJSON() { return { seen: this.seen, flagged: this.flagged, salt: this.salt }; }

  async key(thirdParty, value) {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${this.salt}|${thirdParty}|${value}`));
    return `${thirdParty}|${Array.from(new Uint8Array(d).slice(0, 12), b => b.toString(16).padStart(2, '0')).join('')}`;
  }

  /** Returns the evidence if this observation newly flags [thirdParty], else null. */
  async observe(thirdParty, firstPartySite, ids, now = Date.now()) {
    if (!thirdParty || !firstPartySite || thirdParty === firstPartySite) return null;
    let result = null;
    for (const id of ids) {
      const k = await this.key(thirdParty, id);
      const sites = this.seen[k] || (this.seen[k] = []);
      if (!sites.includes(firstPartySite) && sites.length < 8) sites.push(firstPartySite);
      if (sites.length >= this.minSites && !this.flagged[thirdParty]) {
        this.flagged[thirdParty] = { sites: [...sites], at: now };
        result = this.flagged[thirdParty];
      }
    }
    this.trim();
    return result;
  }

  trim() {
    const keys = Object.keys(this.seen);
    if (keys.length <= this.maxEntries) return;
    for (const k of keys.slice(0, keys.length - this.maxEntries)) delete this.seen[k];
  }
}
