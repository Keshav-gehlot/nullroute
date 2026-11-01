// Phishing / malware reputation without telling anyone what you browse.
//
// Same format and protocol as the Android app (compiler/nullroute_compiler/reputation.py):
// a local, Golomb-Rice coded set of 32-bit SHA-256 prefixes of ~2.4M listed
// domains is checked on every top-level navigation. Only when a host (or one of
// its parents) hits a local prefix is a shard fetched: the 8-byte hash heads of
// every listed domain sharing the first 12 bits. The server learns which of
// 4,096 buckets was asked for, never the site.

export const SHARD_BITS = 12;
export const HEAD_BYTES = 8;
const MAGIC = 'NRP1';

/** Decodes prefixes.rice into a sorted Uint32Array. Throws on a malformed file. */
export function decodePrefixes(buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 13 || String.fromCharCode(...bytes.slice(0, 4)) !== MAGIC) throw new Error('not a NullRoute prefix set');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = view.getUint32(4);
  const k = bytes[8];
  const out = new Uint32Array(count);
  if (count === 0) return out;
  let cur = view.getUint32(9);
  out[0] = cur;
  let pos = 13 * 8;
  const total = bytes.length * 8;
  const bit = () => {
    if (pos >= total) throw new Error('truncated prefix set');
    const b = (bytes[pos >>> 3] >>> (7 - (pos & 7))) & 1;
    pos++;
    return b;
  };
  for (let i = 1; i < count; i++) {
    let q = 0;
    while (bit()) q++;
    let r = 0;
    for (let j = 0; j < k; j++) r = r * 2 + bit();
    cur += q * 2 ** k + r;
    if (cur > 0xffffffff) throw new Error('prefix overflow');
    out[i] = cur;
  }
  return out;
}

/** The host and each parent with at least two labels, as the compiler hashes them. */
export function expressions(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h.includes('.')) return [];
  const parts = h.split('.');
  const out = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
  return out;
}

export async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

const prefix32 = d => ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
const hex = (d, n) => Array.from(d.slice(0, n), b => b.toString(16).padStart(2, '0')).join('');

function contains(sorted, value) {
  let lo = 0, hi = sorted.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (sorted[mid] === value) return true;
    if (sorted[mid] < value) lo = mid + 1; else hi = mid - 1;
  }
  return false;
}

/** Structural check: whole 8-byte entries, strictly increasing, all in the requested bucket. */
export function parseShard(index, buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length % HEAD_BYTES) return null;
  const heads = new Set();
  let prev = '';
  for (let i = 0; i < bytes.length; i += HEAD_BYTES) {
    const h = hex(bytes.slice(i, i + HEAD_BYTES), HEAD_BYTES);
    if (parseInt(h.slice(0, 3), 16) !== index || h <= prev) return null;
    heads.add(h);
    prev = h;
  }
  return heads;
}

export class Reputation {
  /**
   * @param {Uint32Array} prefixes  decoded local prefix set
   * @param {(name: string) => Promise<ArrayBuffer|null>} fetchShard  fetches rep/shards/<name>.bin
   */
  constructor(prefixes, fetchShard, { cacheSize = 128, ttlMs = 6 * 3600e3, now = () => Date.now() } = {}) {
    this.prefixes = prefixes;
    this.fetchShard = fetchShard;
    this.cache = new Map();
    this.cacheSize = cacheSize;
    this.ttlMs = ttlMs;
    this.now = now;
  }

  get size() { return this.prefixes.length; }

  /** Local only: [{expression, digest}] whose 32-bit prefix is in the set. */
  async localHits(host) {
    const hits = [];
    for (const e of expressions(host)) {
      const d = await sha256(e);
      if (contains(this.prefixes, prefix32(d))) hits.push({ expression: e, digest: d });
    }
    return hits;
  }

  /** {verdict: 'clean'|'listed'|'unavailable', expression?} */
  async check(host) {
    let unavailable = false;
    for (const { expression, digest } of await this.localHits(host)) {
      const index = prefix32(digest) >>> (32 - SHARD_BITS);
      const heads = await this.shard(index);
      if (!heads) { unavailable = true; continue; }
      if (heads.has(hex(digest, HEAD_BYTES))) return { verdict: 'listed', expression };
    }
    return { verdict: unavailable ? 'unavailable' : 'clean' };
  }

  async shard(index) {
    const hit = this.cache.get(index);
    if (hit && this.now() - hit.at < this.ttlMs) return hit.heads;
    const name = index.toString(16).padStart(3, '0');
    let heads = null;
    try {
      const buf = await this.fetchShard(name);
      heads = buf ? parseShard(index, buf) : null;
    } catch { heads = null; }
    if (!heads) return null;
    this.cache.delete(index);
    this.cache.set(index, { heads, at: this.now() });
    if (this.cache.size > this.cacheSize) this.cache.delete(this.cache.keys().next().value);
    return heads;
  }
}
