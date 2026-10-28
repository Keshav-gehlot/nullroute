// Hostname helpers shared by the service worker, popup and options page.

/** "a.b.example.com" -> ["a.b.example.com", "b.example.com", "example.com", "com"] */
export function parents(host) {
  const parts = host.split('.');
  const out = [];
  for (let i = 0; i < parts.length; i++) out.push(parts.slice(i).join('.'));
  return out;
}

/** True if host equals, or is a subdomain of, any domain in the set. */
export function matchesAny(host, domainSet) {
  if (!host || !domainSet || domainSet.size === 0) return false;
  for (const p of parents(host)) if (domainSet.has(p)) return true;
  return false;
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$/;

export function isValidDomain(d) {
  return DOMAIN_RE.test(d) && !/^[\d.]+$/.test(d);
}

/** Normalise user input ("https://www.Example.com/path") to a bare hostname. */
export function normalizeDomain(input) {
  let s = String(input || '').trim().toLowerCase();
  if (!s) return null;
  try {
    if (s.includes('://')) s = new URL(s).hostname;
  } catch { return null; }
  s = s.replace(/^\*\./, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (s.startsWith('www.')) s = s.slice(4);
  return isValidDomain(s) ? s : null;
}

export function hostOf(url) {
  try {
    const u = new URL(url);
    return (u.protocol === 'http:' || u.protocol === 'https:') ? u.hostname.toLowerCase() : null;
  } catch { return null; }
}

/** Chrome match pattern covering a domain and all its subdomains. */
export function matchPatternFor(domain) {
  return `*://*.${domain}/*`;
}
