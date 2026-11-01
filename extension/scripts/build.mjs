#!/usr/bin/env node
// Syncs compiler output (../dist/chrome) into the extension and generates the
// derived assets the extension loads at runtime:
//
//   rulesets/rules_*.json          static DNR rulesets (copied)
//   rulesets/rulesets.json         list metadata (copied)
//   rulesets/cosmetic.json         element-hiding data (copied)
//   rulesets/generic.css           generic hiding sheet, injected at document_start
//   rulesets/rep-prefixes.rice     phishing/malware hash-prefix set (copied)
//   rulesets/generic-excluded.json domains that must NOT get generic.css because
//                                  they have exceptions or opted out of generic hiding
//
// It also checks the manifest declares exactly the compiled rulesets.

import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, '..');
const src = process.argv[2] || join(ext, '..', 'dist', 'chrome');
const out = join(ext, 'rulesets');

if (!existsSync(join(src, 'rulesets.json'))) {
  console.error(`No compiled rules in ${src}. Run the compiler first:\n  cd compiler && python -m nullroute_compiler --out ../dist`);
  process.exit(1);
}
mkdirSync(out, { recursive: true });

const meta = JSON.parse(readFileSync(join(src, 'rulesets.json'), 'utf8'));
for (const rs of meta.rulesets) copyFileSync(join(src, `rules_${rs.id}.json`), join(out, `rules_${rs.id}.json`));
copyFileSync(join(src, 'rulesets.json'), join(out, 'rulesets.json'));
copyFileSync(join(src, 'cosmetic.json'), join(out, 'cosmetic.json'));
// Reputation prefix set (phishing/malware), refreshed at runtime from the lists branch.
const rep = join(src, '..', 'rep', 'prefixes.rice');
if (existsSync(rep)) copyFileSync(rep, join(out, 'rep-prefixes.rice'));
else console.warn('! no dist/rep/prefixes.rice: dangerous-site warnings stay off until the first update');

// ---- generic.css + exclusions ------------------------------------------------
const cos = JSON.parse(readFileSync(join(src, 'cosmetic.json'), 'utf8'));
const generic = new Set(cos.generic);
const excluded = new Set([...cos.generichide, ...cos.elemhide]);
for (const [domain, sels] of Object.entries(cos.exceptions)) {
  if (sels.some(s => generic.has(s))) excluded.add(domain);
}
// Every entry becomes a content-script match pattern; a single invalid one makes
// Chrome reject the whole registration, so refuse to build rather than ship it.
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$/;
const bad = [...excluded].filter(d => !DOMAIN_RE.test(d));
if (bad.length) {
  console.error(`✗ invalid domains in cosmetic opt-outs: ${bad.slice(0, 5).join(', ')}`);
  process.exit(1);
}
const CHUNK = 400;
const sels = [...generic];
let css = '/* NullRoute generic element hiding — generated, do not edit */\n';
for (let i = 0; i < sels.length; i += CHUNK) css += `${sels.slice(i, i + CHUNK).join(',\n')}{display:none!important}\n`;
writeFileSync(join(out, 'generic.css'), css);
writeFileSync(join(out, 'generic-excluded.json'), JSON.stringify([...excluded].sort()));

// ---- scriptlets: one MAIN-world file = library + data -------------------------
const scData = existsSync(join(src, 'scriptlets.json'))
  ? JSON.parse(readFileSync(join(src, 'scriptlets.json'), 'utf8'))
  : { byDomain: {}, disabled: {} };
const scDomains = Object.keys(scData.byDomain).filter(d => DOMAIN_RE.test(d)).sort();
const library = readFileSync(join(ext, 'src', 'scriptlets', 'library.js'), 'utf8');
const scFile = `/* NullRoute scriptlets — generated, do not edit */\n${library}\n` +
  `__nullrouteScriptlets(${JSON.stringify({ byDomain: scData.byDomain, disabled: scData.disabled })});\n`;
writeFileSync(join(out, 'scriptlets-main.js'), scFile);
writeFileSync(join(out, 'scriptlet-domains.json'), JSON.stringify(scDomains));

// ---- manifest consistency ------------------------------------------------------
const manifestPath = join(ext, 'manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const declared = manifest.declarative_net_request.rule_resources.map(r => r.id).sort().join(',');
const compiled = meta.rulesets.map(r => r.id).sort().join(',');
if (declared !== compiled) {
  manifest.declarative_net_request.rule_resources = meta.rulesets.map(rs => ({
    id: rs.id, enabled: rs.enabled, path: `rulesets/rules_${rs.id}.json`,
  }));
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  console.log('• manifest rule_resources updated to match compiled rulesets');
}
for (const rr of manifest.declarative_net_request.rule_resources) {
  const want = meta.rulesets.find(r => r.id === rr.id)?.enabled;
  if (rr.enabled !== want) {
    rr.enabled = want;
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  }
}

const total = meta.rulesets.reduce((a, r) => a + r.rules, 0);
console.log(`✓ ${meta.rulesets.length} rulesets, ${total.toLocaleString()} DNR rules`);
console.log(`✓ generic.css: ${sels.length.toLocaleString()} selectors (${(css.length / 1024).toFixed(0)} KB), ${excluded.size} domains excluded`);
console.log(`✓ scriptlets: ${scDomains.length.toLocaleString()} sites (${(scFile.length / 1024).toFixed(0)} KB)`);
