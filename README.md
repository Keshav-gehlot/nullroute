<h1 align="center">NullRoute</h1>

<p align="center">
  <b>A cross-platform ad, tracker and phishing blocker: a Chrome extension, an Android app and an iOS Safari blocker, all built from one filter-compilation pipeline.</b>
</p>

<p align="center">
  <img alt="Chrome MV3" src="https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white">
  <img alt="Android" src="https://img.shields.io/badge/Android-Kotlin%20%2B%20Compose-3DDC84?logo=android&logoColor=white">
  <img alt="iOS" src="https://img.shields.io/badge/iOS-SwiftUI%20%2B%20Safari-000000?logo=apple&logoColor=white">
  <img alt="Compiler" src="https://img.shields.io/badge/compiler-Python%203-3776AB?logo=python&logoColor=white">
  <img alt="Tests" src="https://img.shields.io/badge/tests-165%20passing-2ea44f">
  <img alt="License" src="https://img.shields.io/badge/license-GPL--3.0-blue">
</p>

NullRoute compiles the community-maintained lists that power uBlock Origin and AdGuard (EasyList, EasyPrivacy, uBlock filters, AdGuard's CNAME-cloaking lists and StevenBlack hosts, about 529,000 lines) into the native, OS-enforced rule format each platform expects. It also turns 2.2 million phishing, scam and malware domains from threat feeds into a **privacy-preserving reputation lookup**: sites are checked on the device, and the rare possible match is confirmed without revealing which site you're visiting.

**Blocking always runs inside the browser or OS engine.** NullRoute never proxies your browsing to a server, never sees page contents and keeps no browsing history on disk.

| Platform | Mechanism | What it blocks |
|---|---|---|
| **Chrome** (MV3) | `declarativeNetRequest` static and dynamic rules, user-origin CSS, MAIN-world scriptlets, content settings, navigation checks | Network requests, CNAME-cloaked trackers, click-ID link tracking, anti-adblock scripts and on-page ad slots; Brave Shields-style per-site controls; **dangerous-site warnings**; and **cross-site trackers no list knows**, caught by the identifiers they collect |
| **Android** | Local `VpnService` DNS sinkhole with **CNAME uncloaking**; opt-in full tunnel with **TLS SNI inspection** | Ad, tracker and **phishing/malware** domains in every app, including disguised trackers; with the full tunnel, also apps that bypass system DNS |
| **iOS / Safari** | Four Safari content-blocker extensions (WebKit rule lists) | Network requests and element hiding in Safari |

<p align="center">
  <img src="docs/popup-advanced.png" width="300" alt="Chrome extension popup with per-site advanced controls">
  &nbsp;
  <img src="docs/picker.png" width="480" alt="Element picker hiding an ad">
</p>
<p align="center">
  <img src="docs/warning.png" width="440" alt="Dangerous site blocked warning page">
  &nbsp;
  <img src="docs/options-crosssite.png" width="400" alt="Cross-site tracker detection settings with one tracker found">
</p>

## Contents

- [Architecture](#architecture)
  - [Compile pipeline](#compile-pipeline)
  - [Chrome: what happens to a request](#chrome-what-happens-to-a-request)
  - [Chrome: per-site settings resolution](#chrome-per-site-settings-resolution)
  - [Android: life of a DNS query](#android-life-of-a-dns-query)
  - [Private reputation lookups](#private-reputation-lookups)
  - [Android: full-tunnel SNI inspection](#android-full-tunnel-sni-inspection)
  - [Chrome: catching cross-site trackers](#chrome-catching-cross-site-trackers)
  - [List updates and integrity](#list-updates-and-integrity)
- [Components](#components)
- [Measured on the real lists](#measured-on-the-real-lists)
- [Testing](#testing)
- [Research-informed design](#research-informed-design)
- [Build and run](#build-and-run)
- [Repository layout](#repository-layout)
- [Distribution](#distribution)
- [Privacy](#privacy)
- [Sources and references](#sources-and-references)
- [Licence](#licence)

---

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="NullRoute architecture: filter lists and threat feeds feed a Python compiler, which emits Chrome DNR rulesets, cosmetic CSS, scriptlets, Safari JSON, a DNS blocklist and a hash-prefix reputation set. These are bundled into the Chrome extension, the Android VpnService and the iOS content blockers. GitHub Actions recompiles daily; the apps download verified updates, and fetch reputation shards only on a local prefix hit." width="100%">
</p>

The system has one build-time half and three run-time halves. The **compiler** is the only place that understands filter syntax. Each platform receives rules already in its engine's native format, so nothing on a device parses a filter list, and every list update is verified against a SHA-256 manifest before use.

### Compile pipeline

```mermaid
flowchart LR
  subgraph S["Filter sources"]
    EL["EasyList"]
    EP["EasyPrivacy"]
    UB["uBlock filters"]
    CN["AdGuard CNAME lists"]
    SB["StevenBlack hosts"]
  end
  subgraph TF["Threat feeds"]
    HZ["HaGeZi TIF"]
    PD["Phishing.Database"]
  end
  S --> P["Parse ABP + uBO syntax<br/>into an IR"]
  P --> F["Fold domain filters<br/>into requestDomains"]
  F --> V{"Validate"}
  V -->|"CSS selectors in Chromium"| V
  V -->|"WebKit regex dialect"| V
  V -->|"canary domains, rule budget"| V
  V --> T1["chrome/<br/>6 DNR rulesets, 14,026 rules"]
  V --> T2["cosmetic/<br/>31k selectors"]
  V --> T3["scriptlets/<br/>2,731 rules"]
  V --> T4["params/<br/>click-ID stripping"]
  V --> T5["safari/<br/>4 WebKit JSON lists"]
  V --> T6["dns/<br/>124k domains + DGA model"]
  TF --> G["Drop canaries and<br/>exact top-10k sites"]
  G --> T7["rep/<br/>3.4 MB prefix set + 4,096 shards"]
  T1 & T2 & T3 & T4 & T5 & T6 & T7 --> R["report.json<br/>counts, skips, SHA-256"]
```

Each source list is marked with the platforms that can use it. AdGuard's 300k cloaked-subdomain list, for example, goes only to Chrome: it's over Safari's cap, and Android uncloaks live instead. Filters that can't be reproduced faithfully on a target (regex filters, `$redirect`, `$csp`, procedural cosmetics) are **skipped and counted**, never approximated, so a compiled rule never blocks more than its source filter intended.

### Chrome: what happens to a request

```mermaid
flowchart TD
  N["Navigation or subresource request"] --> TOP{"Top-level navigation?"}
  TOP -->|yes| REP{"Host or a parent hits the<br/>local reputation prefix set?"}
  REP -->|"yes (rare)"| WARN["Interstitial confirms with one shard:<br/>listed → warning page, else continue"]
  REP -->|no| SD
  TOP -->|no| SD{"Site allowlisted?<br/>(shields down)"}
  SD -->|yes| ALLOW["allowAllRequests, priority 100<br/>overrides every rule below"]
  SD -->|no| QT["queryTransform strips gclid, fbclid,<br/>msclkid and 30 more click IDs"]
  QT --> AG{"Aggressive mode<br/>for this site?"}
  AG -->|"yes, 3rd-party script or frame"| BLK["Blocked, priority 50"]
  AG -->|no| ST{"Matches a static ruleset or a<br/>detected cross-site tracker?"}
  ST -->|"yes, no exception"| BLK2["Blocked by Chrome's engine"]
  ST -->|no| CK{"Cross-site and<br/>cookie blocking on?"}
  CK -->|yes| STRIP["modifyHeaders removes<br/>Cookie and Set-Cookie"]
  CK -->|no| PASS["Request proceeds"]
  STRIP --> PASS
  PASS --> OBS["webRequest observes (never blocks):<br/>feeds the cross-site detector"]
  PASS --> DOC{"Is it a document?"}
  DOC -->|yes| CS["At document_start:<br/>generic hiding CSS (content script)<br/>site CSS via insertCSS, USER origin<br/>uBO scriptlets in the MAIN world<br/>canvas and audio farbling"]
```

The service worker never decides whether a request is blocked; it only writes rules, and Chrome's own matcher evaluates them.

### Chrome: per-site settings resolution

```mermaid
flowchart LR
  G["Global defaults<br/>(options page)"] --> M["Effective settings<br/>for example.com"]
  O["Site override<br/>(popup)<br/>covers subdomains"] -->|"wins per control"| M
  M --> R1["Dynamic DNR rules<br/>aggressive, cookies"]
  M --> R2["contentSettings.javascript<br/>block scripts"]
  M --> R3["registerContentScripts<br/>fingerprint farbling"]
  M --> R4["browsingData.remove<br/>forget on close"]
  SD["Shields down<br/>for the site"] -->|"overrides all four"| M
```

Unknown stored values fall back to the global default, and the options page lists every override with a one-click reset.

### Android: life of a DNS query

```mermaid
flowchart TD
  A["Any app looks up<br/>metrics.shop.com"] --> TUN["VpnService tun<br/>routes only the two virtual DNS IPs<br/>(all traffic in full-tunnel mode)"]
  TUN --> PP["Packet processor<br/>parse IPv4/IPv6, UDP, DNS"]
  PP --> CAN{"use-application-dns.net?"}
  CAN -->|yes| NX["NXDOMAIN<br/>keeps Firefox off DoH"]
  CAN -->|no| UA{"User-allowed?"}
  UA -->|yes| FWD
  UA -->|no| BL{"On blocklist or<br/>user-blocked?"}
  BL -->|yes| SINK["Answer 0.0.0.0 / ::<br/>NODATA for HTTPS/SVCB"]
  BL -->|no| DGA{"DGA bigram score"}
  DGA -->|"below block threshold<br/>and blocking opted in"| SINK
  DGA -->|"suspicious"| FLAG["Mark in Activity, then forward"]
  DGA -->|normal| RP{"Local reputation<br/>prefix hit?"}
  FLAG --> RP
  RP -->|"yes (rare)"| BOTH["Fetch one shard in parallel<br/>with the upstream query"]
  RP -->|no| FWD["Forward via protect()ed socket<br/>match transaction ID, fail over"]
  BOTH --> LISTED{"Listed?"}
  LISTED -->|yes| SINK
  LISTED -->|"no / shard unavailable"| ANS
  FWD --> ANS["Upstream answer"]
  ANS --> CN{"Any CNAME in the chain<br/>points at a tracker?"}
  CN -->|"yes, e.g. shop.eulerian.net"| SINK
  CN -->|no| OK["Answer returned to the app"]
```

Every decision is recorded in an in-memory log with the requesting app (`ConnectivityManager.getConnectionOwnerUid`, Android 10+), so the Activity tab can offer a one-tap allow or block.

### Private reputation lookups

Threat feeds are too large to ship as a blocklist (2.2 million domains) and change within hours. NullRoute compiles them into the two-tier structure Google Safe Browsing's Update API uses:

```mermaid
sequenceDiagram
  participant B as Browser / app
  participant L as Local prefix set (3.4 MB)
  participant S as lists branch (shards)
  B->>B: SHA-256 of host and each parent (a.b.evil.com, b.evil.com, evil.com)
  B->>L: first 32 bits in the set?
  alt no hit (all but ~1 in 700 clean sites)
    L-->>B: clean, nothing leaves the device
  else hit
    B->>S: GET rep/shards/XYZ.bin (first 12 bits only: 1 of 4,096 buckets)
    S-->>B: 64-bit hash heads of every listed domain in that bucket
    B->>B: full match → blocked, no match → clean (prefix coincidence)
  end
```

- **What the server learns:** only that some name hashed into one of 4,096 buckets, and only when its 32-bit prefix already matched a listed domain. A typical bucket holds ~540 listed domains and an unbounded number of clean ones.
- **Stale data still answers correctly.** Shards are always fetched fresh, so a device with yesterday's prefix set still gets today's answer: a domain since removed from the feeds misses in the shard and is allowed.
- **Integrity:** the prefix set is verified against `report.json` like every list. Shards are checked structurally (whole 8-byte entries, strictly sorted, every entry in the requested bucket), because pinning them to a hash manifest from the same origin adds no security and would break whenever the lists move on.
- **Failure is open:** an unreachable or malformed shard allows the site and marks the lookup as unverified, rather than stranding the user.
- **Guards:** canary domains (and anything that would cover them) and exact top-10k sites are dropped from the feeds at build time: 109 such entries, including `bit.ly` and `pastebin.com`.

### Android: full-tunnel SNI inspection

By default only DNS enters the tunnel. Apps that use their own resolver (DNS-over-HTTPS) or hard-coded IPs bypass any DNS filter, so an opt-in "Inspect all connections" mode routes everything:

```mermaid
sequenceDiagram
  participant App
  participant R as FlowRelay (userspace TCP)
  participant Srv as Server
  App->>R: SYN (via tun)
  R->>Srv: connect() on a protect()ed socket
  Srv-->>R: connected
  R-->>App: SYN-ACK
  App->>R: TLS ClientHello (may span segments)
  R->>R: parse SNI (or HTTP Host)
  alt name is blocked
    R-->>App: RST
    R->>Srv: close (server never sees a byte)
  else allowed
    R->>Srv: ClientHello
    Srv-->>R: response
    R-->>App: segments within the app's window, retransmitted on timeout
  end
```

- DNS sent to **any** address (an app's hard-coded `8.8.8.8`) is answered by the filter, from the address the app asked.
- **QUIC (UDP 443) is dropped**, so browsers fall back to TCP where SNI is visible; other UDP is relayed.
- With **Encrypted Client Hello** the SNI is the provider's public name; the parser reports ECH so this is visible rather than silently mis-attributed.
- NullRoute's own traffic is excluded from the tunnel, so list and shard downloads never loop.

### Chrome: catching cross-site trackers

```mermaid
flowchart LR
  REQ["Third-party request that<br/>got past the lists<br/>(pixel, XHR, beacon, frame)"] --> IDS["ID-like query values<br/>(not timestamps, versions,<br/>words, page copies)"]
  IDS --> H["Salted SHA-256<br/>(session storage only)"]
  H --> SEEN{"Same ID reached this<br/>third party from<br/>another site?"}
  SEEN -->|no| KEEP["Remember the site"]
  SEEN -->|yes| FLAG["Flag the third party<br/>(shown in options)"]
  FLAG -->|"if blocking opted in"| DNR["Dynamic DNR rule,<br/>third-party requests only"]
```

A third party that receives the same identifier from two unrelated sites can link your visits between them; that is what being a cross-site tracker means, whatever its name. Scripts, styles, fonts and media are excluded because their query strings carry content hashes that are legitimately identical everywhere.

### List updates and integrity

```mermaid
sequenceDiagram
  participant CI as GitHub Actions (daily)
  participant LB as lists branch
  participant App as Android / iOS app / extension
  CI->>CI: Fetch sources, compile, run canary + budget tests
  CI->>LB: Publish dist/ and report.json (SHA-256 per file)
  App->>LB: GET report.json
  alt version unchanged
    App-->>App: Nothing to do
  else new version
    App->>LB: GET changed list files
    App->>App: Verify SHA-256 and sanity-check contents
    App->>App: Atomic swap (tunnel stays up / blockers reload)
  end
```

A failed test in CI stops the publish, so a list update that would block an essential domain (Google, WhatsApp, UPI/NPCI, banks, Play connectivity checks) never reaches a device.

---

## Components

### 1. Filter compiler — `compiler/` (Python, no runtime dependencies)

- **Parses Adblock Plus syntax**: `||domain^`, anchors, wildcards, `$third-party`, `$domain=`, `$denyallow`, `$important`, `$match-case`, `@@` exceptions, `$document`/`$elemhide`/`$generichide`, and `##` / `#@#` cosmetic filters.
- **Parses uBlock Origin extensions**: `##+js(...)` scriptlets with aliases, escaped arguments, per-site exceptions and `#@#+js()` disables, plus `$removeparam` for link-tracking stripping.
- **Folds domain filters.** Every `||domain^` filter sharing the same options merges into one DNR rule with a `requestDomains` list. About 480,000 network filters and domain entries become **14,026 Chrome rules**, so all six rulesets fit inside Chrome's guaranteed 30,000-rule static budget. The 300,065-line CNAME-cloaking list alone folds into 161 rules.
- **Validates every CSS selector in Chromium** (`CSSStyleSheet.insertRule` via Playwright). One invalid selector in a grouped `a, b, c {}` rule silently disables the whole group, and on Safari it breaks the entire content blocker.
- **Translates ABP patterns to WebKit's regex dialect**, which has no `|` alternation and no `{n,m}`. A validator mirrors WebKit's URL-filter parser.
- **Exports only exact domain filters to DNS**: `||domain^` with no options, plus hosts entries. A filter like `||cdn.site.com^$third-party` is excluded, because a resolver can't know whether a lookup is third-party.
- **Builds the reputation data** (`reputation.py`): SHA-256 prefixes Golomb-Rice coded at 12.4 bits each, plus 4,096 shards; includes a reference client used by the tests.
- **Trains and evaluates the DGA model** (`dga.py`) and **evaluates a tracker classifier** (`trackers.py`, see [research](#could-a-classifier-find-unlisted-trackers)).
- **Writes `report.json`** with per-list counts, skip reasons and the SHA-256 of every list file.

### 2. Chrome extension — `extension/` (Manifest V3)

- **Network blocking** with Chrome's native `declarativeNetRequest` engine: six static rulesets (ads, uBlock, privacy, CNAME, hosts, link tracking), each toggleable from the options page.
- **Generic element hiding**: a static stylesheet registered as a content script at `document_start`, so ad slots never flash on screen. The 651 sites with exceptions get a filtered copy instead.
- **Site-specific element hiding** injected per navigation with `scripting.insertCSS({origin: 'USER'})`, which pages can't detect or override.
- **Scriptlets in the page's MAIN world** at `document_start`, before any page script runs: `abort-on-property-read`/`-write`, `abort-current-script`, `set-constant`, `json-prune`, `addEventListener-defuser`, `no-setTimeout-if`/`no-setInterval-if` and `no-window-open-if`, covering 2,731 rules on 2,077 sites. They follow uBlock Origin's semantics; list arguments are only ever used as property paths and patterns, never evaluated as code.
- **Link-tracking removal.** 33 per-user click identifiers (`gclid`, `fbclid`, `msclkid`, `ttclid`, …) are stripped with DNR `queryTransform` before the request leaves the browser. `utm_*` tags are kept on purpose: they identify a campaign, not a person.
- **CNAME-cloaked trackers.** Chrome gives extensions no DNS API, so AdGuard's pre-resolved list of cloaked first-party subdomains is compiled into rules.
- **Dangerous-site warnings.** `webNavigation.onBeforeNavigate` checks each top-level host against the local prefix set (bundled, then refreshed daily into the Cache API after SHA-256 verification). A hit swaps in an interstitial that confirms with one shard and either continues or shows the warning, with "Back to safety" and a session-scoped "continue anyway".
- **Cross-site tracker detection** (`lib/xsite.js`). `webRequest` observes, never blocks, third-party requests that got past the lists and flags receivers of a cross-site identifier. Blocking them is a separate opt-in that adds one third-party-only DNR rule below every allow rule.
- **Per-site controls modelled on Brave Shields.** Every site uses the global defaults unless you change it from the popup. Site changes win, cover subdomains, and are listed with a one-click reset.

  | Control | Implementation |
  |---|---|
  | Trackers & ads: *Aggressive* | One dynamic DNR rule blocking all third-party scripts and frames on the site (uBlock Origin's "medium mode"), priority 50: above list exceptions, below shields down |
  | Block scripts | `chrome.contentSettings.javascript`, which also stops inline scripts and event handlers. DNR alone can only block script files |
  | Block cross-site cookies | DNR `modifyHeaders` strips `Cookie` from third-party requests and `Set-Cookie` from their responses. First-party visits keep their cookies |
  | Block fingerprinting (on by default) | Per-page noise for canvas (`toDataURL`, `toBlob`, `getImageData`) and Web Audio readback, plus a plausible CPU count. Noise is a pure function of a per-page seed and the content, so drawing the same canvas twice gives identical results; per-call random noise is easy to detect. Wrappers are Proxies, so `toString()` still says `[native code]` |
  | Forget site data | `browsingData.remove` for cookies, storage, IndexedDB, caches and service workers, on demand or when the site's last tab closes. Tab-to-site mapping lives in `chrome.storage.session`, so it survives service-worker restarts |
  | Shields down | Priority 100 `allowAllRequests`, which overrides every other control, including script blocking and fingerprint protection |
- **Popup:** per-site switch, live per-category counts (ads, trackers, bad hosts, link tracking, my filters), the advanced controls and "Pause everywhere".
- **Element picker:** hover, click and press Enter to hide anything. Its UI lives in a closed shadow DOM, and auto-generated-looking selectors (hashes, CSS-in-JS) are avoided so rules survive site rebuilds.
- **Options page:** global defaults, site overrides, list toggles that surface Chrome's rule-budget errors, dangerous-site and cross-site settings, an allowed-sites list, and custom filters in a safe ABP subset.

### 3. Android app — `android/` (Kotlin + Jetpack Compose)

- **Split-tunnel DNS sinkhole.** By default the VPN routes only two virtual addresses (one IPv4, one IPv6 DNS server). All other traffic uses the normal network at full speed, so battery cost is negligible.
- **CNAME uncloaking.** Every allowed answer is inspected; if any alias in the chain points at a tracker, the app gets a sinkhole answer instead. `metrics.shop.com` → `shop.eulerian.net` is blocked even though `metrics.shop.com` is on no list. The compression-aware parser has a hop limit, so a malicious pointer loop can't hang the resolver.
- **Phishing and malware protection** (on by default). Names no list or user rule has decided are checked against the reputation prefix set in memory; a hit fetches one shard *in parallel* with the upstream query, so clean names pay nothing and even hits add almost no latency.
- **Opt-in full tunnel with SNI inspection** (`FlowRelay`). A userspace TCP stack (in-order delivery, flow control against the app's window, go-back-N retransmission, orderly close) re-originates every connection from a protected socket and refuses ones whose TLS SNI or HTTP Host is blocked. DNS to any address is filtered; QUIC is dropped.
- **Unlisted machine-generated domains.** A character-bigram model marks suspicious lookups in Activity. Blocking them is opt-in (see [Zero-day domains](#zero-day-domains-entropy-vs-a-bigram-model)).
- **Firefox DoH canary.** `use-application-dns.net` gets NXDOMAIN, which tells Firefox to keep using system DNS so its lookups stay filtered.
- **Sinkhole answers.** Blocked names get `0.0.0.0` / `::` immediately; HTTPS and SVCB records get NODATA. Replies are matched by transaction ID, so spoofed answers are dropped; if one resolver fails the next is tried.
- **Pure-Kotlin engine** (`android/core`): IPv4/IPv6/UDP/TCP parsing, RFC 1071 checksums, DNS encoding, suffix matching, the DGA detector, the reputation client, the TLS SNI parser and the TCP relay, with **no Android dependencies**, so it's unit-tested on the JVM with real sockets.
- **Per-app attribution**, excluded apps (for banking apps that break), a choice of resolver (network default, Cloudflare, Quad9, Google), a Quick Settings tile, Always-on VPN support and restore after reboot.
- **Verified list updates** daily on Wi-Fi, with SHA-256 checks against `report.json` and an atomic swap that keeps the tunnel up.
- **Private DNS detection.** Warns when Android's Private DNS is in strict mode, which would silently bypass any DNS filter.

### 4. iOS app — `ios/` (SwiftUI)

- **Four Safari content blockers**, each under WebKit's 150,000-rule cap: Ads 92,621 · Trackers 103,588 · Bad hosts 41,530 · Element hiding 7,826.
- **Host app** shows which blockers are enabled, manages allowed sites and installs verified list updates through a shared App Group. Allowed sites are applied by appending one `ignore-previous-rules` rule to each list through byte-splicing, so the 20 MB lists are never parsed on the device.
- Reputation lookups and SNI inspection don't apply: Safari content blockers are declarative and can't make network requests, and inspecting connections would need a Network Extension packet tunnel.

---

## Measured on the real lists

| | |
|---|---|
| Source lines parsed | ~529,000 filter lines + ~2.46M threat-feed lines |
| Chrome DNR rules (6 rulesets) | **14,026** (budget: 30,000 guaranteed) |
| CNAME-cloaked subdomains | 300,065 lines folded into **161** rules |
| Scriptlets | 2,731 rules on 2,077 sites |
| Cosmetic selectors | 13,677 generic + 17,524 site-specific |
| DNS blocklist | 124,277 domains after subdomain minimisation, plus 98 CNAME targets |
| Safari rule lists | 92,621 · 103,588 · 41,530 · 7,826 (cap: 150,000 each) |
| Reputation | 2,218,977 domains → **3.4 MB** prefix set (12.4 bits each) + 4,096 shards of ~540 entries |
| Reputation privacy | ~1 in 700 clean names cause a shard request (5.2 × 10⁻⁴ per hashed name); the rest never leave the device |
| Android matcher | ~13 MB heap, **~230 ns per lookup** (JVM benchmark) |
| DGA detector | 35.3% of DGA domains blocked at 0.14% false positives |
| Full compile | ~45 s (including the threat feeds) |

Figures are from the build on 1 November 2026; the lists change daily.

## Testing

| Suite | Tests | What it proves |
|---|---|---|
| `compiler/tests` | 73 | ABP parsing edge cases, rule folding, Safari regex semantics checked against real URLs, WebKit dialect validation, canary domains, Chrome budget, `report.json` hashes, DGA model; reputation: Rice coding round trips, feed guards, a reference client that finds real phishing entries and their subdomains, prefix collisions cleared by the shard, and that no canary is listed |
| `extension/tests/*.test.mjs` | 16 (Node) | Per-site settings model and DNR rule generation; the JS reputation client against the shipped data (clean sites almost never contact the server, broken shards fail open); cross-site detector: identifier shapes, benign values skipped, flags only on two different sites, and persisted state holds only salted hashes |
| `extension/tests/test_e2e.py` | 23 (Chromium) | Loads the real extension, maps every hostname to local HTTP and HTTPS servers with `--host-resolver-rules`, and checks **which requests actually left the browser**: every list, CNAME-cloaked subdomains, click-ID stripping, uBlock scriptlets running before page scripts, cosmetic hiding, allowlisting, custom filters, pause, per-list toggles, the element picker, Chrome's `isRegexSupported` on every regex rule, and all per-site controls. **Reputation**: a tampered update is refused, a listed site gets the warning, the only server request is a 12-bit bucket, "continue" works, a prefix collision is cleared and loads, a clean site makes no request. **Cross-site**: a pixel receiving one ID from two sites is flagged but not blocked until opted in, a third party with per-site IDs is never flagged |
| `android/core` | 53 (JUnit) | Packets from **scapy** and **dnslib** parse correctly; CNAME uncloaking and pointer loops; **real UDP forwarding** with spoofed-ID rejection and failover; the DGA detector reproduces Python's scores; the Kotlin reputation client decodes the shipped prefix set, finds real feed entries, sinkholes a phishing domain end to end while a clean name resolves, and fails open on truncated or wrong-bucket shards; the SNI parser reads **real ClientHellos from the JDK's TLS stack** at every split point and across two records; the TCP relay carries a 300 KB response through real sockets with flow control, resets a blocked SNI before the server sees a byte, blocks by HTTP Host, retransmits a missed segment, resets refused and unknown connections, relays UDP and drops QUIC; hard-coded resolvers are filtered only in full-tunnel mode |

CI (`.github/workflows/ci.yml`) runs all of these, and also builds the Android APK with lint and the iOS app for the simulator.

---

## Research-informed design

Design decisions trace back to the measurement and systems literature on ad blocking. Bracketed references point to [Sources and references](#sources-and-references).

### Applied

| Finding | What NullRoute does |
|---|---|
| CNAME cloaking hides trackers behind first-party subdomains, on about 10% of the top 10k sites [R1]. Chrome extensions can't resolve DNS to unmask them. | Android uncloaks every answer's CNAME chain. Chrome ships AdGuard's pre-resolved cloaked subdomains as folded DNR rules [D3]. |
| Click IDs in links smuggle user identifiers past cookie partitioning [R2, R3]. | DNR `queryTransform` strips 33 click-ID parameters, plus `$removeparam` filters, before navigation. The same insight powers cross-site tracker detection: an identifier arriving from two sites is the tracking. |
| Anti-adblock and ad logic moved into first-party bundles and inline JSON, where URL blocking breaks the site [R4, R5]. | MAIN-world scriptlets compiled from uBlock filters neutralise the specific property or call instead of the whole script. |
| Most list rules are dead weight and list growth has a real cost [R6]. | Rules are folded and budget-checked at build time; the device never parses a list. |
| Encrypted DNS silently bypasses DNS filters [P11]. | The Firefox canary keeps Firefox on system DNS, the app warns about strict Private DNS, and full-tunnel mode filters hard-coded resolvers and DoH endpoints by SNI. |
| MV3 rule budgets are the central constraint (30k guaranteed static, 1,000 regex, 2 KB per regex) [P1]. | Domain folding, a build-time budget check, and an e2e test that runs Chrome's `isRegexSupported` on every regex rule. |
| Breakage makes users turn blockers off entirely [R7]. | One-tap per-site allowlist, per-list toggles, a per-lookup "Always allow" on Android, and every new detector (DGA, cross-site) flags by default and blocks only when opted in. |
| Per-call random canvas noise is itself a fingerprint [R8]. | Farbling is deterministic per page seed and content, modelled on Brave's approach [P10]. |
| Reputation lookups can be private: hashed prefixes locally, full hashes only on a hit [P12]. | The same two-tier design for 2.2M threat-feed domains, with shards keyed by 12 bits. |

One claim was checked rather than copied. A survey cited a 50,000-rule cap per Safari content blocker; that figure predates Safari 15. The current limit is 150,000 [P9], which the iOS blockers are sized for.

### Brave Shields' controls, mapped to what an extension can do

| Brave Shields control | NullRoute |
|---|---|
| Trackers & ads (Standard / Aggressive / Allow all) | Lists; per-site aggressive rule; per-site shields down |
| Block scripts | `contentSettings.javascript`, per site or global [P3] |
| Block cookies | DNR `modifyHeaders` cross-site `Cookie` / `Set-Cookie` stripping |
| Block fingerprinting | MAIN-world canvas and audio farbling, consistent within a page |
| Shred site's data (+ on close) | `browsingData.remove` by origin, manually or when the last tab closes [P4] |
| Block element | Element picker |
| Global settings | Options page "Defaults for every site", with a list of site overrides |
| Upgrade connections to HTTPS | **Left to Chrome.** Chrome upgrades navigations natively *with* HTTP fallback [P5]; a DNR `upgradeScheme` rule has no fallback and would break HTTP-only sites. |

On mobile, the Android app's per-app exclusions play the role of per-site overrides (DNS has no notion of the page you're on). Safari already blocks cross-site cookies by default, and its content blockers can't run scripts, so the remaining controls don't apply there.

### Zero-day domains: entropy vs a bigram model

A proposal suggested sinkholing any unlisted domain whose Shannon entropy exceeds 4.15. It was measured on a labelled dataset before anything was built: 25 DGA malware families plus benign domains, 675k names, used only for evaluation [D6].

| Detector | DGA domains caught | Legitimate domains wrongly flagged |
|---|---|---|
| Entropy > 4.15 (as proposed) | 3.7% | 0.13% |
| Entropy > 3.5 | 51.8% | 30.0% |
| **NullRoute bigram model, block threshold** | **35.3%** | **0.14%** |
| **NullRoute bigram model, flag threshold** | **53.6%** | **0.53%** |

Entropy fails because an *n*-character string can never exceed log₂(*n*) bits: a 13-character DGA label tops out at 3.70, so the 4.15 threshold almost never fires, and lowering it flags real sites by the thousand. NullRoute instead scores how much the **registrant's label** looks like real domain names, using a character-bigram model trained on a public top-1M list [D5] and calibrated on held-out names. `d1a2b3.cloudfront.net` and `r4---sn-x.googlevideo.com` are judged as `cloudfront` / `googlevideo`. At the same false-positive rate it catches about 10× more than entropy, and 77–100% of random-character families. Dictionary-word DGAs (suppobox, matsnu, gozi) look like English and stay out of reach of any character model; that's reported rather than hidden.

On Android, suspicious names are **marked in Activity by default and never blocked** unless you opt in. `python -m nullroute_compiler.dga evaluate` reproduces the table.

The proposal's other real-time ideas, each built in a form that keeps NullRoute's privacy model:

- **Cloud reputation lookups** → [private reputation lookups](#private-reputation-lookups): nothing leaves the device for ~699 of 700 clean sites, and a hit reveals only a 12-bit bucket.
- **TLS SNI inspection** → [opt-in full tunnel](#android-full-tunnel-sni-inspection). It costs battery and throughput, so DNS-only stays the default; with ECH the SNI is the provider's public name, which the parser reports.
- **On-device classifiers** → evaluated first, below.

### Could a classifier find unlisted trackers?

AdGraph, WebGraph and AdFlush [R9–R11] classify trackers by behaviour. Before shipping one, `python -m nullroute_compiler.trackers` evaluated the idea on DuckDuckGo's Tracker Radar [D7]: 5,012 labelled third-party domains, each with the browser APIs its scripts call, its request-type mix, cookie use and reach, using features an extension can observe at runtime. Results are in [`docs/tracker-classifier.json`](docs/tracker-classifier.json):

| Features | Random split: ROC AUC | **Companies held out: ROC AUC** | Recall on trackers the lists miss, 1% FPR (held out) |
|---|---|---|---|
| Script API use + request types + cookies | 0.835 | **0.459** | 3.3% |
| + reach (sites, fingerprinting score) | 0.873 | **0.494** | 6.7% |
| Name tokens ("pixel", "collect", …) | 0.821 | **0.314** | 1.1% |
| All of the above | 0.904 | **0.443** | 5.3% |

A random split looks good, but it's leakage: the model memorises which companies' infrastructure is which. When no company appears in both training and test data, which is the real situation for a tracker nobody has listed, every feature set is at chance or worse. 98% of the benign domains are CDNs, which call the same APIs and are embedded as widely as trackers. So NullRoute ships **no learned blocker**. Instead it detects the one property that defines cross-site tracking regardless of behaviour profile: [the same identifier arriving from two sites](#chrome-catching-cross-site-trackers). Graph classifiers that see full page context [R9, R10] need browser forks; perceptual ones are vulnerable to adversarial perturbation [R12, R13].

### Deliberately not applied

- **YouTube video ads.** YouTube's SABR streaming protocol enforces a server-side backoff when ad placements are stripped client-side, so json-prune-style blocking now produces "fake buffering". NullRoute makes no YouTube video-ad claim.
- **Differential list updates.** CI rebuilds daily and the apps download only when the version changes. Diff patches would cut bandwidth but aren't needed at this size.

---

## Build and run

Requirements (as tested in CI): Python 3.12, Node 22, and for tests `pip install pytest playwright` plus `openssl`. Android needs JDK 17 and the Android SDK; iOS needs Xcode and [XcodeGen](https://github.com/yonaskolb/XcodeGen). The classifier evaluation additionally needs `numpy` and `scikit-learn` and a checkout of Tracker Radar.

```bash
make lists        # fetch + compile every list and threat feed into dist/
make test         # compiler tests + Chrome unit and e2e tests
```

**Chrome:** run `make extension`, open `chrome://extensions`, enable Developer mode, click **Load unpacked** and choose `extension/`.

**Android:** run `make lists`, then open `android/` in Android Studio or run `./gradlew :app:assembleDebug`. Install the APK, tap **Turn on** and accept the VPN prompt. For protection that survives reboots, enable Always-on VPN for NullRoute in Settings › Network & internet › VPN. "Inspect all connections" is under Settings › Advanced.

**iOS:** run `make lists && brew install xcodegen && make ios`, open `ios/NullRoute.xcodeproj`, set your team and run. Then enable the four NullRoute blockers in Settings › Apps › Safari › Extensions.

## Repository layout

```text
nullroute/
├── compiler/                  Python filter compiler (no runtime deps)
│   ├── nullroute_compiler/
│   │   ├── abp.py             ABP + uBO parser → IR
│   │   ├── domains.py         domain normalisation and folding
│   │   ├── validate.py        Chromium CSS + WebKit regex validators
│   │   ├── reputation.py      hash-prefix set, shards, Rice coding, reference client
│   │   ├── dga.py             bigram model: train / evaluate / export
│   │   ├── trackers.py        tracker-classifier evaluation (Tracker Radar)
│   │   └── targets/           chrome · cosmetic · scriptlets · params · safari · dns
│   ├── data/                  canaries, DGA model
│   ├── sources.json           list + feed URLs and per-platform targets
│   └── tests/
├── extension/                 Chrome MV3 extension
│   ├── src/background.js      service worker
│   ├── src/lib/               shields · reputation · xsite · userfilters · cosmetic · domains
│   ├── src/warning.*          dangerous-site interstitial
│   ├── src/scriptlets/        uBO-compatible scriptlet library
│   ├── src/shields/farble.js  canvas / audio farbling
│   └── tests/                 Node unit + Chromium e2e
├── android/
│   ├── core/                  pure-Kotlin packets, DNS, matcher, DGA, reputation, SNI, TCP relay
│   └── app/                   VpnService, Compose UI, list updates
├── ios/                       XcodeGen project, SwiftUI app, 4 content blockers
├── .github/workflows/         ci · lists (daily) · release
└── docs/                      architecture.svg, screenshots, classifier results
```

## Distribution

- **Chrome Web Store:** MV3 with `declarativeNetRequest` is the store-approved model for blockers. `webRequest` is used for observation only.
- **Android:** Google Play prohibits apps that block ads in other apps, including through `VpnService` filtering [P8]. The APK ships through GitHub Releases (`release.yml` attaches a signed build to every tag) or F-Droid, as Blokada and DNS66 do.
- **iOS App Store:** Safari content blockers are an Apple-supported extension type [P9].

## Privacy

- The Chrome extension never decides blocking from request URLs; Chrome's engine evaluates the rules. The cross-site detector reads third-party query strings in memory and keeps only salted hashes, in session storage that Chrome clears on exit.
- Reputation checks happen on the device. A request leaves only on a local prefix hit (about 1 in 700 clean sites), and it names one of 4,096 hash buckets, never the site.
- On Android, the query log lives only in memory, is cleared each session and is never written to disk. Only blocked-request counts are stored. Full-tunnel mode inspects only the first bytes of each connection (the ClientHello or HTTP headers) and forwards everything else untouched; it never decrypts TLS.
- On iOS, Safari compiles and enforces the rules. The extensions never see browsing data.
- No analytics, no accounts, no servers. Every network call NullRoute makes goes to this repository's `lists` branch.

---

## Sources and references

### Research

| # | Reference | Used for |
|---|---|---|
| R1 | Dimova, Acar, Olejnik, Joosen, Van Goethem. [*The CNAME of the Game: Large-scale Analysis of DNS-based Tracking Evasion*](https://petsymposium.org/popets/2021/popets-2021-0053.php). PoPETs 2021. ([arXiv](https://arxiv.org/abs/2102.09301)) | CNAME uncloaking on Android, cloaked-subdomain rules on Chrome |
| R2 | Randall et al. [*Measuring UID Smuggling in the Wild*](https://www.sysnet.ucsd.edu/~voelker/pubs/uid-smuggle-imc22.pdf). IMC 2022. | Click-ID stripping; the same-ID-across-sites test behind cross-site tracker detection |
| R3 | Munir et al. [*PURL: Safe and Effective Sanitization of Link Decoration*](https://www.usenix.org/system/files/usenixsecurity24-munir.pdf). USENIX Security 2024. ([arXiv](https://arxiv.org/abs/2308.03417)) | Which parameters to strip, why `utm_*` is kept, identifier-like values |
| R4 | Smith, Snyder, Livshits, Stefan. [*SugarCoat: Programmatically Generating Privacy-Preserving, Web-Compatible Resource Replacements*](https://www.doc.ic.ac.uk/~livshits/papers/pdf/ccs21.pdf). CCS 2021. | Neutralising scripts instead of blocking them |
| R5 | Iqbal, Shafiq, Qian. [*The Ad Wars: Retrospective Measurement and Analysis of Anti-Adblock Filter Lists*](https://par.nsf.gov/biblio/10073730). IMC 2017. | Anti-adblock scriptlets |
| R6 | Snyder, Vastel, Livshits. [*Who Filters the Filters: Understanding the Growth, Usefulness and Efficiency of Crowdsourced Ad Blocking*](https://arxiv.org/abs/1810.09160). SIGMETRICS 2020. | Rule folding, build-time budgets |
| R7 | Nisenoff et al. [*User Experiences and Remediation Tactics When Ad-Blocking or Tracking-Protection Tools Break Websites*](https://www.usenix.org/conference/usenixsecurity23/presentation/nisenoff-broken). USENIX Security 2023. | One-tap allowlisting, flag-before-block defaults |
| R8 | [Canvas fingerprinting randomization study](https://cseweb.ucsd.edu/~savage/papers/IMC25Canvas.pdf). IMC 2025. | Deterministic, per-page farbling |
| R9 | Iqbal et al. [*AdGraph: A Graph-Based Approach to Ad and Tracker Blocking*](https://arxiv.org/abs/1805.09155). IEEE S&P 2020. | Classifier approach evaluated |
| R10 | Siby et al. [*WebGraph: Capturing Advertising and Tracking Information Flows for Robust Blocking*](https://www.usenix.org/conference/usenixsecurity22/presentation/siby). USENIX Security 2022. | Classifier approach evaluated |
| R11 | [*AdFlush: A Real-World Deployable Machine Learning Solution for Effective Advertisement and Web Tracker Prediction*](https://doi.org/10.1145/3589334.3645698). WWW 2024. ([code](https://github.com/0xk1h0/AdFlush)) | Classifier approach evaluated |
| R12 | Tramèr, Dupré, Rusak, Pellegrino, Boneh. [*AdVersarial: Perceptual Ad Blocking meets Adversarial Machine Learning*](https://arxiv.org/abs/1811.03194). CCS 2019. | Why perceptual blocking was not built |
| R13 | Zhu et al. [*A4: Evading Learning-based Adblockers*](https://arxiv.org/abs/2001.10999). | Adversarial evasion of ML blockers |
| R14 | Cucchiarelli, Morbidoni, Spalazzi, Baldi. [*Algorithmically generated malicious domain names detection based on n-grams features*](https://doi.org/10.1016/j.eswa.2020.114551). Expert Systems with Applications, 2021. | DGA evaluation dataset and n-gram approach |

### Platform documentation

| # | Reference |
|---|---|
| P1 | Chrome: [`chrome.declarativeNetRequest`](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) (rule limits, `requestDomains`, `queryTransform`, `modifyHeaders`, `allowAllRequests`) |
| P2 | Chrome: [`chrome.scripting`](https://developer.chrome.com/docs/extensions/reference/api/scripting), [`chrome.webNavigation`](https://developer.chrome.com/docs/extensions/reference/api/webNavigation) and [`chrome.webRequest`](https://developer.chrome.com/docs/extensions/reference/api/webRequest) |
| P3 | Chrome: [`chrome.contentSettings`](https://developer.chrome.com/docs/extensions/reference/api/contentSettings) |
| P4 | Chrome: [`chrome.browsingData`](https://developer.chrome.com/docs/extensions/reference/api/browsingData), [`chrome.storage`](https://developer.chrome.com/docs/extensions/reference/api/storage) and [`chrome.alarms`](https://developer.chrome.com/docs/extensions/reference/api/alarms) |
| P5 | Chromium Blog: [*Towards HTTPS by default*](https://blog.chromium.org/2023/08/towards-https-by-default.html) (2023) |
| P6 | Android: [`VpnService`](https://developer.android.com/reference/android/net/VpnService) (including `protect()` and `addDisallowedApplication`) and [`ConnectivityManager.getConnectionOwnerUid`](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress)) |
| P7 | Android 14: [Foreground service types are required](https://developer.android.com/about/versions/14/changes/fgs-types-required) |
| P8 | The Register: [*Google Play changes VPN rules*](https://www.theregister.com/2022/08/30/google_play_vpn_rules_changed/) (2022) |
| P9 | Apple: [*Creating a content blocker*](https://developer.apple.com/documentation/safariservices/creating-a-content-blocker); AdGuard KB: [Safari rule limit](https://adguard.com/kb/adguard-for-safari/solving-problems/rule-limit/) (150k per blocker) |
| P10 | Brave: [*Fingerprinting defenses 2.0*](https://brave.com/privacy-updates/4-fingerprinting-defenses-2.0/) (farbling) |
| P11 | Mozilla: [*Canary domain – use-application-dns.net*](https://support.mozilla.org/kb/canary-domain-use-application-dnsnet) |
| P12 | Google: [Safe Browsing Update API](https://developers.google.com/safe-browsing/v4/update-api) (hashed prefixes, full hashes on a hit, Rice-coded prefix sets) |
| P13 | uBlock Origin wiki: [Static filter syntax](https://github.com/gorhill/uBlock/wiki/Static-filter-syntax) and [Resources library (scriptlets)](https://github.com/gorhill/uBlock/wiki/Resources-Library); Adblock Plus: [How to write filters](https://help.adblockplus.org/hc/en-us/articles/360062733293) |
| P14 | [NetGuard](https://github.com/M66B/NetGuard): the no-root userspace TCP relay design for Android firewalls |

### Protocol specifications

- [RFC 768](https://www.rfc-editor.org/rfc/rfc768) – User Datagram Protocol
- [RFC 791](https://www.rfc-editor.org/rfc/rfc791) – Internet Protocol (IPv4)
- [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) – Internet Protocol, Version 6
- [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) – Transmission Control Protocol
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) – Domain Names: Implementation and Specification (including name compression)
- [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071) – Computing the Internet Checksum
- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) – SVCB and HTTPS resource records
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) – TLS 1.3 (ClientHello) and [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) – TLS extensions, including Server Name Indication
- [TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/) – IETF TLS working group

### Filter lists, threat feeds and datasets

| # | Source | Licence |
|---|---|---|
| D1 | [EasyList and EasyPrivacy](https://easylist.to/) ([GitHub](https://github.com/easylist/easylist)) | GPLv3 / CC BY-SA 3.0 |
| D2 | [uBlock Origin filters (uAssets)](https://github.com/uBlockOrigin/uAssets) | GPLv3 |
| D3 | [AdGuard CNAME trackers](https://github.com/AdguardTeam/cname-trackers) | MIT |
| D4 | [StevenBlack hosts](https://github.com/StevenBlack/hosts) | MIT |
| D5 | [Top 1,000,000 domains](https://github.com/zer0h/top-1000000-domains) (bigram training; top-10k feed guard) | — |
| D6 | [DGA domains dataset](https://github.com/chrmor/DGA_domains_dataset) from R14 (evaluation only, not shipped) | — |
| D7 | [DuckDuckGo Tracker Radar](https://github.com/duckduckgo/tracker-radar) (classifier evaluation only, not shipped) | CC BY-NC-SA 4.0 |
| D8 | [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (reputation) | GPLv3 |
| D9 | [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (reputation) | MIT |

### Tools

[Playwright](https://playwright.dev/) (selector validation, e2e tests) · [scapy](https://scapy.net/) and [dnslib](https://github.com/paulc/dnslib) (independent packet fixtures) · [scikit-learn](https://scikit-learn.org/) (classifier evaluation) · [XcodeGen](https://github.com/yonaskolb/XcodeGen) · [Jetpack Compose](https://developer.android.com/develop/ui/compose)

## Licence

GPL-3.0. Filter lists and feeds keep their own licences (table above): EasyList and EasyPrivacy © The EasyList authors, uBlock filters © Raymond Hill and contributors, AdGuard CNAME trackers © AdGuard, StevenBlack hosts © Steven Black, HaGeZi TIF © HaGeZi, Phishing.Database © Mitchell Krog. Tracker Radar data is used only to produce the evaluation numbers and is not redistributed. Scriptlet behaviour follows uBlock Origin's documented semantics; the implementation is original.
