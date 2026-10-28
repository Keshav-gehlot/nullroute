"""Parser for Adblock Plus / EasyList filter syntax and hosts-file lists.

Produces a platform-neutral intermediate representation (IR) that the
per-platform targets (Chrome DNR, Safari content blocker, DNS blocklist)
translate into their native formats.

Only the subset of syntax that can be enforced faithfully on every target
is accepted. Anything else (regex filters, scriptlets, procedural cosmetic
filters, $redirect, $csp, ...) is counted and skipped, never approximated,
so a compiled rule never blocks more than its source filter intended.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# ABP resource-type option -> canonical type name used in the IR.
# The canonical names are Chrome DNR's ResourceType values.
RESOURCE_TYPES = {
    "script": "script",
    "image": "image",
    "stylesheet": "stylesheet",
    "css": "stylesheet",
    "object": "object",
    "xmlhttprequest": "xmlhttprequest",
    "xhr": "xmlhttprequest",
    "subdocument": "sub_frame",
    "frame": "sub_frame",
    "ping": "ping",
    "beacon": "ping",
    "media": "media",
    "font": "font",
    "websocket": "websocket",
    "other": "other",
}

# Options we understand but which carry no enforcement meaning for us.
IGNORED_OPTIONS = {"match-case"}  # handled separately; listed for clarity

# Options that change semantics in ways we cannot reproduce on all targets.
UNSUPPORTED_OPTIONS = {
    "popup", "csp", "redirect", "redirect-rule", "queryprune",
    "rewrite", "header", "sitekey", "webrtc", "permissions", "replace",
    "cookie", "genericblock", "badfilter", "empty", "mp4", "inline-script",
    "inline-font", "urltransform", "uritransform", "method", "to", "from",
    "strict1p", "strict3p", "all", "ipaddress",
    "requestheader", "responseheader", "stealth", "jsonprune", "hls",
    "urlskip", "reason", "ehide", "shide", "ghide", "doc",
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})*$")
HOSTS_LINE_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+([^\s#]+)")
HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost",
              "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
              "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}


def is_valid_domain(d: str) -> bool:
    return bool(DOMAIN_RE.match(d)) and "." in d and not d.replace(".", "").isdigit()


@dataclass(frozen=True)
class NetworkFilter:
    """A URL-blocking (or allowing) filter."""
    pattern: str                       # ABP pattern ('' = match everything)
    exception: bool = False            # @@ rule
    important: bool = False
    match_case: bool = False
    resource_types: frozenset[str] = frozenset()        # empty = default set
    excluded_resource_types: frozenset[str] = frozenset()
    party: str | None = None           # 'third' | 'first' | None
    include_domains: frozenset[str] = frozenset()       # initiator domains
    exclude_domains: frozenset[str] = frozenset()
    exclude_request_domains: frozenset[str] = frozenset()  # $denyallow
    document: bool = False             # @@...$document (allow whole page)
    elemhide: bool = False             # @@...$elemhide
    generichide: bool = False          # @@...$generichide
    removeparam: str | None = None     # $removeparam=name (plain names only)
    source: str = ""

    @property
    def pure_domain(self) -> str | None:
        """If the pattern is exactly ``||domain^``, return the domain."""
        p = self.pattern
        if p.startswith("||") and p.endswith("^"):
            d = p[2:-1]
            if is_valid_domain(d):
                return d
        return None

    @property
    def has_modifiers(self) -> bool:
        return bool(self.resource_types or self.excluded_resource_types or self.party
                    or self.include_domains or self.exclude_domains
                    or self.exclude_request_domains or self.match_case
                    or self.important or self.document or self.elemhide
                    or self.generichide or self.removeparam is not None)


@dataclass(frozen=True)
class CosmeticFilter:
    """An element-hiding filter (##selector) or its exception (#@#)."""
    selector: str
    exception: bool = False
    include_domains: frozenset[str] = frozenset()
    exclude_domains: frozenset[str] = frozenset()
    source: str = ""

    @property
    def generic(self) -> bool:
        return not self.include_domains


# uBO scriptlet names and aliases -> canonical name. Only scriptlets that
# NullRoute implements are accepted; everything else is skipped.
SCRIPTLET_ALIASES = {
    "abort-on-property-read": "abort-on-property-read", "aopr": "abort-on-property-read",
    "abort-on-property-write": "abort-on-property-write", "aopw": "abort-on-property-write",
    "abort-current-script": "abort-current-script", "acs": "abort-current-script",
    "abort-current-inline-script": "abort-current-script", "acis": "abort-current-script",
    "set-constant": "set-constant", "set": "set-constant",
    "addEventListener-defuser": "addEventListener-defuser", "aeld": "addEventListener-defuser",
    "no-setTimeout-if": "no-setTimeout-if", "nostif": "no-setTimeout-if",
    "prevent-setTimeout": "no-setTimeout-if",
    "no-setInterval-if": "no-setInterval-if", "nosiif": "no-setInterval-if",
    "prevent-setInterval": "no-setInterval-if",
    "no-window-open-if": "no-window-open-if", "nowoif": "no-window-open-if",
    "prevent-window-open": "no-window-open-if",
    "json-prune": "json-prune",
}


@dataclass(frozen=True)
class ScriptletFilter:
    """A ``domain##+js(name, args...)`` filter, run in the page's MAIN world."""
    name: str                          # canonical scriptlet name
    args: tuple[str, ...]
    exception: bool = False
    include_domains: frozenset[str] = frozenset()
    exclude_domains: frozenset[str] = frozenset()
    source: str = ""


@dataclass
class ParseResult:
    network: list[NetworkFilter] = field(default_factory=list)
    cosmetic: list[CosmeticFilter] = field(default_factory=list)
    scriptlets: list[ScriptletFilter] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    skipped: Counter = field(default_factory=Counter)
    total_lines: int = 0

    def extend(self, other: "ParseResult") -> None:
        self.network.extend(other.network)
        self.cosmetic.extend(other.cosmetic)
        self.scriptlets.extend(other.scriptlets)
        self.hosts |= other.hosts
        self.skipped.update(other.skipped)
        self.total_lines += other.total_lines


# --------------------------------------------------------------------------
# Cosmetic filters
# --------------------------------------------------------------------------
# Procedural / extended syntax we refuse (cannot be expressed as plain CSS).
_EXTENDED_CSS = re.compile(
    r":(?:-abp-|has-text|contains|xpath|upward|remove|style|matches-css|"
    r"matches-attr|matches-path|matches-media|min-text-length|watch-attr|"
    r"others|if|if-not|nth-ancestor|properties|-ext-)",
    re.I,
)


def _split_domains(spec: str, sep: str) -> tuple[frozenset[str], frozenset[str]] | None:
    inc, exc = set(), set()
    for raw in spec.split(sep):
        raw = raw.strip().lower()
        if not raw:
            continue
        neg = raw.startswith("~")
        d = raw[1:] if neg else raw
        if d.endswith(".*") or "*" in d or "/" in d:
            # Entity / wildcard / path domains have no faithful mapping.
            return None
        if not is_valid_domain(d):
            return None
        (exc if neg else inc).add(d)
    return frozenset(inc), frozenset(exc)


def _is_safe_selector(sel: str) -> bool:
    if not sel or len(sel) > 1000:
        return False
    if _EXTENDED_CSS.search(sel):
        return False
    # Characters that would let a selector break out of a CSS rule block.
    if any(c in sel for c in "{}\\") or "/*" in sel or "\n" in sel:
        return False
    if sel.startswith("+js(") or sel.startswith("^"):
        return False
    return True


def _parse_cosmetic(line: str, res: ParseResult) -> None:
    for marker, exception in (("#@#", True), ("##", False)):
        idx = line.find(marker)
        if idx != -1:
            break
    else:  # pragma: no cover - caller guarantees a marker
        return
    if line.startswith(("#?#", "#$#", "#%#")) or "#?#" in line[:idx + 3] or "#$#" in line or "#%#" in line:
        res.skipped["cosmetic:extended"] += 1
        return
    domains_spec, selector = line[:idx], line[idx + len(marker):].strip()
    if selector.startswith("+js("):
        _parse_scriptlet(domains_spec, selector, exception, line, res)
        return
    if selector.startswith("^"):
        res.skipped["cosmetic:html-filter"] += 1
        return
    if not _is_safe_selector(selector):
        res.skipped["cosmetic:unsupported-selector"] += 1
        return
    parsed = _split_domains(domains_spec, ",") if domains_spec else (frozenset(), frozenset())
    if parsed is None:
        res.skipped["cosmetic:wildcard-domain"] += 1
        return
    inc, exc = parsed
    if exception and not inc:
        # A generic exception (#@#sel with no domain) disables a selector
        # everywhere; honour it by dropping the selector later.
        pass
    res.cosmetic.append(CosmeticFilter(selector, exception, inc, exc, line))


def _split_scriptlet_args(body: str) -> list[str]:
    """Split uBO scriptlet arguments: commas separate, "\\," is a literal comma."""
    args, cur, i = [], [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body) and body[i + 1] == ",":
            cur.append(","); i += 2; continue
        if c == ",":
            args.append("".join(cur).strip()); cur = []; i += 1; continue
        cur.append(c); i += 1
    args.append("".join(cur).strip())
    # Quoted arguments ('foo' / "foo") keep their content verbatim.
    return [a[1:-1] if len(a) >= 2 and a[0] == a[-1] and a[0] in "'\"`" else a for a in args]


def _parse_scriptlet(domains_spec: str, selector: str, exception: bool, line: str, res: ParseResult) -> None:
    if not selector.endswith(")"):
        res.skipped["scriptlet:malformed"] += 1
        return
    body = selector[4:-1]
    parsed = _split_domains(domains_spec, ",") if domains_spec else (frozenset(), frozenset())
    if parsed is None:
        res.skipped["scriptlet:wildcard-domain"] += 1
        return
    inc, exc = parsed
    if exception and not body.strip():
        # "example.com#@#+js()" turns off every scriptlet on that site.
        if inc:
            res.scriptlets.append(ScriptletFilter("*", (), True, inc, exc, line))
        return
    args = _split_scriptlet_args(body)
    raw_name = args[0].removesuffix(".js")
    name = SCRIPTLET_ALIASES.get(raw_name)
    if not name:
        res.skipped[f"scriptlet:unsupported"] += 1
        return
    if not inc and not exception:
        # Generic scriptlets would run on every site; uBO forbids them too.
        res.skipped["scriptlet:generic"] += 1
        return
    params = tuple(args[1:])
    if len(params) > 6 or any(len(a) > 500 for a in params):
        res.skipped["scriptlet:oversized"] += 1
        return
    res.scriptlets.append(ScriptletFilter(name, params, exception, inc, exc, line))


# --------------------------------------------------------------------------
# Network filters
# --------------------------------------------------------------------------
def _find_options_sep(line: str) -> int:
    """Index of the '$' that starts the option list, or -1.

    ABP rules: the last '$' that is followed by something option-like. A '$'
    inside a regex literal pattern is never an options separator, but regex
    patterns are rejected before we get here.
    """
    idx = line.rfind("$")
    if idx <= 0:
        return -1 if idx == -1 else (0 if len(line) > 1 else -1)
    tail = line[idx + 1:]
    if not tail or not re.match(r"^~?[a-z0-9_-]+(?:=|,|$)", tail, re.I):
        return -1
    return idx


def _parse_network(line: str, res: ParseResult) -> None:
    exception = line.startswith("@@")
    body = line[2:] if exception else line

    sep = _find_options_sep(body)
    pattern, opts_str = (body[:sep], body[sep + 1:]) if sep != -1 else (body, "")

    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        res.skipped["network:regex"] += 1
        return

    rtypes: set[str] = set()
    ex_rtypes: set[str] = set()
    party = None
    inc_d: frozenset[str] = frozenset()
    exc_d: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()
    important = match_case = document = elemhide = generichide = False
    removeparam = None

    for opt in filter(None, (o.strip() for o in opts_str.split(","))):
        name, _, value = opt.partition("=")
        name_l = name.lower()
        neg = name_l.startswith("~")
        key = name_l[1:] if neg else name_l
        if key in RESOURCE_TYPES:
            (ex_rtypes if neg else rtypes).add(RESOURCE_TYPES[key])
        elif key in ("third-party", "3p"):
            party = "first" if neg else "third"
        elif key in ("first-party", "1p"):
            party = "third" if neg else "first"
        elif key == "removeparam" and not neg and exception and not value:
            removeparam = ""  # "@@...$removeparam": stop stripping parameters on this site
        elif key == "removeparam" and not neg:
            # Only plain parameter names; regex/negated forms have no DNR equivalent.
            if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", value or ""):
                res.skipped["network:removeparam-complex"] += 1
                return
            removeparam = value
        elif key == "domain":
            parsed = _split_domains(value, "|")
            if parsed is None:
                res.skipped["network:wildcard-domain"] += 1
                return
            inc_d, exc_d = parsed
        elif key == "denyallow":
            parsed = _split_domains(value, "|")
            if parsed is None or parsed[1]:
                res.skipped["network:bad-denyallow"] += 1
                return
            deny = parsed[0]
        elif key == "important":
            important = True
        elif key == "match-case":
            match_case = True
        elif key == "document" and not neg:
            document = True
        elif key == "elemhide" and exception:
            elemhide = True
        elif key == "generichide" and exception:
            generichide = True
        elif key in UNSUPPORTED_OPTIONS or key in ("document", "elemhide", "generichide"):
            res.skipped[f"network:option:{key}"] += 1
            return
        else:
            res.skipped["network:option:unknown"] += 1
            return

    # $elemhide / $generichide exceptions only affect cosmetic filtering.
    if (elemhide or generichide) and not (rtypes or document):
        pass
    elif document and not exception:
        # Blocking a whole document is a "strict blocking" page; skip.
        res.skipped["network:block-document"] += 1
        return

    if any(ord(c) > 127 for c in pattern):
        res.skipped["network:non-ascii"] += 1
        return

    # Normalise patterns DNR rejects but whose meaning is unchanged.
    if pattern.startswith("||*"):
        pattern = pattern[2:]
    if pattern in ("*", "|", "||"):
        pattern = ""

    if not pattern and not (inc_d or document or elemhide or generichide or removeparam):
        # A match-everything rule with no scope would block the whole web.
        res.skipped["network:unscoped-empty"] += 1
        return
    if not pattern and (elemhide or generichide or document) and not inc_d:
        res.skipped["network:unscoped-empty"] += 1
        return

    res.network.append(NetworkFilter(
        pattern=pattern,
        exception=exception,
        important=important,
        match_case=match_case,
        resource_types=frozenset(rtypes),
        excluded_resource_types=frozenset(ex_rtypes),
        party=party,
        include_domains=inc_d,
        exclude_domains=exc_d,
        exclude_request_domains=deny,
        document=document,
        elemhide=elemhide,
        generichide=generichide,
        removeparam=removeparam,
        source=line,
    ))


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------
def parse_abp(lines: Iterable[str]) -> ParseResult:
    res = ParseResult()
    for raw in lines:
        res.total_lines += 1
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("["):
            res.skipped["comment"] += 1
            continue
        if "##" in line or "#@#" in line or "#?#" in line or "#$#" in line or "#%#" in line:
            _parse_cosmetic(line, res)
            continue
        if "$$" in line or "$@$" in line:
            res.skipped["html-filter"] += 1
            continue
        _parse_network(line, res)
    return res


def parse_hosts(lines: Iterable[str]) -> ParseResult:
    res = ParseResult()
    for raw in lines:
        res.total_lines += 1
        m = HOSTS_LINE_RE.match(raw)
        if not m:
            # Some lists are plain "one domain per line".
            plain = raw.split("#", 1)[0].strip().lower()
            if plain and " " not in plain and is_valid_domain(plain):
                res.hosts.add(plain)
            else:
                res.skipped["hosts:other"] += 1
            continue
        d = m.group(1).lower().rstrip(".")
        if d in HOSTS_SKIP or not is_valid_domain(d):
            res.skipped["hosts:invalid"] += 1
            continue
        res.hosts.add(d)
    return res


def detect_format(text_head: str) -> str:
    head = text_head.lstrip()
    if head.startswith("[Adblock") or "\n||" in text_head or "\n##" in text_head:
        return "abp"
    return "hosts"


def iter_lines(text: str) -> Iterator[str]:
    return iter(text.splitlines())
