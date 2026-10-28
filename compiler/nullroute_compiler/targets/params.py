"""Link-decoration stripping (Chrome DNR ``redirect`` + ``queryTransform``).

Click identifiers such as ``gclid`` or ``fbclid`` are appended to links so a
tracker can re-identify you on the landing site even when third-party cookies
are blocked ("UID smuggling", Randall et al. 2022; PURL, USENIX Security 2024).
DNR can drop them from top-level and frame navigations before the request is
sent.

Deliberately NOT stripped: ``utm_*`` campaign tags. They identify a campaign,
not a person, and removing them breaks some landing pages for little privacy
gain — the same call Firefox and Brave make in their default lists.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..abp import NetworkFilter

# Per-user / per-click identifiers only.
CLICK_ID_PARAMS = [
    # Google Ads / DoubleClick
    "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
    # Meta, Microsoft, X, TikTok, LinkedIn, Instagram, Yandex
    "fbclid", "msclkid", "twclid", "ttclid", "li_fat_id", "igshid", "yclid", "ysclid",
    # Email/marketing platforms that embed subscriber IDs
    "mc_eid", "_hsenc", "_hsmi", "__hssc", "__hstc", "__hsfp", "mkt_tok",
    "oly_anon_id", "oly_enc_id", "vero_id", "vero_conv", "wickedid", "rb_clickid",
    "ss_email_id", "bsft_uid", "bsft_clkid", "ml_subscriber", "ml_subscriber_hash",
    "_openstat", "epik",
]

PARAMS_PER_REGEX = 12          # keeps every compiled RE2 program well under Chrome's 2 KB cap
PRIORITY = 1
PRIORITY_EXCEPTION = 2
_NAME = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")


def _regex(names: list[str]) -> str:
    alt = "|".join(re.escape(n) for n in names)
    return rf"^[^#]*[?&](?:{alt})="


def build(filters: Iterable[NetworkFilter]) -> tuple[list[dict], dict]:
    params = set(CLICK_ID_PARAMS)
    scoped: dict[str, set[str]] = {}
    exceptions: set[str] = set()
    skipped = 0
    for f in filters:
        if f.removeparam is None:
            continue
        if f.exception:
            if f.pattern:
                exceptions.add(f.pattern)
            continue
        if f.include_domains or f.exclude_domains or f.resource_types or f.party:
            skipped += 1  # page-scoped variants have no faithful DNR mapping
            continue
        if f.pattern:
            scoped.setdefault(f.pattern, set()).add(f.removeparam)
        else:
            params.add(f.removeparam)
    params = {p for p in params if _NAME.match(p)}

    rules: list[dict] = []
    ordered = sorted(params)
    for i in range(0, len(ordered), PARAMS_PER_REGEX):
        chunk = ordered[i:i + PARAMS_PER_REGEX]
        rules.append({
            "priority": PRIORITY,
            "action": {"type": "redirect",
                       "redirect": {"transform": {"queryTransform": {"removeParams": chunk}}}},
            "condition": {"regexFilter": _regex(chunk), "resourceTypes": ["main_frame", "sub_frame"]},
        })
    for pattern, names in sorted(scoped.items()):
        names = sorted(n for n in names if _NAME.match(n))
        if not names or any(ord(c) > 127 for c in pattern):
            continue
        rules.append({
            "priority": PRIORITY,
            "action": {"type": "redirect",
                       "redirect": {"transform": {"queryTransform": {"removeParams": names}}}},
            "condition": {"urlFilter": pattern, "resourceTypes": ["main_frame", "sub_frame"]},
        })
    for pattern in sorted(exceptions):
        if any(ord(c) > 127 for c in pattern):
            continue
        rules.append({
            "priority": PRIORITY_EXCEPTION,
            "action": {"type": "allow"},
            # Main frame only: an allow on sub_frame would also unblock ad iframes.
            "condition": {"urlFilter": pattern, "resourceTypes": ["main_frame"]},
        })
    for i, r in enumerate(rules, 1):
        rules[i - 1] = {"id": i, **r}
    return rules, {"rules": len(rules), "global_params": len(params),
                   "scoped_patterns": len(scoped), "exceptions": len(exceptions), "skipped": skipped}
