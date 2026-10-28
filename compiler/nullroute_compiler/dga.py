"""Heuristic detection of algorithmically generated domains (DGA).

Why not Shannon entropy? A name of n characters has entropy <= log2(n), so a
"block if entropy > 4.15" rule can never fire on the 10-15 character labels
DGAs actually produce, and lower thresholds flag a large share of legitimate
domains. Measured on the labelled dataset below:

    entropy > 4.15   catches  3.7% of DGA names, flags 0.13% of legitimate ones
    entropy > 3.5    catches 51.8% of DGA names, flags 30%   of legitimate ones

Instead we score how much a site's label looks like real domain names, using a
character-bigram Markov model (mean log-likelihood per transition), as in the
n-gram literature (e.g. Cucchiarelli et al., Expert Systems with Applications
170, 2021). Only the registrable label is scored ("cvyh1po636.ddns.net" ->
"cvyh1po636", "d1a2b3.cloudfront.net" -> "cloudfront"), so random-looking CDN
hostnames don't trip it.

    python -m nullroute_compiler.dga train    --top legit-top1m.txt --out data/dga_model.json
    python -m nullroute_compiler.dga evaluate --model data/dga_model.json --dataset dga_domains_full.csv

Training data: a public top-1M domain list. Evaluation data: a *different*
source (Alexa benign + Netlab 360 DGA families, Cucchiarelli et al. 2021), so
the reported false-positive rate is not measured on training data.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import math
import random
from pathlib import Path

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
MIN_LENGTH = 7  # shorter labels carry too little signal to judge

# Dynamic-DNS / free-subdomain providers: the customer-chosen label is the site.
DYNAMIC_DNS = {
    "ddns.net", "duckdns.org", "no-ip.org", "no-ip.com", "no-ip.biz", "no-ip.info", "noip.me",
    "hopto.org", "zapto.org", "sytes.net", "servebeer.com", "serveftp.com", "myftp.org",
    "myftp.biz", "dyndns.org", "dyndns.info", "dynserv.com", "mooo.com", "yi.org", "afraid.org",
    "chickenkiller.com", "strangled.net", "dnsalias.com", "dynu.net", "freedns.org",
    "3utilities.com", "bounceme.net", "redirectme.net", "servehttp.com", "webhop.me",
}
MULTI_PART_SUFFIXES = DYNAMIC_DNS | {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.in", "net.in",
    "org.in", "ac.in", "edu.in", "gov.in", "com.br", "co.jp", "ne.jp", "or.jp", "co.kr", "com.cn",
    "net.cn", "com.tw", "com.mx", "com.ar", "com.tr", "co.za", "com.sg", "com.my", "co.id",
    "com.vn", "com.ph", "com.pk", "com.ng", "co.nz", "com.co", "com.pe", "com.ua", "com.sa",
    "com.eg", "sa.com", "co.il", "co.th", "com.hk", "com.bd", "com.np", "com.lk",
}


def site_label(domain: str) -> str | None:
    """The label a registrant chose: 'a.b.example.co.uk' -> 'example'."""
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return None
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return parts[-3]
    return parts[-2]


def judgeable(label: str | None) -> bool:
    return bool(label) and len(label) >= MIN_LENGTH and not label.startswith("xn--") \
        and all(c in ALPHABET for c in label)


def train(domains) -> dict:
    bigrams, unigrams = collections.Counter(), collections.Counter()
    for d in domains:
        label = site_label(d)
        if not label or label.startswith("xn--") or any(c not in ALPHABET for c in label):
            continue
        t = "^" + label + "$"
        for a, b in zip(t, t[1:]):
            bigrams[a + b] += 1
            unigrams[a] += 1
    nxt = ALPHABET + "$"
    k = 0.5  # additive smoothing
    return {a: [round(math.log((bigrams[a + b] + k) / (unigrams[a] + k * len(nxt))), 3) for b in nxt]
            for a in "^" + ALPHABET}


def score(model: dict, label: str) -> float:
    """Mean log-probability per transition; lower = less like real domains."""
    nxt = ALPHABET + "$"
    t = "^" + label + "$"
    lps = [model[a][nxt.index(b)] for a, b in zip(t, t[1:])]
    return sum(lps) / len(lps)


def calibrate(model: dict, domains, fpr: float) -> float:
    scores = sorted(score(model, l) for l in map(site_label, domains) if judgeable(l))
    return scores[int(len(scores) * fpr)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="nullroute_compiler.dga")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train")
    t.add_argument("--top", type=Path, required=True, help="one legitimate domain per line")
    t.add_argument("--out", type=Path, required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--model", type=Path, required=True)
    e.add_argument("--dataset", type=Path, required=True, help="CSV: class,family,domain")
    args = ap.parse_args(argv)

    if args.cmd == "train":
        top = [l.strip() for l in args.top.read_text().splitlines() if l.strip()]
        random.Random(7).shuffle(top)
        cut = int(len(top) * 0.9)
        model = train(top[:cut])
        held_out = top[cut:]
        out = {
            "version": 1,
            "alphabet": ALPHABET,
            "minLength": MIN_LENGTH,
            # Calibrated on held-out legitimate names never seen in training.
            "flagThreshold": round(calibrate(model, held_out, 0.005), 3),   # ~0.5% false positives
            "blockThreshold": round(calibrate(model, held_out, 0.001), 3),  # ~0.1% false positives
            "dynamicDnsSuffixes": sorted(DYNAMIC_DNS),
            "multiPartSuffixes": sorted(MULTI_PART_SUFFIXES - DYNAMIC_DNS),
            "model": model,
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(out, separators=(",", ":")) + "\n")
        print(f"trained on {cut} names; flag < {out['flagThreshold']}, block < {out['blockThreshold']}")
        return 0

    m = json.loads(args.model.read_text())
    rows = list(csv.reader(args.dataset.open()))
    legit = [r[2] for r in rows if r[0] == "legit"]
    dga = [(r[1], r[2]) for r in rows if r[0] == "dga"]
    for name, th in (("flag", m["flagThreshold"]), ("block", m["blockThreshold"])):
        hit = lambda d: judgeable(site_label(d)) and score(m["model"], site_label(d)) < th  # noqa: E731
        fp = sum(map(hit, legit)) / len(legit)
        per = collections.defaultdict(lambda: [0, 0])
        for fam, d in dga:
            per[fam][1] += 1
            per[fam][0] += hit(d)
        tp = sum(v[0] for v in per.values()) / len(dga)
        print(f"{name:5s} (< {th}): DGA caught {tp:.1%}, legitimate flagged {fp:.2%}")
        print("   " + ", ".join(f"{f} {a / b:.0%}" for f, (a, b) in
                               sorted(per.items(), key=lambda kv: -kv[1][0] / kv[1][1])))
    for th in (4.15, 3.5):
        def H(s):
            c = collections.Counter(s)
            return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())
        fp = sum(H(d) > th for d in legit) / len(legit)
        tp = sum(H(d) > th for _, d in dga) / len(dga)
        print(f"baseline entropy > {th}: DGA caught {tp:.1%}, legitimate flagged {fp:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
