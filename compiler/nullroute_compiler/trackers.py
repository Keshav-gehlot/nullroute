"""Can a classifier spot trackers that no list has caught yet? Measured here.

The research proposals NullRoute was built from suggest an on-device model
(AdGraph, WebGraph, AdFlush) that recognises trackers by behaviour instead of
by name. Before shipping one, this evaluates the idea on DuckDuckGo's Tracker
Radar (https://github.com/duckduckgo/tracker-radar, CC BY-NC-SA 4.0, used for
evaluation only): ~21k third-party domains crawled from the top US sites, each
with the browser APIs its scripts call, its request-type mix, whether it sets
cookies and how many sites embed it, plus DuckDuckGo's own category labels.

    python -m nullroute_compiler.trackers --radar tracker-radar/domains/US \\
        --blocklist ../dist/dns/blocklist.txt [--out docs/tracker-classifier.json]

Labels: positive if DuckDuckGo files the domain under an advertising /
analytics / tracking category; negative if only under CDN, embedded content,
payments, login and similar. The features are what an extension can observe
at runtime: the scripts' API usage, the request-type mix, third-party cookies
and (optionally) the domain's name tokens.

The finding (numbers come from the run, and are written to --out):

* With a random train/test split a gradient-boosted model looks good:
  ROC AUC 0.82-0.90 depending on the features.
* That is leakage. Split so that **no company appears in both train and test**
  — the real situation for a tracker nobody has listed — and every feature
  set drops to chance or below (AUC 0.31-0.49). The model had memorised
  which companies' infrastructure is which, not learned what tracking looks
  like: 98% of the benign domains are CDNs, which call the same APIs and are
  embedded on as many sites as trackers.
* On the trackers the lists miss (the only ones it would add value on), it
  recovers 1-7% at a 1% false-positive rate across held-out companies.

So NullRoute ships no learned blocker. It ships a *cross-site identifier*
detector instead (extension/src/lib/xsite.js): a third party that receives
the same ID from two unrelated sites is tracking by definition, whatever its
behaviour profile — the property the classifier could not learn.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
from pathlib import Path

TRACKING = {"Ad Motivated Tracking", "Advertising", "Analytics", "Third-Party Analytics Marketing",
            "Action Pixels", "Session Replay", "Audience Measurement", "Ad Fraud"}
BENIGN = {"CDN", "Embedded Content", "Online Payment", "Non-Tracking", "Federated Login", "SSO",
          "Fraud Prevention", "Support Chat Widget", "Consent Management Platform", "Badge",
          "Social - Comment", "Tag Manager"}
TYPES = ["Script", "Image", "Fetch", "XHR", "Ping", "Document", "Stylesheet", "Font", "Media", "WebSocket"]
TOKENS = ["ad", "ads", "adserver", "analytics", "track", "tracking", "tracker", "pixel", "beacon", "collect",
          "metrics", "stats", "tag", "tags", "event", "events", "log", "click", "impression", "sync", "match",
          "cdn", "static", "assets", "img", "fonts", "api", "js", "sdk", "insight", "telemetry", "measure",
          "audience", "segment", "id", "uid", "rtb", "bid", "prebid"]


def load(radar: Path) -> list[tuple[dict, int]]:
    rows = []
    for name in sorted(os.listdir(radar)):
        if not name.endswith(".json"):
            continue
        x = json.loads((radar / name).read_text())
        cats = set(x.get("categories") or [])
        label = 1 if cats & TRACKING else 0 if cats & BENIGN else None
        if label is not None:
            rows.append((x, label))
    return rows


def features(rows, apis: list[str], families: tuple[str, ...]):
    import numpy as np
    out = []
    for x, _ in rows:
        v: list[float] = []
        used = {a for r in x.get("resources", []) for a in r.get("apis", {})}
        types = x.get("types", {})
        total = sum(types.values()) or 1
        if "behaviour" in families:
            v += [1.0 if a in used else 0.0 for a in apis]
            v += [types.get(t, 0) / total for t in TYPES]
            v += [1.0 if x.get("cookies", 0) > 0 else 0.0]
        if "reach" in families:
            v += [float(np.log1p(x.get("sites", 0))), float(x.get("fingerprinting", 0))]
        if "names" in families:
            toks = set(re.split(r"[^a-z0-9]+", x["domain"].lower()))
            for r in x.get("resources", []):
                toks |= set(re.split(r"[^a-z0-9]+", r.get("rule", "").replace("\\", "").lower()))
            v += [1.0 if t in toks else 0.0 for t in TOKENS]
        out.append(v)
    return np.array(out, dtype=float)


def evaluate(radar: Path, blocklist: Path | None) -> dict:
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupKFold, StratifiedKFold

    rows = load(radar)
    y = np.array([label for _, label in rows])
    owners = [((x.get("owner") or {}).get("name") or x["domain"]) for x, _ in rows]
    counts = collections.Counter(a for x, _ in rows for a in {a for r in x.get("resources", []) for a in r.get("apis", {})})
    apis = [a for a, _ in counts.most_common(60)]
    listed = None
    if blocklist and blocklist.exists():
        block = {l.strip() for l in blocklist.read_text().splitlines() if l.strip() and not l.startswith("#")}
        listed = np.array([any(".".join(x["domain"].split(".")[i:]) in block
                               for i in range(x["domain"].count(".") + 1)) for x, _ in rows])

    result: dict = {"domains": len(rows), "positives": int(y.sum()), "negatives": int((y == 0).sum()),
                    "negativesThatAreCdns": round(float(np.mean(["CDN" in (x.get("categories") or [])
                                                                 for x, l in rows if l == 0])), 3),
                    "experiments": []}
    for families in [("behaviour",), ("behaviour", "reach"), ("names",), ("behaviour", "reach", "names")]:
        X = features(rows, apis, families)
        for split in ("random", "by-company"):
            folds = (StratifiedKFold(5, shuffle=True, random_state=0).split(X, y) if split == "random"
                     else GroupKFold(5).split(X, y, owners))
            score = np.zeros(len(y))
            for train, test in folds:
                model = HistGradientBoostingClassifier(random_state=0).fit(X[train], y[train])
                score[test] = model.predict_proba(X[test])[:, 1]
            threshold = float(np.quantile(score[y == 0], 0.99))
            row = {"features": "+".join(families), "split": split,
                   "rocAuc": round(float(roc_auc_score(y, score)), 3),
                   "recallAt1PctFpr": round(float((score[y == 1] > threshold).mean()), 3)}
            if listed is not None:
                missed = (y == 1) & ~listed
                row["recallOnTrackersListsMiss"] = round(float((score[missed] > threshold).mean()), 3)
            result["experiments"].append(row)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--radar", type=Path, required=True, help="tracker-radar/domains/<region>")
    ap.add_argument("--blocklist", type=Path, help="dist/dns/blocklist.txt, to report recall on unlisted trackers")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    result = evaluate(args.radar, args.blocklist)
    print(f"{result['domains']} labelled domains ({result['positives']} tracking, {result['negatives']} benign; "
          f"{result['negativesThatAreCdns']:.0%} of benign are CDNs)")
    print(f"{'features':32} {'split':11} {'ROC AUC':>8} {'recall@1%FPR':>13} {'unlisted':>9}")
    for e in result["experiments"]:
        print(f"{e['features']:32} {e['split']:11} {e['rocAuc']:8.3f} {e['recallAt1PctFpr']:13.3f} "
              f"{e.get('recallOnTrackersListsMiss', float('nan')):9.3f}")
    if args.out:
        args.out.write_text(json.dumps(result, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
