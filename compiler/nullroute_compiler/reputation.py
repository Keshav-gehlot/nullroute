"""Privacy-preserving domain reputation (phishing, malware, scams).

Threat feeds are far too big to ship as a blocklist: HaGeZi's TIF alone has
~2 million domains and changes every few hours. So they're compiled into the
two-tier structure Google Safe Browsing's Update API uses:

1. A local *prefix set*: the first 32 bits of SHA-256 of every listed domain,
   sorted and Golomb-Rice coded (~1.6 bytes per entry). Apps download it with
   the other lists and check every lookup against it **on the device**.
2. *Shards* of longer hashes, fetched only when a lookup hits a local prefix.
   A shard holds the first 64 bits of every listed hash that shares the
   lookup's first 12 bits, so the server learns only which of 4,096 buckets
   was asked for — and only for names whose 32-bit prefix already matched a
   known-bad domain (about 1 in 2,000 clean names, by chance).

A lookup for ``a.b.example.com`` checks ``a.b.example.com``, ``b.example.com``
and ``example.com``: a listed domain covers its subdomains, as in the feeds.

Files written under ``dist/rep/``:

    prefixes.rice       b"NRP1" | u32 count | u8 k | u32 first | Rice-coded gaps
    shard_hashes.bin    4096 x 16 bytes: truncated SHA-256 of each shard file
    shards/XYZ.bin      sorted 8-byte big-endian hash heads, XYZ = first 12 bits
    meta.json           counts, sources, format description
"""
from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Iterable

from .domains import minimize, parents

MAGIC = b"NRP1"
SHARD_BITS = 12
SHARDS = 1 << SHARD_BITS
HEAD_BYTES = 8           # bytes of SHA-256 kept per entry in a shard
SHARD_HASH_BYTES = 16    # bytes of each shard file's SHA-256 kept in shard_hashes.bin
MIN_LABELS = 2           # never hash a bare TLD


def digest(domain: str) -> bytes:
    return hashlib.sha256(domain.encode("ascii")).digest()


def prefix32(h: bytes) -> int:
    return struct.unpack(">I", h[:4])[0]


def shard_of(h: bytes) -> int:
    return prefix32(h) >> (32 - SHARD_BITS)


def shard_name(index: int) -> str:
    return f"{index:03x}"


def lookup_expressions(host: str) -> list[str]:
    """Names a client hashes for one lookup: the host and each parent with >= 2 labels."""
    host = host.lower().rstrip(".")
    return [p for p in parents(host) if p.count(".") >= MIN_LABELS - 1]


# ---- Golomb-Rice coding of sorted 32-bit prefixes ------------------------------

def rice_parameter(values: list[int]) -> int:
    if len(values) < 2:
        return 0
    mean_gap = (values[-1] - values[0]) / (len(values) - 1)
    return max(0, int(math.floor(math.log2(max(mean_gap * math.log(2), 1)))))


def rice_encode(values: list[int]) -> bytes:
    """Encode strictly increasing uint32 values (first raw, then Rice-coded gaps, MSB first)."""
    k = rice_parameter(values)
    header = MAGIC + struct.pack(">IBI", len(values), k, values[0] if values else 0)
    body = bytearray()
    acc = 0      # pending bits, most significant first
    nbits = 0
    mask = (1 << k) - 1
    for prev, cur in zip(values, values[1:]):
        gap = cur - prev
        if gap <= 0:
            raise ValueError("values must be strictly increasing")
        q = gap >> k
        # q ones, a zero, then the k low bits of the gap
        acc = (((acc << (q + 1)) | (((1 << q) - 1) << 1)) << k) | (gap & mask)
        nbits += q + 1 + k
        if nbits >= 64:
            spare = nbits % 8
            body += (acc >> spare).to_bytes((nbits - spare) // 8, "big")
            acc &= (1 << spare) - 1
            nbits = spare
    if nbits:
        pad = -nbits % 8
        body += (acc << pad).to_bytes((nbits + pad) // 8, "big")
    return header + bytes(body)


def rice_decode(blob: bytes) -> list[int]:
    if blob[:4] != MAGIC:
        raise ValueError("not a NullRoute prefix set")
    count, k, first = struct.unpack(">IBI", blob[4:13])
    if count == 0:
        return []
    bits = "".join(f"{b:08b}" for b in blob[13:])
    values = [first]
    cur = first
    pos = 0
    for _ in range(count - 1):
        zero = bits.find("0", pos)
        if zero < 0 or zero + 1 + k > len(bits):
            raise ValueError("truncated prefix set")
        q = zero - pos
        r = int(bits[zero + 1:zero + 1 + k], 2) if k else 0
        cur += (q << k) | r
        values.append(cur)
        pos = zero + 1 + k
    return values


# ---- Build -----------------------------------------------------------------------

def clean_entries(domains: Iterable[str], protected: Iterable[str], popular: Iterable[str]) -> tuple[list[str], dict]:
    """Normalise, drop entries that would block essential or very popular sites, minimise."""
    import re
    valid = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$")
    raw = {d.strip().lower().rstrip(".") for d in domains}
    raw.discard("")
    entries = {d for d in raw if valid.match(d)}
    invalid = len(raw) - len(entries)

    # An entry blocks itself and its subdomains, so it must not be a protected
    # name or a parent of one (e.g. "googleusercontent.com" would take out
    # Google's CDN). Popular sites are dropped only on an exact match: feeds
    # rightly list "login-verify.weebly.com" but sometimes wrongly list a whole
    # top-10k site, which a heuristic feed has no business blocking.
    shielded = {p for d in protected for p in parents(d.lower())}
    popular_set = {d.strip().lower() for d in popular if d.strip()}
    dropped = sorted(d for d in entries if d in shielded or d in popular_set)
    entries -= set(dropped)
    kept = minimize(entries)
    return kept, {"input": len(raw), "invalid": invalid, "droppedProtected": dropped,
                  "coveredByParent": len(entries) - len(kept), "entries": len(kept)}


def build(domains: list[str], out: Path) -> dict:
    """Write dist/rep/*. Returns {relative_path: sha256} for report.json plus stats."""
    hashes = sorted({digest(d) for d in domains})
    prefixes = sorted({prefix32(h) for h in hashes})

    rep = out / "rep"
    (rep / "shards").mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}

    blob = rice_encode(prefixes)
    (rep / "prefixes.rice").write_bytes(blob)
    files["rep/prefixes.rice"] = hashlib.sha256(blob).hexdigest()

    buckets: list[list[bytes]] = [[] for _ in range(SHARDS)]
    for h in hashes:
        buckets[shard_of(h)].append(h[:HEAD_BYTES])
    shard_digests = bytearray()
    sizes = []
    for i, bucket in enumerate(buckets):
        data = b"".join(sorted(set(bucket)))
        (rep / "shards" / f"{shard_name(i)}.bin").write_bytes(data)
        shard_digests += hashlib.sha256(data).digest()[:SHARD_HASH_BYTES]
        sizes.append(len(data) // HEAD_BYTES)
    (rep / "shard_hashes.bin").write_bytes(bytes(shard_digests))
    files["rep/shard_hashes.bin"] = hashlib.sha256(bytes(shard_digests)).hexdigest()

    stats = {
        "domains": len(domains), "hashes": len(hashes), "prefixes": len(prefixes),
        "riceK": blob[8], "prefixBytes": len(blob),
        "bitsPerPrefix": round(len(blob) * 8 / max(len(prefixes), 1), 2),
        "shardEntries": {"min": min(sizes), "max": max(sizes), "mean": round(sum(sizes) / SHARDS, 1)},
        # Chance that a clean name's expression hits a local prefix and triggers a shard fetch.
        "localFalseHitRate": len(prefixes) / 2 ** 32,
    }
    return {"files": files, "stats": stats}


def is_listed(host: str, prefixes: list[int], fetch_shard) -> str | None:
    """Reference client used by tests: returns the matching expression or None."""
    import bisect
    for expr in lookup_expressions(host):
        h = digest(expr)
        p = prefix32(h)
        i = bisect.bisect_left(prefixes, p)
        if i == len(prefixes) or prefixes[i] != p:
            continue
        data = fetch_shard(shard_name(shard_of(h)))
        heads = {data[j:j + HEAD_BYTES] for j in range(0, len(data), HEAD_BYTES)}
        if h[:HEAD_BYTES] in heads:
            return expr
    return None
