#!/usr/bin/env python3
# ioc_extractor.py
#
# ODEA Krino v2.1.2 - IOC Normalization Layer (for MISP / CTI)
#
# Input:
#   <report_root>/normalized/events.jsonl
#
# Output:
#   <report_root>/ioc/iocs.json
#   <report_root>/ioc/misp_attributes.json
#   <report_root>/ioc/summary.json
#
# What it does:
# - Reads Krino unified events (JSONL)
# - Extracts IOC candidates from:
#     - action.details (remote_address, domain, url, hashes, command_line, path, etc.)
#     - raw (best-effort recursion)
# - Normalizes & deduplicates IOCs
# - Maps to MISP attribute-like objects (type/category/value/comment)
# - Keeps traceability to source event_id (+ source tool/module)
#
# Notes:
# - This script does NOT talk to MISP API (upload). It creates MISP-ready JSON.
# - You can later add uploader.py that reads misp_attributes.json and pushes via PyMISP.
#
# Usage:
#   python3 ioc_extractor.py ~/odea_krino/evidence/v2_report/<case_dir>
#
# Options:
#   --include-private-ip        Include RFC1918/loopback/link-local IPs (default: off)
#   --max-events N              Stop after N events (debug)
#   --max-values-per-event N    Cap IOC extraction per event to avoid explosions
#   --min-confidence X          Only consider events with confidence >= X
#
# Safe-by-default:
# - Excludes private IPs unless requested
# - Dedupes strongly (type+value)
# - Caps extracted strings from huge blobs

import os
import re
import sys
import json
import time
import argparse
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now_iso() -> str:
    return time.strftime(ISO_FMT, time.gmtime())


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_jsonl(path: str, max_lines: Optional[int] = None) -> Iterable[Tuple[int, Dict[str, Any]]]:
    i = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if max_lines is not None and i >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield (i, obj)
                    i += 1
            except Exception:
                continue


def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        # exclude private, loopback, link-local, multicast, reserved, unspecified
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return False


def looks_like_hash(s: str) -> Optional[str]:
    # returns "md5"/"sha1"/"sha256"/None
    s = s.strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", s):
        return "md5"
    if re.fullmatch(r"[a-f0-9]{40}", s):
        return "sha1"
    if re.fullmatch(r"[a-f0-9]{64}", s):
        return "sha256"
    return None


# ---------------------------
# Regex extractors
# ---------------------------

# IPv4 (strict-ish)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# URLs (http/https) + defanged variants
RE_URL = re.compile(
    r"\b(?:hxxp|https?)://[^\s\"\'<>]+",
    re.IGNORECASE
)

# Domains (basic)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b",
    re.IGNORECASE
)

# Emails
RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.IGNORECASE)

# Windows file path (very permissive)
RE_WIN_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"\'<>]{1,260}")

# Mutex-ish (heuristic)
RE_MUTEX = re.compile(r"\b(?:Global\\|Local\\)?[A-Za-z0-9._-]{6,64}\b")


def de_defang_url(u: str) -> str:
    # Normalize common defang patterns:
    # hxxp -> http, [.] -> ., (.) -> ., etc.
    u2 = u.strip()
    u2 = re.sub(r"^hxxp", "http", u2, flags=re.IGNORECASE)
    u2 = u2.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    u2 = u2.replace("[://]", "://")
    return u2


def clean_str(s: str, max_len: int = 500) -> str:
    if not isinstance(s, str):
        s = str(s)
    s = s.strip()
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


# ---------------------------
# IOC model & MISP mapping
# ---------------------------

def misp_map(ioc_type: str) -> Tuple[str, str]:
    """
    Return (misp_type, misp_category) for our internal ioc_type.
    """
    mapping = {
        "ip": ("ip-dst", "Network activity"),
        "domain": ("domain", "Network activity"),
        "url": ("url", "Network activity"),
        "email": ("email-src", "Payload delivery"),
        "md5": ("md5", "Payload delivery"),
        "sha1": ("sha1", "Payload delivery"),
        "sha256": ("sha256", "Payload delivery"),
        "file_path": ("filename|path", "Artifacts dropped"),
        "mutex": ("mutex", "Artifacts dropped"),
        "user_agent": ("user-agent", "Network activity"),
        "registry_key": ("regkey", "Persistence mechanism"),
        "registry_value": ("regkey|value", "Persistence mechanism"),
    }
    return mapping.get(ioc_type, ("text", "Other"))


def make_ioc_key(ioc_type: str, value: str) -> str:
    return f"{ioc_type}::{value}".lower()


def extract_from_string(s: str, include_private_ip: bool) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not s:
        return out

    # URLs
    for u in RE_URL.findall(s):
        u2 = de_defang_url(u)
        out.append(("url", u2))

    # Emails
    for e in RE_EMAIL.findall(s):
        out.append(("email", e.lower()))

    # IPs
    for ip in RE_IPV4.findall(s):
        if include_private_ip or is_public_ip(ip):
            out.append(("ip", ip))

    # Domains (avoid double-counting domains from URLs by still allowing; dedupe later)
    for d in RE_DOMAIN.findall(s):
        d2 = d.rstrip(".").lower()
        # skip if looks like an IP (rare)
        if RE_IPV4.fullmatch(d2):
            continue
        out.append(("domain", d2))

    # Windows paths
    for p in RE_WIN_PATH.findall(s):
        out.append(("file_path", p))

    # Hashes: scan tokens
    for tok in re.split(r"[^a-fA-F0-9]", s):
        if len(tok) in (32, 40, 64):
            ht = looks_like_hash(tok)
            if ht:
                out.append((ht, tok.lower()))

    return out


def deep_iter(obj: Any, max_depth: int = 6, _depth: int = 0) -> Iterable[Any]:
    """
    Yield scalar-ish values from nested dict/list structures.
    """
    if _depth > max_depth:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            yield from deep_iter(v, max_depth=max_depth, _depth=_depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from deep_iter(v, max_depth=max_depth, _depth=_depth + 1)
    else:
        yield obj


def extract_iocs_from_event(
    ev: Dict[str, Any],
    include_private_ip: bool,
    max_values_per_event: int,
) -> List[Dict[str, Any]]:
    """
    Returns list of IOC observations with traceability to this event.
    Each item:
      {
        "type": "...",
        "value": "...",
        "event_id": "...",
        "timestamp": "...",
        "source": {...},
        "confidence": 0.x,
        "context": "...",
      }
    """
    out: List[Dict[str, Any]] = []

    event_id = ev.get("event_id", "")
    ts = ev.get("timestamp", "")
    src = ev.get("source", {}) or {}
    tool = src.get("tool", "")
    module = src.get("module", "")
    conf = float(ev.get("confidence", 0.0) or 0.0)

    # Candidate objects to scan first (high signal)
    candidates: List[Tuple[str, Any]] = []

    action = ev.get("action", {}) or {}
    details = action.get("details", {}) or {}
    actor = ev.get("actor", {}) or {}

    # Common keys that likely contain IOCs
    key_hints = [
        ("remote_address", details.get("remote_address")),
        ("remote_ip", details.get("remote_ip")),
        ("local_address", details.get("local_address")),
        ("ip", details.get("ip")),
        ("domain", details.get("domain")),
        ("host", details.get("host")),
        ("url", details.get("url")),
        ("uri", details.get("uri")),
        ("user_agent", details.get("user_agent")),
        ("command_line", details.get("command_line")),
        ("cmdline", details.get("cmdline")),
        ("path", details.get("path")),
        ("image", details.get("image")),
        ("process_path", actor.get("path")),
        ("process_name", actor.get("name")),
    ]
    for k, v in key_hints:
        if v is not None:
            candidates.append((k, v))

    # Also scan raw (best-effort), but capped
    raw = ev.get("raw", {})
    candidates.append(("raw", raw))

    extracted_pairs: List[Tuple[str, str, str]] = []  # (ioc_type, value, context_key)

    # Extract from candidates
    for context_key, val in candidates:
        if len(extracted_pairs) >= max_values_per_event:
            break

        if isinstance(val, (dict, list)):
            # Dive into nested structures and extract from scalar strings/numbers
            for scalar in deep_iter(val, max_depth=5):
                if len(extracted_pairs) >= max_values_per_event:
                    break
                if scalar is None:
                    continue
                if isinstance(scalar, (int, float, bool)):
                    continue
                s = clean_str(str(scalar), max_len=800)
                for t, v2 in extract_from_string(s, include_private_ip):
                    extracted_pairs.append((t, v2, context_key))
                    if len(extracted_pairs) >= max_values_per_event:
                        break
        else:
            s = clean_str(str(val), max_len=800)
            for t, v2 in extract_from_string(s, include_private_ip):
                extracted_pairs.append((t, v2, context_key))
                if len(extracted_pairs) >= max_values_per_event:
                    break

    # Build IOC observation objects
    for ioc_type, value, ctx in extracted_pairs:
        out.append(
            {
                "type": ioc_type,
                "value": value,
                "event_id": event_id,
                "timestamp": ts,
                "source": {"tool": tool, "module": module},
                "confidence": conf,
                "context": ctx,
            }
        )
    return out


def to_misp_attribute(ioc: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """
    Convert IOC observation to a MISP attribute-like dict.
    """
    ioc_type = ioc["type"]
    value = ioc["value"]
    tool = (ioc.get("source") or {}).get("tool", "")
    module = (ioc.get("source") or {}).get("module", "")
    event_id = ioc.get("event_id", "")
    ts = ioc.get("timestamp", "")
    conf = ioc.get("confidence", 0.0)

    misp_type, misp_category = misp_map(ioc_type)

    comment = f"Krino {case_id} | src={tool}/{module} | event_id={event_id} | conf={conf}"
    if ts:
        comment += f" | ts={ts}"

    return {
        "type": misp_type,
        "category": misp_category,
        "value": value,
        "comment": comment,
        # Optional fields (kept simple & safe)
        "to_ids": True if ioc_type in {"ip", "domain", "url", "md5", "sha1", "sha256"} else False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="ODEA Krino v2.1.2 IOC Extractor (events.jsonl -> MISP-ready JSON)")
    ap.add_argument("report_root", help="Path to v2_report/<case_dir>")
    ap.add_argument("--include-private-ip", action="store_true", help="Include RFC1918/loopback/link-local IPs")
    ap.add_argument("--max-events", type=int, default=0, help="Stop after N events (0 = all)")
    ap.add_argument("--max-values-per-event", type=int, default=50, help="Max IOC values to extract per event")
    ap.add_argument("--min-confidence", type=float, default=0.0, help="Only process events with confidence >= X")
    args = ap.parse_args()

    report_root = os.path.abspath(os.path.expanduser(args.report_root))
    norm_events = os.path.join(report_root, "normalized", "events.jsonl")
    if not os.path.isfile(norm_events):
        print(f"[!] Not found: {norm_events}")
        sys.exit(1)

    case_id = os.path.basename(report_root)

    out_dir = os.path.join(report_root, "ioc")
    ensure_dir(out_dir)

    max_lines = args.max_events if args.max_events and args.max_events > 0 else None

    # 1) Extract IOC observations (with trace)
    observations: List[Dict[str, Any]] = []
    seen_obs: Set[str] = set()

    processed_events = 0
    skipped_conf = 0

    for idx, ev in read_jsonl(norm_events, max_lines=max_lines):
        processed_events += 1
        conf = float(ev.get("confidence", 0.0) or 0.0)
        if conf < args.min_confidence:
            skipped_conf += 1
            continue

        iocs = extract_iocs_from_event(
            ev,
            include_private_ip=args.include_private_ip,
            max_values_per_event=args.max_values_per_event,
        )

        # Strong dedupe: type+value+event_id
        for it in iocs:
            key = f"{it['type']}::{it['value']}::{it.get('event_id','')}".lower()
            if key in seen_obs:
                continue
            seen_obs.add(key)
            observations.append(it)

    # 2) Aggregate unique IOCs across events (type+value)
    agg: Dict[str, Dict[str, Any]] = {}
    for obs in observations:
        k = make_ioc_key(obs["type"], obs["value"])
        if k not in agg:
            agg[k] = {
                "type": obs["type"],
                "value": obs["value"],
                "first_seen": obs.get("timestamp", ""),
                "last_seen": obs.get("timestamp", ""),
                "max_confidence": float(obs.get("confidence", 0.0) or 0.0),
                "occurrences": 0,
                "sources": set(),      # tool/module
                "event_ids": set(),    # event ids
                "contexts": set(),     # context keys
            }
        a = agg[k]
        a["occurrences"] += 1
        a["sources"].add(f"{(obs.get('source') or {}).get('tool','')}/{(obs.get('source') or {}).get('module','')}")
        a["event_ids"].add(obs.get("event_id", ""))
        a["contexts"].add(obs.get("context", ""))

        ts = obs.get("timestamp", "")
        if ts:
            if not a["first_seen"] or ts < a["first_seen"]:
                a["first_seen"] = ts
            if not a["last_seen"] or ts > a["last_seen"]:
                a["last_seen"] = ts

        conf = float(obs.get("confidence", 0.0) or 0.0)
        if conf > a["max_confidence"]:
            a["max_confidence"] = conf

    # Convert sets to lists for JSON
    iocs_unique: List[Dict[str, Any]] = []
    for a in agg.values():
        iocs_unique.append(
            {
                "type": a["type"],
                "value": a["value"],
                "first_seen": a["first_seen"],
                "last_seen": a["last_seen"],
                "max_confidence": round(float(a["max_confidence"]), 3),
                "occurrences": int(a["occurrences"]),
                "sources": sorted([s for s in a["sources"] if s and s != "/"]),
                "event_ids": sorted([e for e in a["event_ids"] if e]),
                "contexts": sorted([c for c in a["contexts"] if c]),
            }
        )
    # Sort: high confidence first, then occurrences
    iocs_unique.sort(key=lambda x: (x["max_confidence"], x["occurrences"]), reverse=True)

    # 3) Build MISP attributes from unique IOCs
    misp_attributes: List[Dict[str, Any]] = []
    seen_attr: Set[str] = set()
    for ioc in iocs_unique:
        # fabricate a representative observation for comment (no single event_id is perfect; keep first)
        rep_event_id = ioc["event_ids"][0] if ioc["event_ids"] else ""
        rep_source = ioc["sources"][0] if ioc["sources"] else "/"
        tool, module = rep_source.split("/", 1) if "/" in rep_source else ("", rep_source)

        rep_obs = {
            "type": ioc["type"],
            "value": ioc["value"],
            "event_id": rep_event_id,
            "timestamp": ioc.get("first_seen", ""),
            "source": {"tool": tool, "module": module},
            "confidence": ioc.get("max_confidence", 0.0),
        }
        attr = to_misp_attribute(rep_obs, case_id=case_id)

        # Dedup by misp type+value
        k = f"{attr.get('type','')}::{attr.get('value','')}".lower()
        if k in seen_attr:
            continue
        seen_attr.add(k)
        misp_attributes.append(attr)

    # 4) Write outputs
    iocs_path = os.path.join(out_dir, "iocs.json")
    misp_path = os.path.join(out_dir, "misp_attributes.json")
    summary_path = os.path.join(out_dir, "summary.json")

    write_json(iocs_path, {"case_id": case_id, "created_at": utc_now_iso(), "iocs": iocs_unique})
    write_json(misp_path, {"case_id": case_id, "created_at": utc_now_iso(), "attributes": misp_attributes})

    summary = {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "input": relpath(norm_events, report_root),
        "params": {
            "include_private_ip": bool(args.include_private_ip),
            "max_events": args.max_events,
            "max_values_per_event": args.max_values_per_event,
            "min_confidence": args.min_confidence,
        },
        "stats": {
            "processed_events": processed_events,
            "skipped_by_confidence": skipped_conf,
            "ioc_observations": len(observations),
            "unique_iocs": len(iocs_unique),
            "misp_attributes": len(misp_attributes),
        },
        "outputs": {
            "iocs": relpath(iocs_path, report_root),
            "misp_attributes": relpath(misp_path, report_root),
        },
        "notes": [
            "This is IOC normalization (Indicator-centric), not event normalization.",
            "Private IPs are excluded by default. Use --include-private-ip to include them.",
            "MISP upload is not performed here; this only generates MISP-ready JSON.",
        ],
    }
    write_json(summary_path, summary)

    print("\n[✓] IOC extraction complete")
    print(f" - {relpath(iocs_path, report_root)}")
    print(f" - {relpath(misp_path, report_root)}")
    print(f" - {relpath(summary_path, report_root)}")
    print(f"   Unique IOCs: {len(iocs_unique)} | MISP attributes: {len(misp_attributes)}")


def relpath(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except Exception:
        return path


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
