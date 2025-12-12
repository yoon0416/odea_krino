#!/usr/bin/env python3
# ioc_refiner.py
#
# ODEA Krino v2.1.3-final
# IOC Semantic Normalization (MISP-hard / conservative)
#
# Policy goals:
# - Refined output should be directly ingestible into MISP
# - Minimize baseline/noise even at the cost of recall
# - Preserve all raw IOC evidence unchanged
#
# Strategy:
# - Path allowlist (user/temporary/startup only)
# - Extension allowlist (execution/script focused)
# - Strong domain sanity checks
# - Very conservative to_ids policy

import os
import re
import sys
import json
import time
import argparse
import ipaddress
from typing import Any, Dict, List, Optional, Tuple


ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


# -----------------------------
# Utils
# -----------------------------
def utc_now_iso() -> str:
    return time.strftime(ISO_FMT, time.gmtime())


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def normalize_value(v: str) -> str:
    return (v or "").strip()


def lower_win(v: str) -> str:
    return v.replace("/", "\\").lower()


def split_ext(v: str) -> str:
    _, ext = os.path.splitext(os.path.basename(v))
    return ext.lower()


# -----------------------------
# Allow / Deny Policies
# -----------------------------

# Only these paths are considered *suspicious enough* for MISP
SUSPICIOUS_PATH_PREFIXES = [
    r"c:\users\\",
    r"c:\programdata\\",
    r"c:\windows\temp\\",
    r"c:\temp\\",
]

STARTUP_HINTS = [
    r"\startup\\",
    r"\start menu\\programs\\startup\\",
]

# Only these extensions are allowed into refined IOC
EXECUTABLE_EXT_ALLOWLIST = {
    ".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd",
    ".lnk", ".scr", ".hta"
}

# Domain hardening
BLOCKED_DOMAIN_TOKENS = {
    "windows", "microsoft", "update", "driver", "drivers", "kernel", "sys"
}

VALID_TLDS = (
    ".com", ".net", ".org", ".io", ".co", ".biz", ".info",
    ".ru", ".cn", ".kr", ".jp", ".xyz"
)

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


# -----------------------------
# Classification helpers
# -----------------------------
def is_private_or_special_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return True


def classify_kind(ioc_type: str, value: str) -> str:
    t = (ioc_type or "").lower()
    v = value

    if t in {"ip", "domain", "url", "email", "md5", "sha1", "sha256"}:
        return t

    if "\\" in v or re.match(r"^[a-zA-Z]:\\", v):
        return "file_path"

    if RE_IPV4.fullmatch(v):
        return "ip"

    return "text"


# -----------------------------
# Core policy checks
# -----------------------------
def is_suspicious_path(v: str) -> bool:
    v = lower_win(v)
    if any(v.startswith(p) for p in SUSPICIOUS_PATH_PREFIXES):
        return True
    if any(h in v for h in STARTUP_HINTS):
        return True
    return False


def domain_is_valid(v: str) -> bool:
    v = v.lower()
    if not any(v.endswith(tld) for tld in VALID_TLDS):
        return False
    if any(tok in v for tok in BLOCKED_DOMAIN_TOKENS):
        return False
    return True


def should_to_ids(kind: str, confidence: float, value: str) -> bool:
    if confidence < 0.8:
        return False

    if kind == "ip":
        return not is_private_or_special_ip(value)

    if kind in {"domain", "url", "md5", "sha1", "sha256"}:
        return True

    return False


# -----------------------------
# MISP mapping
# -----------------------------
def misp_map(kind: str) -> Tuple[str, str]:
    return {
        "ip": ("ip-dst", "Network activity"),
        "domain": ("domain", "Network activity"),
        "url": ("url", "Network activity"),
        "md5": ("md5", "Payload delivery"),
        "sha1": ("sha1", "Payload delivery"),
        "sha256": ("sha256", "Payload delivery"),
        "file_path": ("filename|path", "Artifacts dropped"),
    }.get(kind, ("text", "Other"))


# -----------------------------
# Refinement
# -----------------------------
def build_refined_ioc(i: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    value = normalize_value(i.get("value", ""))
    if not value:
        return None

    kind = classify_kind(i.get("type", ""), value)
    confidence = float(i.get("max_confidence", 0.0) or 0.0)

    # ---------- File policy ----------
    if kind == "file_path":
        ext = split_ext(value)
        if ext not in EXECUTABLE_EXT_ALLOWLIST:
            return None
        if not is_suspicious_path(value):
            return None

    # ---------- Domain policy ----------
    if kind == "domain":
        if not domain_is_valid(value):
            return None

    # ---------- IP policy ----------
    if kind == "ip":
        if is_private_or_special_ip(value):
            return None

    misp_type, misp_cat = misp_map(kind)
    to_ids = should_to_ids(kind, confidence, value)

    return {
        "kind": kind,
        "value": value,
        "confidence": round(confidence, 3),
        "occurrences": int(i.get("occurrences", 0) or 0),
        "sources": i.get("sources", []),
        "event_ids": i.get("event_ids", []),
        "misp": {
            "type": misp_type,
            "category": misp_cat,
            "to_ids": to_ids,
        },
    }


# -----------------------------
# IO orchestration
# -----------------------------
def run(report_root: str) -> Dict[str, Any]:
    report_root = os.path.abspath(report_root)
    case_id = os.path.basename(report_root)

    ioc_dir = os.path.join(report_root, "ioc")
    raw_dir = os.path.join(ioc_dir, "raw")
    refined_dir = os.path.join(ioc_dir, "refined")
    ensure_dir(raw_dir)
    ensure_dir(refined_dir)

    raw_iocs_path = os.path.join(raw_dir, "iocs.json")
    if not os.path.isfile(raw_iocs_path):
        raise FileNotFoundError("ioc/raw/iocs.json not found")

    raw = read_json(raw_iocs_path)
    raw_iocs = raw.get("iocs", [])

    refined_iocs = []
    dropped = 0

    for i in raw_iocs:
        r = build_refined_ioc(i)
        if r is None:
            dropped += 1
            continue
        refined_iocs.append(r)

    # Deduplicate
    seen = set()
    uniq = []
    for r in refined_iocs:
        k = f"{r['kind']}::{r['value']}".lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)

    refined_iocs = sorted(
        uniq, key=lambda x: x.get("confidence", 0.0), reverse=True
    )

    # MISP attributes
    attrs = []
    for r in refined_iocs:
        attrs.append({
            "type": r["misp"]["type"],
            "category": r["misp"]["category"],
            "value": r["value"],
            "to_ids": r["misp"]["to_ids"],
            "comment": f"Krino {case_id} | conf={r['confidence']}",
        })

    write_json(os.path.join(refined_dir, "iocs_refined.json"), {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "policy": "misp_hard_conservative",
        "iocs": refined_iocs,
    })

    write_json(os.path.join(refined_dir, "misp_attributes_refined.json"), {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "attributes": attrs,
    })

    write_json(os.path.join(refined_dir, "summary_refined.json"), {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "stats": {
            "raw_iocs": len(raw_iocs),
            "refined_iocs": len(refined_iocs),
            "dropped": dropped,
        },
        "notes": [
            "MISP-hard conservative policy applied",
            "Only user/temporary/startup paths and executable/script extensions allowed",
            "Raw IOC evidence preserved unchanged",
        ],
    })

    return {
        "raw": len(raw_iocs),
        "refined": len(refined_iocs),
        "dropped": dropped,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report_root")
    args = ap.parse_args()

    s = run(args.report_root)
    print("[✓] IOC refinement v2.1.3-final complete")
    print(f" - Raw: {s['raw']} | Refined: {s['refined']} | Dropped: {s['dropped']}")


if __name__ == "__main__":
    main()
