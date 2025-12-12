#!/usr/bin/env python3
# ioc_refiner.py
#
# ODEA Krino v2.1.3 - IOC Semantic Normalization (MISP-ready)
# Policy: Windows baseline path + extension based (fast & safe)
#
# Input (auto-detect):
#   <report_root>/ioc/raw/iocs.json
#   or <report_root>/ioc/iocs.json  (legacy v2.1.2 flat)
#
# Output:
#   <report_root>/ioc/raw/ (preserve v2.1.2 outputs if they were flat)
#   <report_root>/ioc/refined/iocs_refined.json
#   <report_root>/ioc/refined/misp_attributes_refined.json
#   <report_root>/ioc/refined/summary_refined.json
#
# What it does:
# - Keeps v2.1.2 outputs (raw) unchanged (moves them into ioc/raw if needed)
# - Applies baseline filtering:
#     - Drop or to_ids=false for Windows core paths & known safe extensions
#     - Excludes private IPs from to_ids by default
# - Re-classifies obvious mis-typed "domain" like "acpi.sys" into file indicators
# - Rewrites MISP attribute (type/category/to_ids) for refined output
#
# Usage:
#   python3 scripts/ioc_refiner.py <report_root>
#
# Notes:
# - This does NOT upload to MISP; it generates "refined" MISP-ready attribute JSON.

import os
import re
import sys
import json
import time
import argparse
import ipaddress
from typing import Any, Dict, List, Optional, Tuple


ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


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


def relpath(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except Exception:
        return path


# -----------------------------
# Baseline policy (fast & safe)
# -----------------------------
WIN_BASE_PATH_PREFIXES = [
    r"c:\windows\system32\\",
    r"c:\windows\syswow64\\",
    r"c:\windows\winsxs\\",
    r"c:\windows\servicing\\",
    r"c:\windows\system32\catroot\\",
    r"c:\windows\system32\catroot2\\",
    r"c:\windows\system32\drivers\\",
    r"c:\windows\system32\driverstore\\",
    r"c:\program files\\",
    r"c:\program files (x86)\\",
]

# Extensions that are *often* baseline/noise when found under baseline paths.
# We only apply these aggressively when value indicates a Windows baseline path.
BASELINE_EXTS_UNDER_WIN = {
    ".sys", ".cat", ".inf", ".mui", ".dll", ".exe", ".ocx", ".cpl"
}

# Extensions that are almost never meaningful as "domain"
FILE_EXTS = {
    ".sys", ".dll", ".exe", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".msi",
    ".tmp", ".dat", ".lnk", ".scr", ".com", ".cpl", ".ocx", ".inf", ".cat"
}

RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


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


def normalize_value_str(v: str) -> str:
    return (v or "").strip()


def to_lower_windows_path(v: str) -> str:
    return v.replace("/", "\\").lower()


def startswith_any(v_lower: str, prefixes: List[str]) -> bool:
    return any(v_lower.startswith(p) for p in prefixes)


def split_filename_ext(value: str) -> Tuple[str, str]:
    v = value.strip().strip('"').strip("'")
    base = os.path.basename(v.replace("\\", "/"))
    _, ext = os.path.splitext(base)
    return base, ext.lower()


# -----------------------------
# MISP mapping helpers
# -----------------------------
def misp_map(kind: str) -> Tuple[str, str]:
    """
    Returns (misp_type, misp_category)
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
        "file_name": ("filename", "Artifacts dropped"),
        "registry_key": ("regkey", "Persistence mechanism"),
        "registry_value": ("regkey|value", "Persistence mechanism"),
        "mutex": ("mutex", "Artifacts dropped"),
        "user_agent": ("user-agent", "Network activity"),
        "text": ("text", "Other"),
    }
    return mapping.get(kind, ("text", "Other"))


def should_to_ids(kind: str, confidence: float, value: str) -> bool:
    """
    Conservative default:
    - external IP/domain/url/hash => to_ids true if confidence>=0.7
    - internal/private IP => false
    - file path/name => false by default (until you add hash/signature)
    """
    if kind == "ip":
        ip = value.strip()
        if is_private_or_special_ip(ip):
            return False
        return confidence >= 0.7

    if kind in {"domain", "url", "md5", "sha1", "sha256", "email"}:
        return confidence >= 0.7

    return False


# -----------------------------
# Refine rules
# -----------------------------
def classify_kind(ioc_type: str, value: str) -> str:
    """
    v2.1.2 ioc 'type' -> refined 'kind' (may reclassify)
    """
    t = (ioc_type or "").strip().lower()
    v = normalize_value_str(value)

    # direct pass-through for known kinds
    if t in {"ip", "domain", "url", "email", "md5", "sha1", "sha256", "mutex", "user_agent"}:
        # but domain might be a file name (acpi.sys), fix below
        if t == "domain":
            _, ext = split_filename_ext(v)
            # If it's like "acpi.sys" (no dots beyond extension? actually has dot)
            if ext in FILE_EXTS and not v.lower().endswith((".com", ".net", ".org", ".kr", ".io", ".co", ".biz", ".info")):
                # definitely not a domain in most cases
                # treat as file name/path
                if "\\" in v or ":" in v:
                    return "file_path"
                return "file_name"
        return t

    if t == "file_path":
        return "file_path"

    # fallback
    # if it's a windows path -> file_path
    if "\\" in v or re.match(r"^[A-Za-z]:\\", v):
        return "file_path"

    # if it's an IP string -> ip
    if RE_IPV4.fullmatch(v):
        return "ip"

    return "text"


def is_baseline_noise(kind: str, value: str) -> Tuple[bool, str]:
    """
    Returns (is_noise, reason)
    Only using baseline paths + extension rules.
    """
    v = normalize_value_str(value)
    v_lower = to_lower_windows_path(v)

    if kind in {"file_path", "file_name"}:
        # If full path, check baseline prefixes
        if "\\" in v_lower or re.match(r"^[a-z]:\\", v_lower):
            if startswith_any(v_lower, WIN_BASE_PATH_PREFIXES):
                _, ext = split_filename_ext(v)
                if ext in BASELINE_EXTS_UNDER_WIN:
                    return True, f"baseline_path+ext({ext})"
                # still baseline-ish even if ext unknown
                return True, "baseline_path"
        else:
            # file_name only: noisy extensions like .sys/.cat/.inf treated as baseline by default
            _, ext = split_filename_ext(v)
            if ext in {".sys", ".cat", ".inf", ".mui"}:
                return True, f"baseline_ext_only({ext})"

    if kind == "ip":
        if is_private_or_special_ip(v):
            return True, "private_or_special_ip"

    # Domain sanity: if no TLD-ish and looks like file => noise handled via classify
    return False, ""


def refine_confidence(base_conf: float, kind: str, noise: bool) -> float:
    """
    Minimal semantic adjustments:
    - baseline noise -> clamp to 0.0
    - otherwise keep base (you can later add tool-based boosting)
    """
    c = float(base_conf or 0.0)
    if noise:
        return 0.0
    # clamp
    if c < 0.0:
        c = 0.0
    if c > 1.0:
        c = 1.0
    return round(c, 3)


def build_refined_ioc(i: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convert v2.1.2 ioc item to refined ioc.
    If it's baseline noise -> return None (drop) OR keep with verdict=benign?
    Policy here: DROP baseline noise for MISP-focused refined output.
    """
    ioc_type = i.get("type", "")
    value = normalize_value_str(i.get("value", ""))
    if not value:
        return None

    first_seen = i.get("first_seen", "")
    last_seen = i.get("last_seen", "")
    occ = int(i.get("occurrences", 0) or 0)
    sources = i.get("sources", []) or []
    event_ids = i.get("event_ids", []) or []
    contexts = i.get("contexts", []) or []

    base_conf = float(i.get("max_confidence", 0.0) or 0.0)

    kind = classify_kind(ioc_type, value)
    noise, noise_reason = is_baseline_noise(kind, value)

    # Policy: drop baseline noise from refined output
    if noise:
        return None

    conf = refine_confidence(base_conf, kind, noise=False)

    misp_type, misp_cat = misp_map(kind)
    to_ids = should_to_ids(kind, conf, value)

    verdict = "candidate"
    reasons: List[str] = []
    if conf >= 0.85:
        verdict = "likely_malicious"
        reasons.append("high_confidence")
    elif conf <= 0.2:
        verdict = "low_signal"
        reasons.append("low_confidence")

    # slight hint reason based on kind
    if kind in {"ip", "domain", "url"} and to_ids:
        reasons.append("network_indicator")
    if kind in {"md5", "sha1", "sha256"} and to_ids:
        reasons.append("file_hash_indicator")

    refined = {
        "kind": kind,
        "value": value,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "occurrences": occ,
        "confidence": conf,
        "verdict": verdict,
        "reason": reasons,
        "sources": sources,
        "event_ids": event_ids,
        "contexts": contexts,
        "misp": {
            "type": misp_type,
            "category": misp_cat,
            "to_ids": bool(to_ids),
        },
    }
    return refined


def refined_to_misp_attribute(refined: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """
    Build a MISP attribute-like dict from refined ioc.
    Keep comment short and traceable.
    """
    kind = refined["kind"]
    value = refined["value"]
    conf = float(refined.get("confidence", 0.0) or 0.0)

    misp_type = refined.get("misp", {}).get("type", "text")
    misp_cat = refined.get("misp", {}).get("category", "Other")
    to_ids = bool(refined.get("misp", {}).get("to_ids", False))

    src = ""
    sources = refined.get("sources", []) or []
    if sources:
        src = sources[0]

    eid = ""
    eids = refined.get("event_ids", []) or []
    if eids:
        eid = eids[0]

    comment = f"Krino {case_id} | kind={kind} | conf={conf}"
    if src:
        comment += f" | src={src}"
    if eid:
        comment += f" | event_id={eid}"

    return {
        "type": misp_type,
        "category": misp_cat,
        "value": value,
        "to_ids": to_ids,
        "comment": comment,
    }


# -----------------------------
# IO Layout helpers
# -----------------------------
def detect_ioc_inputs(report_root: str) -> Tuple[str, str, str]:
    """
    Return (ioc_dir, raw_dir, raw_iocs_path) where raw_iocs_path exists.
    Supports:
      - <root>/ioc/raw/iocs.json
      - <root>/ioc/iocs.json
    """
    ioc_dir = os.path.join(report_root, "ioc")
    raw_dir = os.path.join(ioc_dir, "raw")
    refined_dir = os.path.join(ioc_dir, "refined")

    ensure_dir(ioc_dir)
    ensure_dir(raw_dir)
    ensure_dir(refined_dir)

    p1 = os.path.join(raw_dir, "iocs.json")
    p2 = os.path.join(ioc_dir, "iocs.json")

    if os.path.isfile(p1):
        return (ioc_dir, raw_dir, p1)

    if os.path.isfile(p2):
        # legacy flat layout -> move into raw/
        move_to_raw(report_root, ioc_dir, raw_dir)
        if os.path.isfile(p1):
            return (ioc_dir, raw_dir, p1)

    raise FileNotFoundError("iocs.json not found under ioc/ or ioc/raw/")


def move_to_raw(report_root: str, ioc_dir: str, raw_dir: str) -> None:
    """
    If v2.1.2 outputs exist in ioc/ root, move them into ioc/raw/.
    (No overwrite; if raw already exists, we keep raw and leave flat files untouched.)
    """
    # candidates in flat ioc/
    flat_candidates = [
        ("iocs.json", "iocs.json"),
        ("misp_attributes.json", "misp_attributes.json"),
        ("summary.json", "summary.json"),
    ]
    for src_name, dst_name in flat_candidates:
        src = os.path.join(ioc_dir, src_name)
        dst = os.path.join(raw_dir, dst_name)
        if os.path.isfile(src) and not os.path.isfile(dst):
            os.rename(src, dst)


def run(report_root: str) -> Dict[str, Any]:
    report_root = os.path.abspath(os.path.expanduser(report_root))
    case_id = os.path.basename(report_root)

    ioc_dir, raw_dir, raw_iocs_path = detect_ioc_inputs(report_root)
    refined_dir = os.path.join(ioc_dir, "refined")

    raw_obj = read_json(raw_iocs_path)
    raw_iocs = raw_obj.get("iocs", [])
    if not isinstance(raw_iocs, list):
        raise ValueError("Invalid iocs.json format: expected { iocs: [...] }")

    refined_iocs: List[Dict[str, Any]] = []
    dropped = 0

    for item in raw_iocs:
        if not isinstance(item, dict):
            continue
        r = build_refined_ioc(item)
        if r is None:
            dropped += 1
            continue
        refined_iocs.append(r)

    # sort by confidence desc, occurrences desc
    refined_iocs.sort(key=lambda x: (float(x.get("confidence", 0.0)), int(x.get("occurrences", 0))), reverse=True)

    # build refined misp attributes
    refined_attrs: List[Dict[str, Any]] = []
    seen_attr = set()
    for r in refined_iocs:
        a = refined_to_misp_attribute(r, case_id)
        k = f"{a.get('type','')}::{a.get('value','')}".lower()
        if k in seen_attr:
            continue
        seen_attr.add(k)
        refined_attrs.append(a)

    # write outputs
    out_iocs = os.path.join(refined_dir, "iocs_refined.json")
    out_attrs = os.path.join(refined_dir, "misp_attributes_refined.json")
    out_sum = os.path.join(refined_dir, "summary_refined.json")

    write_json(out_iocs, {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "policy": {
            "baseline": "windows_paths + extension_based",
            "drop_private_ip": True,
            "drop_windows_baseline_files": True
        },
        "iocs": refined_iocs
    })

    write_json(out_attrs, {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "attributes": refined_attrs
    })

    summary = {
        "case_id": case_id,
        "created_at": utc_now_iso(),
        "inputs": {
            "raw_iocs": relpath(raw_iocs_path, report_root),
            "raw_dir": relpath(raw_dir, report_root),
        },
        "outputs": {
            "iocs_refined": relpath(out_iocs, report_root),
            "misp_attributes_refined": relpath(out_attrs, report_root),
            "summary_refined": relpath(out_sum, report_root),
        },
        "stats": {
            "raw_unique_iocs": len(raw_iocs),
            "refined_unique_iocs": len(refined_iocs),
            "dropped_as_baseline_or_private": dropped,
            "refined_misp_attributes": len(refined_attrs),
        },
        "notes": [
            "v2.1.2 raw outputs are preserved under ioc/raw/.",
            "v2.1.3 refined outputs are written under ioc/refined/ and are intended for MISP ingestion.",
            "Baseline policy is conservative: Windows core paths + noisy extensions are dropped.",
        ]
    }
    write_json(out_sum, summary)

    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="ODEA Krino v2.1.3 IOC Refiner (MISP-ready)")
    ap.add_argument("report_root", help="Path to v2_report/<case_dir>")
    args = ap.parse_args()

    summary = run(args.report_root)

    print("\n[✓] IOC refinement complete (v2.1.3)")
    print(f" - {summary['outputs']['iocs_refined']}")
    print(f" - {summary['outputs']['misp_attributes_refined']}")
    print(f" - Dropped: {summary['stats']['dropped_as_baseline_or_private']}")
    print(f" - Refined IOCs: {summary['stats']['refined_unique_iocs']} | MISP attrs: {summary['stats']['refined_misp_attributes']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
