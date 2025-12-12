#!/usr/bin/env python3
# normalizer.py
#
# ODEA Krino v2.2 - Evidence Normalization Layer
# - Reads your existing v2 evidence folder structure:
#     <report_root>/
#       evtx/ (raw)
#       chainsaw/chainsaw_report.json
#       osquery/*.json
#       velociraptor/*.jsonl
#       misc/
#
# - Builds bundles/ (optional) + bundle_index.json
# - Produces normalized/events.jsonl (+ normalized/summary.json)
#
# Design goals (based on your code):
# 1) Collectors remain "raw/detection" writers (do NOT mutate their outputs)
# 2) Normalizer is read-only over raw evidence and emits unified events
# 3) Robust: chainsaw output formats vary across versions; handle best-effort
#
# NOTE:
# - Osquery and Velociraptor produce "snapshot/dataset" evidence (not true events).
#   We still emit low-confidence "state observation" events so v3+ can consume.
# - Chainsaw detections produce higher-confidence events.

import os
import sys
import json
import uuid
import time
import argparse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------
# Helpers
# ---------------------------

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now_iso() -> str:
    return time.strftime(ISO_FMT, time.gmtime())


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def append_jsonl(path: str, items: Iterable[Dict[str, Any]]) -> int:
    count = 0
    with open(path, "a", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
            count += 1
    return count


def safe_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        if isinstance(v, bool):
            return int(v)
        return int(str(v))
    except Exception:
        return None


def is_iso_like(s: str) -> bool:
    # Very light check; we avoid dependencies.
    if not isinstance(s, str):
        return False
    return "T" in s and ("Z" in s or "+" in s or "-" in s)


def pick_first(*vals: Any) -> Any:
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return None


def walk_files(root: str, exts: Tuple[str, ...]) -> List[str]:
    out: List[str] = []
    if not os.path.isdir(root):
        return out
    for name in os.listdir(root):
        p = os.path.join(root, name)
        if os.path.isfile(p) and name.lower().endswith(exts):
            out.append(p)
    out.sort()
    return out


def relpath(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except Exception:
        return path


# ---------------------------
# Unified Event Model (K-UEM)
# ---------------------------

def make_event(
    *,
    timestamp: str,
    host: Dict[str, Any],
    source: Dict[str, Any],
    actor: Optional[Dict[str, Any]] = None,
    action: Optional[Dict[str, Any]] = None,
    severity: str = "info",
    confidence: float = 0.0,
    tags: Optional[List[str]] = None,
    raw: Optional[Any] = None,
    raw_ref: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source": source,
        "host": host,
        "actor": actor or {},
        "action": action or {},
        "severity": severity,
        "confidence": confidence,
        "tags": tags or [],
        "raw_ref": raw_ref or {},
        "raw": raw if raw is not None else {},
    }


# ---------------------------
# Bundle discovery (based on your on-disk structure)
# ---------------------------

@dataclass
class Bundle:
    tool: str
    collected_at: str
    host: Dict[str, Any]
    base_dir: str
    payload: Dict[str, Any]


def discover_host(report_root: str, fallback_ip: str = "") -> Dict[str, Any]:
    # Your v2 structure doesn't store host meta explicitly; keep minimal.
    return {"ip": fallback_ip}


def find_evtx_extract_dir(report_root: str) -> Optional[str]:
    evtx_dir = os.path.join(report_root, "evtx")
    if not os.path.isdir(evtx_dir):
        return None
    # Prefer newest extract_* directory
    extracts = []
    for name in os.listdir(evtx_dir):
        p = os.path.join(evtx_dir, name)
        if os.path.isdir(p) and name.startswith("extract_"):
            extracts.append((name, p))
    extracts.sort(reverse=True)
    return extracts[0][1] if extracts else None


def build_evtx_bundle(report_root: str, host: Dict[str, Any]) -> Optional[Bundle]:
    extract_dir = find_evtx_extract_dir(report_root)
    if not extract_dir:
        return None
    logs = []
    for fn in ("Security.evtx", "System.evtx", "Application.evtx"):
        p = os.path.join(extract_dir, fn)
        if os.path.isfile(p):
            logs.append(fn)
    if not logs:
        # still allow bundle with empty logs, but it's likely mis-collected
        logs = []

    return Bundle(
        tool="evtx",
        collected_at=utc_now_iso(),
        host=host,
        base_dir=extract_dir,
        payload={"logs": logs, "extract_dir": relpath(extract_dir, report_root)},
    )


def build_chainsaw_bundle(report_root: str, host: Dict[str, Any]) -> Optional[Bundle]:
    p = os.path.join(report_root, "chainsaw", "chainsaw_report.json")
    if not os.path.isfile(p):
        return None
    evtx_extract = find_evtx_extract_dir(report_root)
    return Bundle(
        tool="chainsaw",
        collected_at=utc_now_iso(),
        host=host,
        base_dir=os.path.join(report_root, "chainsaw"),
        payload={
            "report_file": relpath(p, report_root),
            "report_path": p,
            "input_evtx_extract": relpath(evtx_extract, report_root) if evtx_extract else "",
        },
    )


def build_osquery_bundle(report_root: str, host: Dict[str, Any]) -> Optional[Bundle]:
    osq_dir = os.path.join(report_root, "osquery")
    if not os.path.isdir(osq_dir):
        return None
    json_files = walk_files(osq_dir, (".json",))
    if not json_files:
        return None
    tables = {}
    for p in json_files:
        name = os.path.splitext(os.path.basename(p))[0]
        tables[name] = {"file": os.path.basename(p), "path": p}
    return Bundle(
        tool="osquery",
        collected_at=utc_now_iso(),
        host=host,
        base_dir=osq_dir,
        payload={"tables": tables},
    )


def build_velociraptor_bundle(report_root: str, host: Dict[str, Any]) -> Optional[Bundle]:
    vdir = os.path.join(report_root, "velociraptor")
    if not os.path.isdir(vdir):
        return None
    jsonl_files = walk_files(vdir, (".jsonl",))
    if not jsonl_files:
        return None
    artifacts = {}
    for p in jsonl_files:
        name = os.path.splitext(os.path.basename(p))[0]
        artifacts[name] = {"file": os.path.basename(p), "path": p}
    return Bundle(
        tool="velociraptor",
        collected_at=utc_now_iso(),
        host=host,
        base_dir=vdir,
        payload={"artifacts": artifacts},
    )


def write_bundles(report_root: str, bundles: List[Bundle]) -> str:
    bdir = os.path.join(report_root, "bundles")
    ensure_dir(bdir)

    out_map = {}
    for b in bundles:
        out = {
            "tool": b.tool,
            "collected_at": b.collected_at,
            "host": b.host,
            "base_dir": relpath(b.base_dir, report_root),
            **b.payload,
        }
        fp = os.path.join(bdir, f"{b.tool}_bundle.json")
        write_json(fp, out)
        out_map[b.tool] = relpath(fp, report_root)

    index = {
        "case_id": os.path.basename(report_root),
        "created_at": utc_now_iso(),
        "host": bundles[0].host if bundles else {},
        "bundles": [{"tool": k, "file": v} for k, v in out_map.items()],
    }
    index_path = os.path.join(report_root, "bundle_index.json")
    write_json(index_path, index)
    return index_path


# ---------------------------
# Normalizers (tool-specific)
# ---------------------------

# A small mapping from artifact/table name to action category for "state observations"
OSQUERY_CATEGORY_HINTS: Dict[str, str] = {
    "processes": "process",
    "process_open_sockets": "network",
    "listening_ports": "network",
    "connections": "network",
    "services": "service",
    "drivers": "driver",
    "kernel_drivers": "driver",
    "startup_items": "persistence",
    "scheduled_tasks": "persistence",
    "registry_run_hklm": "registry",
    "registry_run_hkcu": "registry",
    "registry_rdp": "registry",
    "users": "user",
    "groups": "user",
    "user_groups": "user",
    "logged_in_users": "auth",
    "logon_sessions": "auth",
    "usb_devices": "device",
    "usb_devices_history": "device",
    "windows_security_products": "security",
}

VELO_CATEGORY_HINTS: Dict[str, str] = {
    "processes": "process",
    "services": "service",
    "drivers": "driver",
    "autoruns": "persistence",
    "scheduled_tasks": "persistence",
    "run_keys": "registry",
    "startup_approved": "registry",
    "prefetch": "execution",
    "amcache": "execution",
    "shimcache": "execution",
    "mft": "file",
    "usn_journal": "file",
    "jump_lists": "execution",
    "lnk_files": "execution",
    "usb_devices": "device",
    "rdp_connections": "network",
    "netstat": "network",
    "dns_cache": "network",
    "firewall_logs": "network",
    # evtx_* artifacts are "log-derived"
    "evtx_fast": "log",
    "evtx_security": "log",
    "evtx_system": "log",
    "evtx_application": "log",
    "evtx_powershell": "log",
    "evtx_powershell_oper": "log",
}

SEVERITY_MAP = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

CONFIDENCE_DEFAULTS = {
    "chainsaw": 0.80,
    "osquery": 0.30,
    "velociraptor": 0.60,
    "evtx": 0.20,  # raw log presence only
}


def normalize_evtx_bundle(bundle: Bundle) -> List[Dict[str, Any]]:
    # Emit a single "evidence available" event. (Raw EVTX isn't parsed here.)
    logs = bundle.payload.get("logs", [])
    ts = bundle.collected_at
    host = bundle.host
    return [
        make_event(
            timestamp=ts,
            host=host,
            source={"tool": "evtx", "module": "collect", "raw_id": ""},
            actor={"type": "host", "name": host.get("ip", "")},
            action={
                "category": "log",
                "operation": "collect",
                "object": relpath(bundle.base_dir, os.path.dirname(os.path.dirname(bundle.base_dir)))
                if bundle.base_dir else "",
                "details": {"logs": logs},
            },
            severity="info",
            confidence=CONFIDENCE_DEFAULTS["evtx"],
            tags=["evtx", "raw"],
            raw=bundle.payload,
        )
    ]


def _iter_jsonl(path: str, max_lines: int = 20000) -> Iterable[Tuple[int, Dict[str, Any]]]:
    # Best-effort JSONL reader. Stops at max_lines to avoid runaway huge files.
    i = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if i >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield (i, obj)
                i += 1
            except Exception:
                continue


def _guess_timestamp_from_record(rec: Dict[str, Any], fallback: str) -> str:
    # Many sources use different keys. We'll try common ones.
    candidates = [
        rec.get("TimeCreated"),
        rec.get("time"),
        rec.get("timestamp"),
        rec.get("EventTime"),
        rec.get("UtcTime"),
        rec.get("Created"),
        rec.get("StartTime"),
        rec.get("start_time"),
        rec.get("LastWriteTime"),
        rec.get("last_write_time"),
        rec.get("last_visit_time"),
        rec.get("expires_utc"),
    ]
    for c in candidates:
        if isinstance(c, str) and is_iso_like(c):
            return c
    # Sometimes it's numeric (Windows epoch, unix, etc). We'll not convert here safely.
    return fallback


def normalize_osquery_bundle(bundle: Bundle, per_row_limit: int = 200) -> List[Dict[str, Any]]:
    # For osquery: emit low-confidence "state observations".
    # Strategy:
    # - For selected tables, emit per-row events (bounded).
    # - For everything else, emit a summary event per table.
    events: List[Dict[str, Any]] = []
    ts = bundle.collected_at
    host = bundle.host

    tables: Dict[str, Dict[str, Any]] = bundle.payload.get("tables", {}) or {}
    for tname, meta in tables.items():
        fpath = meta.get("path")
        if not fpath or not os.path.isfile(fpath):
            continue

        category = OSQUERY_CATEGORY_HINTS.get(tname, "state")
        try:
            data = read_json(fpath)
            if not isinstance(data, list):
                # osquery JSON usually is list; if not, wrap
                data_list = [data]
            else:
                data_list = data
        except Exception as e:
            events.append(
                make_event(
                    timestamp=ts,
                    host=host,
                    source={"tool": "osquery", "module": tname, "raw_id": ""},
                    action={
                        "category": "error",
                        "operation": "parse_failed",
                        "object": meta.get("file", ""),
                        "details": {"error": str(e)},
                    },
                    severity="low",
                    confidence=0.1,
                    tags=["osquery", "parse_error"],
                    raw={"file": meta.get("file", ""), "path": fpath},
                )
            )
            continue

        # Tables we want row-level for (bounded)
        row_level_tables = {
            "processes",
            "connections",
            "listening_ports",
            "process_open_sockets",
            "services",
            "drivers",
            "kernel_drivers",
            "startup_items",
            "scheduled_tasks",
            "registry_run_hklm",
            "registry_run_hkcu",
            "usb_devices",
            "usb_devices_history",
            "logged_in_users",
            "logon_sessions",
        }

        if tname in row_level_tables:
            for idx, row in enumerate(data_list[:per_row_limit]):
                actor = {}
                action_details = dict(row) if isinstance(row, dict) else {"value": row}

                # A few common actor hints
                if tname == "processes" and isinstance(row, dict):
                    actor = {
                        "type": "process",
                        "name": row.get("name") or "",
                        "pid": safe_int(row.get("pid")) or 0,
                        "user": row.get("uid") if row.get("uid") is not None else "",
                    }
                    obj = row.get("path") or row.get("name") or ""
                elif tname in {"connections", "listening_ports", "process_open_sockets"} and isinstance(row, dict):
                    actor = {
                        "type": "process",
                        "name": "",
                        "pid": safe_int(row.get("pid")) or 0,
                    }
                    obj = f"{row.get('local_address')}:{row.get('local_port')} -> {row.get('remote_address')}:{row.get('remote_port')}"
                else:
                    obj = meta.get("file", "")

                events.append(
                    make_event(
                        timestamp=ts,
                        host=host,
                        source={"tool": "osquery", "module": tname, "raw_id": ""},
                        actor=actor,
                        action={
                            "category": category,
                            "operation": "observe",
                            "object": obj,
                            "details": action_details,
                        },
                        severity="info",
                        confidence=CONFIDENCE_DEFAULTS["osquery"],
                        tags=["osquery", tname],
                        raw_ref={"bundle_tool": "osquery", "table": tname, "index": idx},
                        raw=row,
                    )
                )
        else:
            events.append(
                make_event(
                    timestamp=ts,
                    host=host,
                    source={"tool": "osquery", "module": tname, "raw_id": ""},
                    actor={"type": "host", "name": host.get("ip", "")},
                    action={
                        "category": category,
                        "operation": "observe_table",
                        "object": meta.get("file", ""),
                        "details": {"row_count": len(data_list)},
                    },
                    severity="info",
                    confidence=CONFIDENCE_DEFAULTS["osquery"],
                    tags=["osquery", "table_summary", tname],
                    raw={"file": meta.get("file", ""), "row_count": len(data_list)},
                )
            )

    return events


def normalize_velociraptor_bundle(bundle: Bundle, per_artifact_limit: int = 300) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    ts = bundle.collected_at
    host = bundle.host

    artifacts: Dict[str, Dict[str, Any]] = bundle.payload.get("artifacts", {}) or {}
    for aname, meta in artifacts.items():
        fpath = meta.get("path")
        if not fpath or not os.path.isfile(fpath):
            continue

        category = VELO_CATEGORY_HINTS.get(aname, "dataset")
        # For some high-signal artifacts, emit per-row (bounded)
        row_level = aname in {
            "processes",
            "services",
            "drivers",
            "autoruns",
            "scheduled_tasks",
            "run_keys",
            "prefetch",
            "amcache",
            "shimcache",
            "rdp_connections",
            "netstat",
            "dns_cache",
            "usb_devices",
        } or aname.startswith("evtx_")

        if row_level:
            for idx, rec in _iter_jsonl(fpath, max_lines=per_artifact_limit):
                ts2 = _guess_timestamp_from_record(rec, ts)

                actor = {}
                obj = meta.get("file", "")

                if aname == "processes" and isinstance(rec, dict):
                    actor = {
                        "type": "process",
                        "name": pick_first(rec.get("Name"), rec.get("name"), ""),
                        "pid": safe_int(pick_first(rec.get("Pid"), rec.get("pid"))) or 0,
                        "user": pick_first(rec.get("Username"), rec.get("username"), ""),
                    }
                    obj = pick_first(rec.get("Exe"), rec.get("Path"), rec.get("path"), rec.get("Name"), "")
                elif aname in {"autoruns", "run_keys", "scheduled_tasks"} and isinstance(rec, dict):
                    actor = {"type": "persistence", "name": pick_first(rec.get("Name"), rec.get("name"), "")}
                    obj = pick_first(rec.get("Path"), rec.get("path"), rec.get("Command"), rec.get("command"), meta.get("file", ""))
                elif aname.startswith("evtx_") and isinstance(rec, dict):
                    actor = {"type": "log", "name": aname}
                    obj = pick_first(rec.get("EventID"), rec.get("EventId"), rec.get("event_id"), meta.get("file", ""))
                else:
                    actor = {"type": "dataset", "name": aname}

                events.append(
                    make_event(
                        timestamp=ts2,
                        host=host,
                        source={"tool": "velociraptor", "module": aname, "raw_id": ""},
                        actor=actor,
                        action={
                            "category": category,
                            "operation": "observe",
                            "object": obj,
                            "details": rec if isinstance(rec, dict) else {"value": rec},
                        },
                        severity="info",
                        confidence=CONFIDENCE_DEFAULTS["velociraptor"],
                        tags=["velociraptor", aname],
                        raw_ref={"bundle_tool": "velociraptor", "artifact": aname, "line": idx},
                        raw=rec,
                    )
                )
        else:
            # Summary only
            # Count lines (bounded)
            cnt = 0
            for _idx, _rec in _iter_jsonl(fpath, max_lines=1000000):
                cnt += 1
                if cnt >= 5000:
                    break
            events.append(
                make_event(
                    timestamp=ts,
                    host=host,
                    source={"tool": "velociraptor", "module": aname, "raw_id": ""},
                    actor={"type": "dataset", "name": aname},
                    action={
                        "category": category,
                        "operation": "observe_artifact",
                        "object": meta.get("file", ""),
                        "details": {"row_count_est": cnt},
                    },
                    severity="info",
                    confidence=CONFIDENCE_DEFAULTS["velociraptor"],
                    tags=["velociraptor", "artifact_summary", aname],
                    raw={"file": meta.get("file", ""), "row_count_est": cnt},
                )
            )

    return events


def _normalize_severity(level: Any) -> str:
    if not level:
        return "medium"
    s = str(level).strip().lower()
    return SEVERITY_MAP.get(s, s if s in {"info", "low", "medium", "high", "critical"} else "medium")


def _extract_detections_from_chainsaw(obj: Any) -> List[Dict[str, Any]]:
    """
    Chainsaw JSON output formats vary.
    We try common shapes:

    - List[dict] of detections
    - {"detections": [...]} or {"hits": [...]} or {"results": [...]}
    - {"rules": {...}} etc.

    We return list of "detection-like" dicts.
    """
    if obj is None:
        return []
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for k in ("detections", "hits", "results", "alerts", "matches"):
            v = obj.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        # Sometimes nested:
        for k, v in obj.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                # last resort: pick first list of dicts
                return v
    return []


def _pick_sigma_fields(det: Dict[str, Any]) -> Tuple[str, str, str, Dict[str, Any]]:
    """
    Return (rule_id, title, level, event_fields)
    best-effort from arbitrary detection dict.
    """
    rule_id = pick_first(det.get("rule_id"), det.get("id"), det.get("RuleID"), det.get("RuleId"), det.get("sigma_rule_id"), "")
    title = pick_first(det.get("title"), det.get("name"), det.get("RuleTitle"), det.get("rule_title"), det.get("description"), "")
    level = pick_first(det.get("level"), det.get("Level"), det.get("severity"), det.get("Severity"), "")

    # Where event fields might live:
    event_fields = {}
    for k in ("event", "Event", "data", "Data", "fields", "Fields", "record", "Record"):
        v = det.get(k)
        if isinstance(v, dict):
            event_fields = v
            break
    return str(rule_id or ""), str(title or ""), str(level or ""), event_fields


def normalize_chainsaw_bundle(bundle: Bundle) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    ts = bundle.collected_at
    host = bundle.host

    report_path = bundle.payload.get("report_path")
    if not report_path or not os.path.isfile(report_path):
        # fallback: try relative
        guess = os.path.join(bundle.base_dir, "chainsaw_report.json")
        if os.path.isfile(guess):
            report_path = guess
        else:
            return []

    try:
        obj = read_json(report_path)
    except Exception as e:
        return [
            make_event(
                timestamp=ts,
                host=host,
                source={"tool": "chainsaw", "module": "sigma", "raw_id": ""},
                action={
                    "category": "error",
                    "operation": "parse_failed",
                    "object": relpath(report_path, os.path.dirname(report_path)),
                    "details": {"error": str(e)},
                },
                severity="high",
                confidence=0.2,
                tags=["chainsaw", "parse_error"],
                raw={"file": relpath(report_path, os.path.dirname(report_path))},
            )
        ]

    detections = _extract_detections_from_chainsaw(obj)

    # If we couldn't find a detection list, emit a single summary event so pipeline doesn't look empty.
    if not detections:
        return [
            make_event(
                timestamp=ts,
                host=host,
                source={"tool": "chainsaw", "module": "sigma", "raw_id": ""},
                actor={"type": "engine", "name": "chainsaw"},
                action={
                    "category": "detection",
                    "operation": "analyze",
                    "object": relpath(report_path, os.path.dirname(os.path.dirname(report_path))),
                    "details": {"note": "No detections list recognized; keep raw for manual review."},
                },
                severity="info",
                confidence=0.4,
                tags=["chainsaw", "sigma", "summary_only"],
                raw=obj,
            )
        ]

    for idx, det in enumerate(detections):
        rule_id, title, level, ev = _pick_sigma_fields(det)
        sev = _normalize_severity(level)
        # Confidence based on severity (simple heuristic)
        conf = CONFIDENCE_DEFAULTS["chainsaw"]
        if sev == "critical":
            conf = 0.90
        elif sev == "high":
            conf = 0.85
        elif sev == "medium":
            conf = 0.75
        elif sev == "low":
            conf = 0.65
        else:
            conf = 0.70

        # Try to infer actor/action from event fields
        image = pick_first(ev.get("Image"), ev.get("ProcessName"), ev.get("process"), ev.get("process_name"), ev.get("NewProcessName"))
        cmd = pick_first(ev.get("CommandLine"), ev.get("cmdline"), ev.get("ProcessCommandLine"), ev.get("ParentCommandLine"))
        pid = safe_int(pick_first(ev.get("ProcessId"), ev.get("ProcessID"), ev.get("pid"), ev.get("NewProcessId")))
        user = pick_first(ev.get("User"), ev.get("SubjectUserName"), ev.get("AccountName"), ev.get("username"))

        ts2 = _guess_timestamp_from_record(ev if isinstance(ev, dict) else {}, ts)

        actor = {}
        if image or pid or user:
            actor = {
                "type": "process",
                "name": str(image or ""),
                "pid": int(pid) if pid is not None else 0,
                "user": str(user or ""),
            }

        action_obj = str(image or title or rule_id or "sigma_detection")
        action_details = {"title": title, "rule_id": rule_id}
        if cmd:
            action_details["command_line"] = cmd

        # Keep full detection raw for traceability.
        events.append(
            make_event(
                timestamp=ts2,
                host=host,
                source={"tool": "chainsaw", "module": "sigma", "raw_id": rule_id},
                actor=actor,
                action={
                    "category": "detection",
                    "operation": "match",
                    "object": action_obj,
                    "details": action_details,
                },
                severity=sev,
                confidence=conf,
                tags=["chainsaw", "sigma"] + ([sev] if sev else []) + ([rule_id] if rule_id else []),
                raw_ref={"bundle_tool": "chainsaw", "report": "chainsaw_report.json", "index": idx},
                raw=det,
            )
        )

    return events


def normalize_bundle(bundle: Bundle) -> List[Dict[str, Any]]:
    if bundle.tool == "evtx":
        return normalize_evtx_bundle(bundle)
    if bundle.tool == "chainsaw":
        return normalize_chainsaw_bundle(bundle)
    if bundle.tool == "osquery":
        return normalize_osquery_bundle(bundle)
    if bundle.tool == "velociraptor":
        return normalize_velociraptor_bundle(bundle)
    return []


# ---------------------------
# Driver
# ---------------------------

def normalize_report_root(
    report_root: str,
    *,
    host_ip: str = "",
    write_bundle_files: bool = True,
    per_osquery_row_limit: int = 200,
    per_velo_artifact_limit: int = 300,
) -> Dict[str, Any]:
    """
    Main entry:
    - discovers bundles from on-disk structure
    - optionally writes bundles/*.json + bundle_index.json
    - writes normalized/events.jsonl + normalized/summary.json
    """
    report_root = os.path.abspath(os.path.expanduser(report_root))
    if not os.path.isdir(report_root):
        raise FileNotFoundError(f"report_root not found: {report_root}")

    host = discover_host(report_root, fallback_ip=host_ip)

    bundles: List[Bundle] = []
    b1 = build_evtx_bundle(report_root, host)
    if b1:
        bundles.append(b1)
    b2 = build_chainsaw_bundle(report_root, host)
    if b2:
        bundles.append(b2)
    b3 = build_osquery_bundle(report_root, host)
    if b3:
        bundles.append(b3)
    b4 = build_velociraptor_bundle(report_root, host)
    if b4:
        bundles.append(b4)

    # Apply limits (update normalization fns via args)
    # (We store limits in summary only; functions use their own args in calls below.)
    bundle_index_path = ""
    if write_bundle_files and bundles:
        bundle_index_path = write_bundles(report_root, bundles)

    # Normalize
    norm_dir = os.path.join(report_root, "normalized")
    ensure_dir(norm_dir)

    events_path = os.path.join(norm_dir, "events.jsonl")
    # reset file each run
    if os.path.exists(events_path):
        os.remove(events_path)

    totals = {"events": 0, "by_tool": {}}

    for b in bundles:
        if b.tool == "osquery":
            evs = normalize_osquery_bundle(b, per_row_limit=per_osquery_row_limit)
        elif b.tool == "velociraptor":
            evs = normalize_velociraptor_bundle(b, per_artifact_limit=per_velo_artifact_limit)
        else:
            evs = normalize_bundle(b)

        c = append_jsonl(events_path, evs)
        totals["events"] += c
        totals["by_tool"][b.tool] = totals["by_tool"].get(b.tool, 0) + c

    summary = {
        "case_id": os.path.basename(report_root),
        "created_at": utc_now_iso(),
        "report_root": report_root,
        "bundle_index": bundle_index_path,
        "counts": totals,
        "limits": {
            "osquery_per_table_rows": per_osquery_row_limit,
            "velociraptor_per_artifact_rows": per_velo_artifact_limit,
        },
        "notes": [
            "Osquery/Velociraptor are emitted as low/medium-confidence observations (snapshot/dataset).",
            "Chainsaw Sigma detections are emitted as higher-confidence detection events.",
            "Raw evidence remains unchanged under evtx/, osquery/, velociraptor/, chainsaw/.",
        ],
    }
    write_json(os.path.join(norm_dir, "summary.json"), summary)

    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="ODEA Krino v2.2 Normalizer")
    ap.add_argument("report_root", help="Path to v2_report/<case_dir>")
    ap.add_argument("--host-ip", default="", help="Optional IP to embed in events")
    ap.add_argument("--no-write-bundles", action="store_true", help="Do not write bundles/*.json and bundle_index.json")
    ap.add_argument("--osq-row-limit", type=int, default=200, help="Max per-table osquery row events")
    ap.add_argument("--velo-row-limit", type=int, default=300, help="Max per-artifact velociraptor row events")
    args = ap.parse_args()

    summary = normalize_report_root(
        args.report_root,
        host_ip=args.host_ip,
        write_bundle_files=not args.no_write_bundles,
        per_osquery_row_limit=args.osq_row_limit,
        per_velo_artifact_limit=args.velo_row_limit,
    )

    print("\n[✓] Normalization complete")
    print(" - normalized/events.jsonl")
    print(" - normalized/summary.json")
    if summary.get("bundle_index"):
        print(" - bundle_index.json + bundles/*.json")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
