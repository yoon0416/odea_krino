#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime


# -------------------------------------------------
# Utils
# -------------------------------------------------
def load_json(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------
# Main runner
# -------------------------------------------------
def run(report_root: str):
    report_root = Path(report_root)

    # -----------------------------
    # Paths
    # -----------------------------
    ioc_dir = report_root / "ioc" / "refined"
    misp_dir = report_root / "misp"

    summary_file = ioc_dir / "summary_refined.json"
    attr_file = ioc_dir / "misp_attributes_refined.json"

    ensure_dir(misp_dir)

    # -----------------------------
    # Load data
    # -----------------------------
    summary_raw = load_json(summary_file)
    misp_raw = load_json(attr_file)

    # summary 방어 처리
    summary = {}
    if isinstance(summary_raw, dict):
        summary = summary_raw.get("summary", summary_raw)

    # attributes 추출 (핵심)
    misp_attrs = misp_raw.get("attributes", [])
    if not isinstance(misp_attrs, list):
        misp_attrs = []

    # -----------------------------
    # Event meta
    # -----------------------------
    event_info = summary.get(
        "title",
        f"ODEA Krino Incident - {report_root.name}"
    )

    event_date = summary.get("date")
    if not event_date:
        event_date = datetime.utcnow().strftime("%Y-%m-%d")

    threat_level = summary.get("threat_level_id", 2)
    analysis = summary.get("analysis", 1)

    tags = [{"name": "source:odea-krino"}]
    for tool in summary.get("tool_chain", []):
        tags.append({"name": f"tool:{tool}"})

    # -----------------------------
    # Attribute helpers
    # -----------------------------
    def attrs_by_type(t):
        return [
            a for a in misp_attrs
            if isinstance(a, dict) and a.get("type") == t
        ]

    def build_attr(attr_type, value, category):
        return {
            "type": attr_type,
            "value": value,
            "category": category,
            "to_ids": True
        }

    objects = []

    # -----------------------------
    # Network Object
    # -----------------------------
    network_attrs = []
    for t in ("ip-dst", "domain", "url"):
        for a in attrs_by_type(t):
            network_attrs.append(
                build_attr(t, a["value"], "Network activity")
            )

    if network_attrs:
        objects.append({
            "name": "network-connection",
            "meta-category": "network",
            "Attribute": network_attrs
        })

    # -----------------------------
    # File Object
    # -----------------------------
    file_attrs = []
    for t in ("md5", "sha1", "sha256"):
        for a in attrs_by_type(t):
            file_attrs.append(
                build_attr(t, a["value"], "Payload delivery")
            )

    if file_attrs:
        objects.append({
            "name": "file",
            "meta-category": "file",
            "Attribute": file_attrs
        })

    # -----------------------------
    # Final MISP Event
    # -----------------------------
    misp_event = {
        "Event": {
            "info": event_info,
            "date": event_date,
            "analysis": analysis,
            "threat_level_id": threat_level,
            "distribution": 0,
            "published": False,
            "Org": {
                "name": "ODEA_KRINO"
            },
            "Tag": tags,
            "Object": objects
        }
    }

    # -----------------------------
    # Write output
    # -----------------------------
    output_file = misp_dir / "misp_event.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(misp_event, f, indent=2, ensure_ascii=False)

    print(f"[+] MISP Event JSON created: {output_file}")
