#!/usr/bin/env python3
import getpass
import sys
import os
import time

# -----------------------------
# Import pipeline modules
# -----------------------------
import remote_evtx_collect
import analyze_evtx
import osquery_collect
import velo_one_shot   # ★ 기존 파일명 그대로 사용 (변경 금지)

# v2.2 Normalizer
import normalizer

# v2.1.2 IOC Extractor
import ioc_extractor

# v2.1.3 IOC Refiner (MISP-ready)
import ioc_refiner


# ---------------------------------------------------------
# v2 Report Root Folder 생성
# ---------------------------------------------------------
def prepare_v2_report_root(username):
    """
    ~/odea_krino/evidence/v2_report/<username>_<YYYYMMDD_HHMM>/
    """
    ts = time.strftime("%Y%m%d_%H%M")
    base = os.path.expanduser("~/odea_krino/evidence/v2_report")
    root = os.path.join(base, f"{username}_{ts}")

    os.makedirs(root, exist_ok=True)
    for d in ("evtx", "chainsaw", "osquery", "velociraptor", "misc"):
        os.makedirs(os.path.join(root, d), exist_ok=True)

    print(f"\n[+] v2 Report Root 생성됨 → {root}\n")
    return root


# -----------------------------
# Mini-EDR v2.2 + IOC v2.1.3
# -----------------------------
def main():
    print("\n===== Mini-EDR v2.2 + IOC v2.1.3 Full Pipeline =====\n")

    target_ip = input("Target IP: ").strip()
    username  = input("Username: ").strip()
    password  = getpass.getpass("Password: ").strip()

    # 1) Evidence Root
    report_root = prepare_v2_report_root(username)

    # -------------------------------------------------
    # [1/7] EVTX
    # -------------------------------------------------
    print("\n[1/7] EVTX 수집 시작...\n")
    evtx_folder = remote_evtx_collect.run(
        target_ip, username, password, report_root
    )
    if not evtx_folder:
        print("[!] EVTX 수집 실패 → 중단")
        sys.exit(1)

    # -------------------------------------------------
    # [2/7] Chainsaw
    # -------------------------------------------------
    print("\n[2/7] Chainsaw + Sigma 분석 시작...\n")
    report_json = analyze_evtx.run(evtx_folder, report_root)
    if not report_json:
        print("[!] Chainsaw 분석 실패 → 중단")
        sys.exit(1)

    # -------------------------------------------------
    # [3/7] OSQuery
    # -------------------------------------------------
    print("\n[3/7] OSQuery Sweep 시작...\n")
    osquery_folder = osquery_collect.run(
        target_ip, username, password, report_root
    )
    if not osquery_folder:
        print("[!] OSQuery Sweep 실패 → 중단")
        sys.exit(1)

    # -------------------------------------------------
    # [4/7] Velociraptor
    # -------------------------------------------------
    print("\n[4/7] Velociraptor Query 시작...\n")
    velo_output = velo_one_shot.run(
        target_ip, username, password, report_root
    )
    if not velo_output:
        print("[!] Velociraptor 실패 → 계속 진행")

    # -------------------------------------------------
    # [5/7] Normalization (v2.2)
    # -------------------------------------------------
    print("\n[5/7] Evidence Normalization (v2.2)...\n")
    try:
        normalizer.normalize_report_root(
            report_root,
            host_ip=target_ip,
            write_bundle_files=True,
            per_osquery_row_limit=200,
            per_velo_artifact_limit=300,
        )
    except Exception as e:
        print(f"[!] Normalization 실패: {e}")
        sys.exit(1)

    print("[✓] Normalization 완료")

    # -------------------------------------------------
    # [6/7] IOC Normalization (v2.1.2 - Raw)
    # -------------------------------------------------
    print("\n[6/7] IOC Normalization (v2.1.2 - Raw)...\n")
    try:
        sys.argv = ["ioc_extractor", report_root]
        ioc_extractor.main()
    except Exception as e:
        print(f"[!] IOC v2.1.2 실패 (파이프라인 유지): {e}")

    # -------------------------------------------------
    # [7/7] IOC Refinement (v2.1.3 - MISP Ready)
    # -------------------------------------------------
    print("\n[7/7] IOC Refinement (v2.1.3 - MISP Ready)...\n")
    try:
        ioc_refiner.run(report_root)
    except Exception as e:
        print(f"[!] IOC v2.1.3 실패 (파이프라인 유지): {e}")

    # -------------------------------------------------
    # Final Summary
    # -------------------------------------------------
    print("\n===== Mini-EDR Pipeline 완료 =====\n")
    print(f"Report Root             : {report_root}")
    print(f"EVTX                    : {evtx_folder}")
    print(f"Chainsaw                : {report_json}")
    print(f"OSQuery                 : {osquery_folder}")
    print(f"Velociraptor            : {velo_output}")
    print(f"Events                  : normalized/events.jsonl")
    print(f"IOC Raw (v2.1.2)        : ioc/raw/iocs.json")
    print(f"IOC Refined (v2.1.3)    : ioc/refined/iocs_refined.json")
    print(f"MISP Attributes Ready   : ioc/refined/misp_attributes_refined.json")
    print("\n[✓] 전체 작업 완료!\n")


if __name__ == "__main__":
    main()
