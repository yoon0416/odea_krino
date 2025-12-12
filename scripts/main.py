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
# Mini-EDR v2.2 + IOC v2.1.2
# -----------------------------
def main():
    print("\n===== Mini-EDR v2.2 + IOC v2.1.2 Full Pipeline =====\n")

    target_ip = input("Target IP: ").strip()
    username  = input("Username: ").strip()
    password  = getpass.getpass("Password: ").strip()

    # 1) Evidence Root
    report_root = prepare_v2_report_root(username)

    # -------------------------------------------------
    # [1/6] EVTX
    # -------------------------------------------------
    print("\n[1/6] EVTX 수집 시작...\n")
    evtx_folder = remote_evtx_collect.run(
        target_ip, username, password, report_root
    )
    if not evtx_folder:
        print("[!] EVTX 수집 실패 → 중단")
        sys.exit(1)

    # -------------------------------------------------
    # [2/6] Chainsaw
    # -------------------------------------------------
    print("\n[2/6] Chainsaw + Sigma 분석 시작...\n")
    report_json = analyze_evtx.run(evtx_folder, report_root)
    if not report_json:
        print("[!] Chainsaw 분석 실패 → 중단")
        sys.exit(1)

    # -------------------------------------------------
    # [3/6] OSQuery
    # -------------------------------------------------
    print("\n[3/6] OSQuery Sweep 시작...\n")
    osquery_folder = osquery_collect.run(
        target_ip, username, password, report_root
    )
    if not osquery_folder:
        print("[!] OSQuery Sweep 실패 → 중단")
        sys.exit(1)

    # -------------------------------------------------
    # [4/6] Velociraptor
    # -------------------------------------------------
    print("\n[4/6] Velociraptor Query 시작...\n")
    velo_output = velo_one_shot.run(
        target_ip, username, password, report_root
    )
    if not velo_output:
        print("[!] Velociraptor 실패 → 계속 진행")

    # -------------------------------------------------
    # [5/6] Normalization (v2.2)
    # -------------------------------------------------
    print("\n[5/6] Evidence Normalization (v2.2)...\n")
    try:
        norm_summary = normalizer.normalize_report_root(
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
    # [6/6] IOC Normalization (v2.1.2)
    # -------------------------------------------------
    print("\n[6/6] IOC Normalization (v2.1.2)...\n")
    try:
        # ioc_extractor는 CLI 기반이므로 main 함수 직접 호출
        sys.argv = [
            "ioc_extractor",
            report_root
        ]
        ioc_extractor.main()
    except Exception as e:
        print(f"[!] IOC 정규화 실패 (파이프라인은 유지): {e}")

    # -------------------------------------------------
    # Final Summary
    # -------------------------------------------------
    print("\n===== Mini-EDR Pipeline 완료 =====\n")
    print(f"Report Root        : {report_root}")
    print(f"EVTX               : {evtx_folder}")
    print(f"Chainsaw           : {report_json}")
    print(f"OSQuery            : {osquery_folder}")
    print(f"Velociraptor       : {velo_output}")
    print(f"Events             : normalized/events.jsonl")
    print(f"IOCs               : ioc/iocs.json")
    print(f"MISP Attributes    : ioc/misp_attributes.json")
    print("\n[✓] 전체 작업 완료!\n")


if __name__ == "__main__":
    main()
