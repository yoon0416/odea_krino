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

# ★ v2.2 Normalizer 추가
import normalizer


# ---------------------------------------------------------
# v2 Report Root Folder 생성
# ---------------------------------------------------------
def prepare_v2_report_root(username):
    """
    ~/odea_krino/evidence/v2_report/<username>_<YYYYMMDD_HHMM>/
    내부에 evtx, chainsaw, osquery, velociraptor, misc 폴더 자동 생성
    """

    ts = time.strftime("%Y%m%d_%H%M")

    base = os.path.expanduser("~/odea_krino/evidence/v2_report")
    root = os.path.join(base, f"{username}_{ts}")

    os.makedirs(root, exist_ok=True)
    os.makedirs(os.path.join(root, "evtx"), exist_ok=True)
    os.makedirs(os.path.join(root, "chainsaw"), exist_ok=True)
    os.makedirs(os.path.join(root, "osquery"), exist_ok=True)
    os.makedirs(os.path.join(root, "velociraptor"), exist_ok=True)
    os.makedirs(os.path.join(root, "misc"), exist_ok=True)

    print(f"\n[+] v2 Report Root 생성됨 → {root}\n")
    return root


# -----------------------------
# Mini-EDR v2.2 Full Pipeline
# -----------------------------
def main():
    print("\n===== Mini-EDR v2.2 : Full Pipeline + Normalization =====\n")

    target_ip = input("Target IP: ").strip()
    username  = input("Username: ").strip()
    password  = getpass.getpass("Password: ").strip()

    # 1) 통합 Evidence Root 생성
    report_root = prepare_v2_report_root(username)

    # -------------------------------------------------
    # [1/5] EVTX 수집
    # -------------------------------------------------
    print("\n[1/5] EVTX 수집 단계 시작...\n")

    evtx_folder = remote_evtx_collect.run(
        target_ip, username, password, report_root
    )
    if not evtx_folder:
        print("\n[!] EVTX 수집 실패 → 중단")
        sys.exit(1)

    print(f"[✓] EVTX 수집 완료 → {evtx_folder}\n")

    # -------------------------------------------------
    # [2/5] Chainsaw + Sigma 분석
    # -------------------------------------------------
    print("\n[2/5] Chainsaw + Sigma 분석 단계 시작...\n")

    report_json = analyze_evtx.run(evtx_folder, report_root)
    if not report_json:
        print("\n[!] Chainsaw 분석 실패 → 중단")
        sys.exit(1)

    print(f"[✓] Chainsaw JSON 저장됨 → {report_json}\n")

    # -------------------------------------------------
    # [3/5] OSQuery Sweep
    # -------------------------------------------------
    print("\n[3/5] OSQuery Sweep 단계 시작...\n")

    osquery_folder = osquery_collect.run(
        target_ip, username, password, report_root
    )
    if not osquery_folder:
        print("\n[!] OSQuery Sweep 실패 → 중단")
        sys.exit(1)

    print(f"[✓] OSQuery Sweep 저장됨 → {osquery_folder}\n")

    # -------------------------------------------------
    # [4/5] Velociraptor Query
    # -------------------------------------------------
    print("\n[4/5] Velociraptor Query 기반 수집 단계 시작...\n")

    velo_output = velo_one_shot.run(
        target_ip, username, password, report_root
    )
    if not velo_output:
        print(
            "\n[!] Velociraptor Query 실패 → "
            "Velociraptor 단계만 건너뜀 (다른 파이프라인은 정상)"
        )
    else:
        print(f"[✓] Velociraptor 수집 결과 저장됨 → {velo_output}\n")

    # -------------------------------------------------
    # [5/5] v2.2 Evidence Normalization
    # -------------------------------------------------
    print("\n[5/5] Evidence Normalization (v2.2) 시작...\n")

    try:
        summary = normalizer.normalize_report_root(
            report_root,
            host_ip=target_ip,
            write_bundle_files=True,      # bundles/*.json + bundle_index.json 생성
            per_osquery_row_limit=200,
            per_velo_artifact_limit=300,
        )
    except Exception as e:
        print(f"\n[!] Normalization 실패: {e}")
        sys.exit(1)

    print("\n[✓] Normalization 완료")
    print(f"  - Events File : {report_root}/normalized/events.jsonl")
    print(f"  - Summary     : {report_root}/normalized/summary.json")
    if summary.get("bundle_index"):
        print(f"  - Bundle Index: {summary['bundle_index']}")

    # -------------------------------------------------
    # Final Summary
    # -------------------------------------------------
    print("\n===== Mini-EDR v2.2 Full Pipeline 완료 =====\n")
    print(f"Unified Evidence Root : {report_root}")
    print(f"EVTX Folder           : {evtx_folder}")
    print(f"Chainsaw Report JSON  : {report_json}")
    print(f"OSQuery Sweep Folder  : {osquery_folder}")
    print(f"Velociraptor Output   : {velo_output}")
    print(f"Unified Events        : normalized/events.jsonl")
    print("\n[✓] 전체 작업 완료!\n")


if __name__ == "__main__":
    main()
