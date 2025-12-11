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
# Mini-EDR v2 + Velociraptor Pipeline
# -----------------------------
def main():
    print("\n===== Mini-EDR v2 : One-Click Full Pipeline + Velociraptor Query =====\n")

    target_ip = input("Target IP: ").strip()
    username  = input("Username: ").strip()
    password  = getpass.getpass("Password: ").strip()

    # 1) 통합 Evidence Root 생성
    report_root = prepare_v2_report_root(username)

    print("\n[1/4] EVTX 수집 단계 시작...\n")

    # 2) EVTX 수집
    evtx_folder = remote_evtx_collect.run(target_ip, username, password, report_root)
    if not evtx_folder:
        print("\n[!] EVTX 수집 실패 → 중단")
        sys.exit(1)
    print(f"[✓] EVTX 수집 완료 → {evtx_folder}\n")

    print("\n[2/4] Chainsaw + Sigma 분석 단계 시작...\n")

    # 3) Chainsaw 분석
    report_json = analyze_evtx.run(evtx_folder, report_root)
    if not report_json:
        print("\n[!] Chainsaw 분석 실패 → 중단")
        sys.exit(1)
    print(f"[✓] Chainsaw JSON 저장됨 → {report_json}\n")

    print("\n[3/4] OSQuery Sweep 단계 시작...\n")

    # 4) OSQuery Sweep
    osquery_folder = osquery_collect.run(target_ip, username, password, report_root)
    if not osquery_folder:
        print("\n[!] OSQuery Sweep 실패 → 중단")
        sys.exit(1)
    print(f"[✓] OSQuery Sweep 저장됨 → {osquery_folder}\n")

    print("\n[4/4] Velociraptor Query 기반 수집 단계 시작...\n")

    # 5) Velociraptor Query 실행 (velo_one_shot.py)
    velo_output = velo_one_shot.run(target_ip, username, password, report_root)
    if not velo_output:
        print("\n[!] Velociraptor Query 실패 → Velociraptor 단계만 건너뜀 (다른 파이프라인은 정상)")
    else:
        print(f"[✓] Velociraptor 수집 결과 저장됨 → {velo_output}\n")

    # 6) Final Summary
    print("\n===== Mini-EDR v2 + Velociraptor Pipeline 완료 =====\n")
    print(f"Unified Evidence Root : {report_root}")
    print(f"EVTX Folder           : {evtx_folder}")
    print(f"Chainsaw Report JSON  : {report_json}")
    print(f"OSQuery Sweep Folder  : {osquery_folder}")
    print(f"Velociraptor Output   : {velo_output}")
    print("\n[✓] 전체 작업 완료!\n")


if __name__ == "__main__":
    main()
