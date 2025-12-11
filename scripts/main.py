#!/usr/bin/env python3
import getpass
import sys

# -----------------------------
# Import pipeline modules
# -----------------------------
import remote_evtx_collect
import analyze_evtx
import osquery_collect


# -----------------------------
# Mini-EDR v2 Pipeline
# -----------------------------
def main():
    print("\n===== Mini-EDR v2 : One-Click Full Pipeline =====\n")

    # -----------------------------
    # 1) Single Input (once only)
    # -----------------------------
    target_ip = input("Target IP: ").strip()
    username  = input("Username: ").strip()
    password  = getpass.getpass("Password: ").strip()

    print("\n[1/3] EVTX 수집 단계 시작...\n")

    # -----------------------------
    # 2) EVTX 수집 / ZIP 다운로드 / 압축해제
    # -----------------------------
    evtx_folder = remote_evtx_collect.run(target_ip, username, password)

    if not evtx_folder:
        print("\n[!] EVTX 수집 단계 실패 → 파이프라인 종료")
        sys.exit(1)

    print(f"[✓] EVTX 수집 완료 → {evtx_folder}\n")

    # -----------------------------
    # 3) Chainsaw 분석
    # -----------------------------
    print("\n[2/3] Chainsaw + Sigma 분석 단계 시작...\n")

    report_json = analyze_evtx.run(evtx_folder)

    if not report_json:
        print("\n[!] Chainsaw 분석 실패 → 파이프라인 종료")
        sys.exit(1)

    print(f"[✓] Chainsaw 결과 JSON 생성됨 → {report_json}\n")

    # -----------------------------
    # 4) OSQuery Sweep
    # -----------------------------
    print("\n[3/3] OSQuery Sweep 단계 시작...\n")

    osquery_folder = osquery_collect.run(target_ip, username, password)

    if not osquery_folder:
        print("\n[!] OSQuery Sweep 실패 → 파이프라인 종료")
        sys.exit(1)

    print(f"[✓] OSQuery Sweep 결과 저장됨 → {osquery_folder}\n")

    # -----------------------------
    # 5) Final Summary
    # -----------------------------
    print("\n===== Mini-EDR v2 전체 파이프라인 완료 =====\n")
    print("✔ EVTX 압축 및 전송 / 압축해제 성공")
    print("✔ Chainsaw Sigma 분석 JSON 생성 성공")
    print("✔ OSQuery Sweep 결과 수집 성공")
    print("--------------------------------------------")
    print(f"EVTX Folder      : {evtx_folder}")
    print(f"Chainsaw Report  : {report_json}")
    print(f"OSQuery Sweep    : {osquery_folder}")
    print("--------------------------------------------")
    print("\n[✓] Mini-EDR v2 모든 작업 완료!\n")


# -----------------------------
# ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    main()
