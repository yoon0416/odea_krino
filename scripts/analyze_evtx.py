#!/usr/bin/env python3
import os
import time
import subprocess

# ------------------------------
# 보고서 저장 폴더 생성
# ------------------------------
def prepare_report_folder():
    base = os.path.expanduser("~/openedr_v1/evidence")
    report_dir = os.path.join(base, "reports")
    os.makedirs(report_dir, exist_ok=True)
    return report_dir


# ------------------------------
# v2 파이프라인에서 호출할 메인 함수
# ------------------------------
def run(evtx_dir):
    """
    Chainsaw + Sigma 기반 EVTX 분석 실행
    입력: EVTX 폴더 경로
    출력: 생성된 JSON 보고서 경로 또는 None
    """

    print("\n===== [v2] Chainsaw EVTX 분석 시작 =====\n")

    # -------------------------
    # 유효성 체크
    # -------------------------
    if not os.path.isdir(evtx_dir):
        print(f"[!] 유효하지 않은 EVTX 경로: {evtx_dir}")
        return None

    # Sigma rule 폴더
    sigma_dir = os.path.expanduser("~/openedr_v1/tools/sigma/rules/windows")
    if not os.path.isdir(sigma_dir):
        print(f"[!] Sigma 룰 폴더 없음: {sigma_dir}")
        return None

    # Chainsaw 매핑 파일
    mapping_file = os.path.expanduser(
        "~/openedr_v1/tools/chainsaw/mappings/sigma-event-logs-all.yml"
    )
    if not os.path.isfile(mapping_file):
        print(f"[!] Chainsaw 매핑 파일 없음: {mapping_file}")
        return None

    # 출력 JSON 생성
    report_dir = prepare_report_folder()
    ts = time.strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(report_dir, f"report_{ts}.json")

    print("[+] 분석 설정:")
    print(f"    - 입력 폴더: {evtx_dir}")
    print(f"    - Sigma 룰:  {sigma_dir}")
    print(f"    - Mapping:   {mapping_file}")
    print(f"    - 출력 JSON: {output_file}\n")

    # Chainsaw 실행 명령어
    cmd = [
        "chainsaw",
        "hunt",
        evtx_dir,
        "--sigma", sigma_dir,
        "--mapping", mapping_file,
        "--output", output_file
    ]

    try:
        subprocess.run(cmd, check=True)
        print(f"[✓] Chainsaw 분석 완료 → {output_file}\n")
        return output_file

    except subprocess.CalledProcessError as e:
        print("[!] Chainsaw 실행 중 오류 발생")
        print("    Return Code:", e.returncode)
        print("    Command:", " ".join(cmd))
        return None


# ------------------------------
# Standalone 실행 모드
# ------------------------------
if __name__ == "__main__":
    print("\nStandalone analyze_evtx.py 모드")
    target = input("EVTX 폴더 경로: ").strip()
    run(target)
