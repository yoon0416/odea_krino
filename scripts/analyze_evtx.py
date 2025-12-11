#!/usr/bin/env python3
import os
import time
import subprocess


# ---------------------------------------------------------
# v2 chainsaw 보고서 저장 경로 준비
# ---------------------------------------------------------
def prepare_chainsaw_output(report_root):
    """
    report_root/chainsaw/ 폴더 내 chainsaw_report.json 생성 경로 반환
    """
    chainsaw_dir = os.path.join(report_root, "chainsaw")
    os.makedirs(chainsaw_dir, exist_ok=True)

    output_path = os.path.join(chainsaw_dir, "chainsaw_report.json")
    return output_path


# ---------------------------------------------------------
# v2 파이프라인용 Chainsaw 분석 실행
# ---------------------------------------------------------
def run(evtx_dir, report_root):
    """
    Chainsaw + Sigma 기반 EVTX 분석 실행 (v2 통합 폴더 구조)
    입력:
        evtx_dir     - remote_evtx_collect가 반환한 압축해제 폴더
        report_root  - 전체 evidence 저장 루트

    출력:
        chainsaw_report.json 경로
    """

    print("\n===== [v2] Chainsaw EVTX 분석 시작 =====\n")

    # ---------------------------------------------------------
    # 입력 경로 검증
    # ---------------------------------------------------------
    if not os.path.isdir(evtx_dir):
        print(f"[!] 유효하지 않은 EVTX 경로: {evtx_dir}")
        return None

    # Sigma rule 폴더
    sigma_dir = os.path.expanduser("~/odea_krino/tools/sigma/rules/windows")
    if not os.path.isdir(sigma_dir):
        print(f"[!] Sigma 룰 폴더 없음: {sigma_dir}")
        return None

    # Chainsaw 매핑 파일
    mapping_file = os.path.expanduser(
        "~/odea_krino/tools/chainsaw/mappings/sigma-event-logs-all.yml"
    )
    if not os.path.isfile(mapping_file):
        print(f"[!] Chainsaw 매핑 파일 없음: {mapping_file}")
        return None

    # ---------------------------------------------------------
    # 출력 JSON 파일 경로 생성
    # ---------------------------------------------------------
    output_file = prepare_chainsaw_output(report_root)

    print("[+] Chainsaw 분석 설정:")
    print(f"    - 입력 EVTX 폴더: {evtx_dir}")
    print(f"    - Sigma 룰:       {sigma_dir}")
    print(f"    - Mapping 파일:  {mapping_file}")
    print(f"    - 출력 JSON:     {output_file}\n")

    # ---------------------------------------------------------
    # Chainsaw 실행 명령어 구성
    # ---------------------------------------------------------
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

        # misc 폴더에 오류 로그 저장
        misc_dir = os.path.join(report_root, "misc")
        os.makedirs(misc_dir, exist_ok=True)
        err_log_path = os.path.join(misc_dir, "chainsaw_error.log")

        with open(err_log_path, "w", encoding="utf-8") as f:
            f.write(f"Chainsaw Error Code: {e.returncode}\n")
            f.write("Command: " + " ".join(cmd) + "\n")

        print(f"[!] 오류 로그 저장됨 → {err_log_path}")
        return None


# ---------------------------------------------------------
# Standalone 실행 모드 (테스트용)
# ---------------------------------------------------------
if __name__ == "__main__":
    print("\nStandalone analyze_evtx.py 모드")

    target = input("EVTX 폴더 경로: ").strip()

    # standalone 테스트용 report_root 자동 생성
    test_root = os.path.expanduser("~/odea_krino/evidence/v2_report/standalone_test")
    os.makedirs(test_root, exist_ok=True)

    run(target, test_root)
