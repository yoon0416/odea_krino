#!/usr/bin/env python3
import winrm
import os
import sys
import base64
import zipfile
import time


# ------------------------------
# PowerShell Script Template
# ------------------------------
PS_SCRIPT = r'''
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$rand = -join ((65..90) | Get-Random -Count 2 | ForEach-Object {[char]$_})
$baseName = "logs_${timestamp}_${rand}"

$root = "C:\EDR_TEMP\exports"
New-Item -ItemType Directory -Force -Path $root | Out-Null

$evtxFolder = "$root\$baseName"
New-Item -ItemType Directory -Force -Path $evtxFolder | Out-Null

wevtutil epl Security    "$evtxFolder\Security.evtx"
wevtutil epl System      "$evtxFolder\System.evtx"
wevtutil epl Application "$evtxFolder\Application.evtx"

$zipPath = "$root\$baseName.zip"
Compress-Archive -Path "$evtxFolder\*" -DestinationPath $zipPath -Force

Write-Output "ZIP_CREATED:$zipPath"
'''


# ---------------------------------------------------------
# ZIP을 Base64로 변환하여 다운로드하는 PowerShell 명령 생성
# ---------------------------------------------------------
def build_b64_script(zip_path):
    return fr"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{zip_path}'))"


# ---------------------------------------------------------
# ZIP 다운로드 → report_root/evtx/에 저장
# ---------------------------------------------------------
def download_zip(session, zip_path, save_dir):
    print(f"[+] ZIP Base64 다운로드 요청: {zip_path}")

    result = session.run_ps(build_b64_script(zip_path))

    if result.status_code != 0:
        raise Exception(result.std_err.decode())

    b64_data = result.std_out.decode().strip()
    file_name = os.path.basename(zip_path.replace("\\", "/"))
    local_path = os.path.join(save_dir, file_name)

    with open(local_path, "wb") as f:
        f.write(base64.b64decode(b64_data))

    print(f"[+] ZIP 다운로드 완료 → {local_path}")
    return local_path


# ---------------------------------------------------------
# ZIP 압축 해제 → report_root/evtx/<extract_YYYYMMDD_HHMMSS>
# ---------------------------------------------------------
def extract_evtx(zip_file_path, evtx_root):
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(evtx_root, f"extract_{ts}")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[+] ZIP 압축 해제 위치: {out_dir}")

    with zipfile.ZipFile(zip_file_path, 'r') as z:
        z.extractall(out_dir)

    print("[+] EVTX 압축 해제 완료!")
    return out_dir


# ---------------------------------------------------------
# v2 통합 구조용 run() 함수
# ---------------------------------------------------------
def run(target_ip, username, password, report_root):
    """
    v2 파이프라인용 EVTX 수집 엔진 (통합 evidence 폴더 버전)
    - report_root/evtx/ 아래에 ZIP 다운로드 및 압축 해제
    - 최종적으로 EVTX 폴더 경로 반환
    """

    print("\n===== [v2] EVTX 수집 시작 =====")

    # WinRM 연결
    try:
        session = winrm.Session(
            f"http://{target_ip}:5985/wsman",
            auth=(username, password),
            transport='ntlm',
            server_cert_validation='ignore'
        )
    except Exception as e:
        print(f"[!] WinRM 연결 실패: {e}")
        return None

    # 원격 PowerShell 실행 → ZIP 생성
    result = session.run_ps(PS_SCRIPT)

    if result.status_code != 0:
        print(result.std_err.decode())
        return None

    output = result.std_out.decode().strip()
    zip_path = None

    for line in output.splitlines():
        if line.startswith("ZIP_CREATED:"):
            zip_path = line.replace("ZIP_CREATED:", "").strip()

    if not zip_path:
        print("[!] ZIP 경로 추출 실패!")
        return None

    print(f"[+] 원격 ZIP 생성됨: {zip_path}")

    # ---------------------------------------------------------
    # 로컬 저장 경로는 report_root/evtx/
    # ---------------------------------------------------------
    evtx_save_dir = os.path.join(report_root, "evtx")
    os.makedirs(evtx_save_dir, exist_ok=True)

    local_zip = download_zip(session, zip_path, evtx_save_dir)

    # ---------------------------------------------------------
    # 압축 해제 → report_root/evtx/extract_xxx
    # ---------------------------------------------------------
    extracted_dir = extract_evtx(local_zip, evtx_save_dir)

    print(f"[✓] EVTX 수집 완료 → {extracted_dir}")
    return extracted_dir


# ---------------------------------------------------------
# Standalone 실행 모드
# ---------------------------------------------------------
if __name__ == "__main__":
    import getpass
    print("Standalone remote_evtx_collect 실행 모드")
    ip = input("IP: ")
    user = input("Username: ")
    pw = getpass.getpass("Password: ")

    # Standalone 테스트용 — 통합 폴더 자동 생성
    test_root = os.path.expanduser("~/odea_krino/evidence/v2_report/standalone_test")
    os.makedirs(test_root, exist_ok=True)

    run(ip, user, pw, test_root)
