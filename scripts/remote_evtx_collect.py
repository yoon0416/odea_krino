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

# ------------------------------
# Helper Functions
# ------------------------------

def build_b64_script(zip_path):
    return fr"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{zip_path}'))"


def prepare_kali_folder():
    base_dir = os.path.expanduser("~/openedr_v1/evidence")
    raw_dir = os.path.join(base_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    return raw_dir


def prepare_extract_folder():
    base_dir = os.path.expanduser("~/openedr_v1/evidence")
    extract_dir = os.path.join(base_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    return extract_dir


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


def extract_evtx(zip_file_path):
    extract_root = prepare_extract_folder()

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(extract_root, f"extract_{ts}")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[+] ZIP 압축 해제 위치: {out_dir}")

    with zipfile.ZipFile(zip_file_path, 'r') as z:
        z.extractall(out_dir)

    print("[+] 압축 해제 완료!")
    return out_dir


# ------------------------------
# v2 메인 실행 함수 (main.py에서 호출)
# ------------------------------
def run(target_ip, username, password):
    """
    v2 파이프라인용 EVTX 수집 엔진
    - WinRM으로 EVTX Export + ZIP 생성
    - ZIP을 Base64로 Kali에 다운로드
    - 압축 해제
    - 최종적으로 EVTX 폴더 경로 반환
    """
    print("\n===== [v2] EVTX 수집 시작 =====")

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

    # PowerShell 실행 → ZIP 생성
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

    # ZIP 다운로드
    save_dir = prepare_kali_folder()
    local_zip = download_zip(session, zip_path, save_dir)

    # 압축 해제
    extracted_dir = extract_evtx(local_zip)

    print(f"[✓] EVTX 수집 완료 → {extracted_dir}")
    return extracted_dir


# ------------------------------
# Standalone 실행 (개별 실습용)
# ------------------------------
if __name__ == "__main__":
    import getpass
    print("Standalone remote_evtx_collect 실행 모드")
    ip = input("IP: ")
    user = input("Username: ")
    pw = getpass.getpass("Password: ")
    run(ip, user, pw)
