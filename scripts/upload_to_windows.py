#!/usr/bin/env python3
import winrm
import getpass
import base64
import os
import sys

def upload_file(session, local_path, remote_path):
    # 1) 파일 존재 체크
    if not os.path.isfile(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    print(f"[+] Reading local file: {local_path}")
    with open(local_path, "rb") as f:
        b64_data = base64.b64encode(f.read()).decode()

    print(f"[+] File encoded as Base64 ({len(b64_data)} bytes)")

    # 2) PowerShell: Base64 → Windows 파일 복원
    ps_script = f"""
$bytes = [System.Convert]::FromBase64String("{b64_data}")
[IO.File]::WriteAllBytes("{remote_path}", $bytes)
Write-Output "UPLOAD_OK:{remote_path}"
"""

    print("[+] Uploading to Windows via WinRM...")
    result = session.run_ps(ps_script)

    stdout = result.std_out.decode().strip()
    stderr = result.std_err.decode().strip()

    if stderr:
        print("[!] PowerShell Error:")
        print(stderr)

    if "UPLOAD_OK" in stdout:
        print(f"[✓] Upload Success → {remote_path}")
    else:
        print("[!] Upload may have failed. Output:")
        print(stdout)


def main():
    print("\n===== WinRM File Upload (Kali → Windows) =====\n")

    target_ip = input("Target IP: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    local_file = input("Local file path to upload: ").strip()
    remote_file = input("Windows destination path: ").strip()

    if not os.path.exists(local_file):
        print(f"[!] Local file not found: {local_file}")
        sys.exit(1)

    # 1) WinRM 연결
    print("\n[+] Connecting WinRM...")
    try:
        session = winrm.Session(
            f"http://{target_ip}:5985/wsman",
            auth=(username, password),
            transport='ntlm',
            server_cert_validation='ignore'
        )
    except Exception as e:
        print(f"[!] WinRM Connection Failed: {e}")
        sys.exit(1)

    # 2) 업로드 실행
    try:
        upload_file(session, local_file, remote_file)
    except Exception as e:
        print(f"[!] Upload Failed: {e}")
        sys.exit(1)

    print("\n[✓] Done!\n")


if __name__ == "__main__":
    main()
