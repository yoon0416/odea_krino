#!/usr/bin/env python3
import winrm
import getpass
import base64
import os
import sys

CHUNK_SIZE = 200000   # 200KB per chunk (WinRM safe)

def upload_file_chunked(session, local_path, remote_path):
    file_size = os.path.getsize(local_path)
    print(f"[+] File size: {file_size} bytes")

    # 1) Windows 파일 초기화 (빈 파일 생성)
    init_script = f'[IO.File]::WriteAllBytes("{remote_path}", @())'
    session.run_ps(init_script)
    print("[+] Remote file initialized.")

    sent = 0

    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            b64 = base64.b64encode(chunk).decode()

            ps_script = f"""
$bytes = [System.Convert]::FromBase64String("{b64}")
[IO.File]::WriteAllBytes("{remote_path}", ([IO.File]::ReadAllBytes("{remote_path}") + $bytes))
"""

            result = session.run_ps(ps_script)

            if result.status_code != 0:
                print(result.std_err.decode())
                raise Exception("Chunk upload failed.")

            sent += len(chunk)
            print(f"[+] Uploaded: {sent}/{file_size} bytes")

    print(f"[✓] Upload completed → {remote_path}")


def main():
    print("\n===== WinRM Chunk File Upload (Kali → Windows) =====\n")

    target_ip = input("Target IP: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    local_file = input("Local file path to upload: ").strip()
    remote_file = input("Windows destination path: ").strip()

    if not os.path.isfile(local_file):
        print(f"[!] File not found: {local_file}")
        sys.exit(1)

    print("\n[+] Connecting WinRM...")
    session = winrm.Session(
        f"http://{target_ip}:5985/wsman",
        auth=(username, password),
        transport='ntlm',
        server_cert_validation='ignore'
    )

    upload_file_chunked(session, local_file, remote_file)

    print("\n[✓] Done!\n")


if __name__ == "__main__":
    main()
