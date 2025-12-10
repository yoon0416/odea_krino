#!/usr/bin/env python3
#!/usr/bin/env python3

import getpass
import winrm

def ask(prompt):
    v = input(prompt).strip()
    while not v:
        v = input(prompt).strip()
    return v

def main():
    print("=== WinRM 연결 테스트 ===")

    target = ask("Target IP: ")
    username = ask("Username: ")
    password = getpass.getpass("Password: ")

    endpoint = f"http://{target}:5985/wsman"
    print(f"[+] Endpoint: {endpoint}")

    try:
        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
        )
    except Exception as e:
        print(f"[ERROR] 세션 생성 실패: {e}")
        return

    print("[+] 연결 테스트 중...")

    r = session.run_cmd("hostname")
    print("hostname:", r.std_out.decode(errors="ignore"))

    if r.status_code != 0:
        print("[ERROR] hostname 명령 실패 → WinRM 설정 문제 가능")
        return

    r2 = session.run_cmd("whoami")
    print("whoami:", r2.std_out.decode(errors="ignore"))

    print("[+] WinRM 연결 성공!")

if __name__ == "__main__":
    main()

