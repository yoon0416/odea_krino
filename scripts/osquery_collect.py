#!/usr/bin/env python3
import winrm
import os
import sys
import base64
import time


# ---------------------------------------------------------
# 1. OSQuery 실행 파일 경로 (Windows)
# ---------------------------------------------------------
OSQUERY_PATH = r"C:\Program Files\osquery\osqueryi.exe"


# ---------------------------------------------------------
# 2. OSQuery 쿼리 목록 (생략 없이 그대로 유지)
# ---------------------------------------------------------
OSQUERY_QUERIES = {
    # --- 프로세스 / 네트워크 ---
    "processes": """
        SELECT pid, name, path, cmdline, parent, uid, gid, start_time
        FROM processes;
    """,
    "process_open_sockets": """
        SELECT pid, family, protocol, local_address, local_port,
               remote_address, remote_port, state
        FROM process_open_sockets;
    """,
    "listening_ports": """
        SELECT pid, address, port, protocol, path
        FROM listening_ports;
    """,
    "connections": """
        SELECT pid, family, protocol, local_address, local_port,
               remote_address, remote_port, state
        FROM connections;
    """,

    # --- 서비스 / 드라이버 ---
    "services": """
        SELECT name, display_name, path, status, start_type, user_account
        FROM services;
    """,
    "drivers": """
        SELECT name, display_name, path, service_key, start_type
        FROM drivers;
    """,
    "kernel_drivers": """
        SELECT name, path, service_key, start_type
        FROM kernel_drivers;
    """,

    # --- 계정 / 권한 ---
    "users": """SELECT uid, username, description, directory, shell FROM users;""",
    "groups": """SELECT gid, groupname, group_sid FROM groups;""",
    "user_groups": """
        SELECT ug.uid, u.username, ug.gid, g.groupname
        FROM user_groups ug
        JOIN users u ON ug.uid = u.uid
        JOIN groups g ON ug.gid = g.gid;
    """,
    "logged_in_users": """SELECT * FROM logged_in_users;""",
    "logon_sessions": """SELECT * FROM logon_sessions;""",

    # --- 시작 프로그램 / 스케줄러 ---
    "startup_items": """SELECT name, path, args, type, source FROM startup_items;""",
    "scheduled_tasks": """SELECT name, path, state, enabled, action, next_run_time FROM scheduled_tasks;""",

    # --- 시스템 정보 ---
    "os_version": """SELECT * FROM os_version;""",
    "system_info": """SELECT * FROM system_info;""",
    "patches": """SELECT * FROM patches;""",
    "programs": """SELECT name, version, install_location, publisher, install_date FROM programs;""",

    # --- 디스크 ---
    "disks": """SELECT * FROM disks;""",
    "logical_drives": """SELECT * FROM logical_drives;""",
    "mounts": """SELECT * FROM mounts;""",

    # --- 보안 제품 ---
    "windows_security_products": """SELECT * FROM windows_security_products;""",

    # --- 레지스트리 ---
    "registry_run_hklm": """
        SELECT key, name, data
        FROM registry
        WHERE key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%';
    """,
    "registry_run_hkcu": """
        SELECT key, name, data
        FROM registry
        WHERE key LIKE 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%';
    """,
    "registry_rdp": """
        SELECT key, name, data
        FROM registry
        WHERE key LIKE 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Terminal Server%';
    """,

    # --- 네트워크 설정 ---
    "dns_resolvers": """SELECT * FROM dns_resolvers;""",
    "interface_addresses": """SELECT * FROM interface_addresses;""",

    # --- USB ---
    "usb_devices": """SELECT * FROM usb_devices;""",
    "usb_devices_history": """SELECT * FROM usb_devices_history;""",

    # --- Chrome 포렌식 ---
    "chrome_extensions": """SELECT * FROM chrome_extensions;""",
    "chrome_history": """
        SELECT * FROM chrome_history ORDER BY last_visit_time DESC LIMIT 100;
    """,
    "chrome_cookies": """
        SELECT host_key, name, path, encrypted_value, expires_utc
        FROM chrome_cookies LIMIT 100;
    """,

    # --- 공격 흔적 ---
    "prefetch": """SELECT * FROM prefetch;""",
    "shimcache": """SELECT * FROM shimcache;""",
    "amcache": """SELECT * FROM amcache;""",
    "powershell_events": """SELECT * FROM powershell_events ORDER BY time DESC LIMIT 200;""",
    "powershell_scripts": """SELECT * FROM powershell_scripts ORDER BY time DESC LIMIT 200;""",
}


# ---------------------------------------------------------
# OSQuery 쿼리 실행 → Base64 결과 반환
# ---------------------------------------------------------
def run_osquery_query(session, query):
    ps_cmd = f"""
$Output = & "{OSQUERY_PATH}" --json "{query.strip().replace('"', '\\"')}"
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Output)
[Convert]::ToBase64String($Bytes)
"""
    result = session.run_ps(ps_cmd)

    if result.status_code != 0:
        stderr = result.std_err.decode(errors="ignore").strip()
        raise Exception(f"OSQuery 실행 실패\n{stderr}")

    return result.std_out.decode().strip()


# ---------------------------------------------------------
# v2 통합 구조용 run() 함수
# ---------------------------------------------------------
def run(target_ip, username, password, report_root):
    """
    - WinRM으로 모든 OSQuery 쿼리 실행
    - 결과 JSON을 report_root/osquery/ 에 저장
    - 실패한 쿼리는 report_root/misc/osquery_errors.log에 기록
    """

    print("\n===== [v2] OSQuery Sweep 시작 =====")

    # WinRM 연결
    try:
        session = winrm.Session(
            f"http://{target_ip}:5985/wsman",
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
        )
    except Exception as e:
        print(f"[!] WinRM 연결 실패: {e}")
        return None

    # 최종 저장 경로 (report_root/osquery/)
    osq_dir = os.path.join(report_root, "osquery")
    os.makedirs(osq_dir, exist_ok=True)

    misc_dir = os.path.join(report_root, "misc")
    os.makedirs(misc_dir, exist_ok=True)
    error_log_path = os.path.join(misc_dir, "osquery_errors.log")

    success = []
    failed = []

    # 전체 쿼리 반복 실행
    for name, query in OSQUERY_QUERIES.items():
        print(f"[+] [{name}] 실행 중...")

        try:
            b64 = run_osquery_query(session, query)
            data = base64.b64decode(b64)

            # 파일 저장 경로
            out_path = os.path.join(osq_dir, f"{name}.json")

            with open(out_path, "wb") as f:
                f.write(data)

            print(f"    → 저장됨: {out_path}")
            success.append(name)

        except Exception as e:
            print(f"    [!] 실패: {e}")
            failed.append(name)

            # 실패 기록 로그 저장
            with open(error_log_path, "a", encoding="utf-8") as log:
                log.write(f"[{name}] 실패: {str(e)}\n")

    # 요약 출력
    print("\n===== OSQuery Sweep 요약 =====")
    print(f"성공 {len(success)}개 / 실패 {len(failed)}개")

    if failed:
        print(f"[!] 실패 로그 저장됨 → {error_log_path}")

    print(f"[✓] Sweep 완료 → {osq_dir}\n")

    return osq_dir


# ---------------------------------------------------------
# Standalone 실행 모드 (테스트용)
# ---------------------------------------------------------
if __name__ == "__main__":
    import getpass
    print("Standalone 실행")

    ip = input("Target IP: ").strip()
    user = input("Username: ").strip()
    pw = getpass.getpass("Password: ")

    test_root = os.path.expanduser("~/odea_krino/evidence/v2_report/standalone_test")
    os.makedirs(test_root, exist_ok=True)

    run(ip, user, pw, test_root)
