#!/usr/bin/env python3
# velo_one_shot.py
#
# Velociraptor "query 모드" 원샷 수집 스크립트
# - Windows 에 사전 설치된 vr.exe 사용 (collect 말고 query)
# - 다양한 포렌식 Artifact들을 JSONL로 수집
# - ~/odea_krino/evidence/v2_report/<...>/velociraptor/ 아래에 저장
#
# ⚠ 파일명 바꾸지 말 것: velo_one_shot.py (main.py에서 그대로 import 함)

import os
import time
import base64
import winrm

# -------------------------------------------------------------------
# 1. Velociraptor 실행 파일 경로 (Windows)
# -------------------------------------------------------------------
VR_EXE_PATH = r"C:\EDR_TOOLS\velociraptor\vr.exe"

# -------------------------------------------------------------------
# 2. 수집할 Velociraptor Artifact 목록 (VQL 함수 형태)
#    - key: 로컬/원격 파일 이름 prefix
#    - value: VQL에서 사용할 함수 이름 (SELECT * FROM <함수>() 형태)
# -------------------------------------------------------------------
VELO_ARTIFACTS = {
    # --- 프로세스 / 세션 / 계정 ---
    "processes":              "Artifact.Windows.Sys.Processes",
    "logon_sessions":         "Artifact.Windows.Sys.LogonSessions",
    "users":                  "Artifact.Windows.Sys.Users",
    "user_sessions":          "Artifact.Windows.Sys.UserSessions",
    "scheduled_tasks":        "Artifact.Windows.Sys.ScheduledTasks",
    "services":               "Artifact.Windows.Sys.Services",
    "drivers":                "Artifact.Windows.Sys.Drivers",
    "autoruns":               "Artifact.Windows.Sys.Autoruns",

    # --- 포렌식 핵심 (Prefetch / Amcache / ShimCache / USB / MFT / JumpList / LNK 등) ---
    "prefetch":               "Artifact.Windows.Sys.Prefetch",
    "amcache":                "Artifact.Windows.Registry.Amcache",
    "shimcache":              "Artifact.Windows.Registry.ShimCache",
    "mft":                    "Artifact.Windows.Forensic.MFT",
    "usn_journal":            "Artifact.Windows.Forensic.UsnJrnl",
    "jump_lists":             "Artifact.Windows.Forensic.JumpLists",
    "lnk_files":              "Artifact.Windows.Forensic.Lnk",
    "usb_devices":            "Artifact.Windows.Forensic.USBDevices",
    "recycle_bin":            "Artifact.Windows.Forensic.RecycleBin",
    "recent_docs":            "Artifact.Windows.Forensic.RecentDocs",
    "srudb":                  "Artifact.Windows.Forensic.SRUM",

    # --- 브라우저 포렌식 (Chrome / Edge) ---
    "chrome_history":         "Artifact.Windows.Forensic.Chrome.History",
    "chrome_downloads":       "Artifact.Windows.Forensic.Chrome.Downloads",
    "chrome_cookies":         "Artifact.Windows.Forensic.Chrome.Cookies",
    "edge_history":           "Artifact.Windows.Forensic.Edge.History",
    "edge_downloads":         "Artifact.Windows.Forensic.Edge.Downloads",
    "edge_cookies":           "Artifact.Windows.Forensic.Edge.Cookies",

    # --- 이벤트 로그 / PowerShell / 보안 ---
    "evtx_fast":              "Artifact.Windows.Forensic.EvtxFast",
    "evtx_security":          "Artifact.Windows.EventLogs.Security",
    "evtx_system":            "Artifact.Windows.EventLogs.System",
    "evtx_application":       "Artifact.Windows.EventLogs.Application",
    "evtx_powershell":        "Artifact.Windows.EventLogs.PowerShell",
    "evtx_powershell_oper":   "Artifact.Windows.EventLogs.PowerShellOperational",

    # --- RDP / 네트워크 활동 ---
    "rdp_connections":        "Artifact.Windows.Forensic.RDPConnections",
    "rdp_logs":               "Artifact.Windows.EventLogs.RemoteDesktop",
    "firewall_logs":          "Artifact.Windows.Forensic.FirewallLogs",
    "netstat":                "Artifact.Windows.Sys.Netstat",
    "dns_cache":              "Artifact.Windows.Sys.DNSCache",

    # --- 레지스트리 기반 흔적 ---
    "run_keys":               "Artifact.Windows.Registry.RunKeys",
    "startup_approved":       "Artifact.Windows.Registry.StartupApproved",
    "installed_programs":     "Artifact.Windows.Registry.InstalledPrograms",
    "shellbags":              "Artifact.Windows.Registry.ShellBags",

    # --- PowerShell / ScriptBlock ---
    "powershell_events":      "Artifact.Windows.EventLogs.PowerShell",
    "powershell_scriptblock": "Artifact.Windows.Forensic.PowershellScriptBlock",

    # --- 기타 시스템 정보 ---
    "system_info":            "Artifact.Windows.Sys.SystemInfo",
    "os_info":                "Artifact.Windows.Sys.OsInformation",
    "installed_updates":      "Artifact.Windows.Sys.InstalledPatches",
}


# -------------------------------------------------------------------
# 3. 원격에서 Velo Query 실행 + JSONL 다운로드 공통 함수
# -------------------------------------------------------------------
def _run_single_artifact(session, short_name, vql_func, remote_root, local_dir):
    """
    단일 Velociraptor Artifact에 대해:
    - 원격 VQL 쿼리 실행 (query 모드)
    - C:\Windows\Temp\openedr_velo\<short_name>.jsonl 에 저장
    - Base64로 읽어서 Kali에 저장
    """
    remote_out = rf"{remote_root}\{short_name}.jsonl"
    local_out = os.path.join(local_dir, f"{short_name}.jsonl")

    vql = f"SELECT * FROM {vql_func}()"

    print(f"[+] [{short_name}] Velo Query 실행 중...")

    ps_query = f"""
& "{VR_EXE_PATH}" query "{vql}" --format jsonl --output "{remote_out}"
"""

    result = session.run_ps(ps_query)

    if result.status_code != 0:
        stderr = result.std_err.decode(errors="ignore").strip()
        print(f"    [!] Velociraptor query 실패: {short_name}")
        if stderr:
            print(f"        STDERR: {stderr}")
        return None

    # 원격 파일이 너무 작거나 없는 경우도 있을 수 있음 → 존재 여부는 그냥 다운로드 시도
    ps_download = f"""
[Convert]::ToBase64String([IO.File]::ReadAllBytes("{remote_out}"))
"""

    dl_result = session.run_ps(ps_download)

    if dl_result.status_code != 0:
        stderr = dl_result.std_err.decode(errors="ignore").strip()
        print(f"    [!] [{short_name}] JSONL 다운로드 실패")
        if stderr:
            print(f"        STDERR: {stderr}")
        return None

    b64_data = dl_result.std_out.decode().strip()
    try:
        raw = base64.b64decode(b64_data)
    except Exception as e:
        print(f"    [!] Base64 디코딩 실패 ({short_name}): {e}")
        return None

    os.makedirs(local_dir, exist_ok=True)
    with open(local_out, "wb") as f:
        f.write(raw)

    print(f"    → 저장됨: {local_out}")
    return local_out


# -------------------------------------------------------------------
# 4. 외부에서 main.py가 호출하는 진입점 함수
# -------------------------------------------------------------------
def run(ip, username, password, report_root):
    """
    Velociraptor Query 모드로 다양한 Artifact를 한 번에 수집
    - WinRM을 통해 Windows의 vr.exe를 호출
    - 여러 Artifact를 query 모드로 JSONL 수집
    - ~/odea_krino/evidence/v2_report/.../velociraptor/ 에 저장
    - return: 로컬 velo 결과 폴더 경로
    """

    print("[+] Velociraptor Query 기반 포렌식 수집 시작...")

    # 1) WinRM 세션 연결
    try:
        session = winrm.Session(
            f"http://{ip}:5985/wsman",
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
        )
    except Exception as e:
        print(f"[!] WinRM 연결 실패: {e}")
        return None

    # 2) 원격 / 로컬 폴더 준비
    remote_root = r"C:\Windows\Temp\openedr_velo"
    ps_init = f"""
if (Test-Path "{remote_root}") {{
    Remove-Item -Path "{remote_root}" -Recurse -Force
}}
New-Item -Path "{remote_root}" -ItemType Directory | Out-Null
"""
    init_result = session.run_ps(ps_init)
    if init_result.status_code != 0:
        stderr = init_result.std_err.decode(errors="ignore").strip()
        print("[!] 원격 Velociraptor 임시 폴더 초기화 실패")
        if stderr:
            print(f"    STDERR: {stderr}")
        return None

    local_dir = os.path.join(report_root, "velociraptor")
    os.makedirs(local_dir, exist_ok=True)

    # 3) 전체 Artifact 순회 실행
    success = []
    failed = []

    for short_name, vql_func in VELO_ARTIFACTS.items():
        out_path = _run_single_artifact(session, short_name, vql_func, remote_root, local_dir)
        if out_path:
            success.append(short_name)
        else:
            failed.append(short_name)

    # 4) 요약 출력
    print("\n===== Velociraptor Query 요약 =====")
    print(f"성공: {len(success)}개 / 실패: {len(failed)}개")
    if success:
        print("  [성공 목록]")
        print("   - " + ", ".join(success))
    if failed:
        print("  [실패 목록]")
        print("   - " + ", ".join(failed))
    print(f"\n[✓] Velociraptor Query 결과 폴더 → {local_dir}\n")

    # 하나도 성공 못 했으면 None 리턴
    if not success:
        return None

    return local_dir


# -------------------------------------------------------------------
# 5. Standalone 실행용 (테스트용)
# -------------------------------------------------------------------
if __name__ == "__main__":
    import getpass

    print("Standalone Velociraptor Query 모드 실행")
    ip = input("Target IP: ").strip()
    user = input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    root = os.path.expanduser("~/odea_krino/evidence/v2_report/standalone_test")
    os.makedirs(root, exist_ok=True)
    result_dir = run(ip, user, pw, root)
    print("결과 폴더:", result_dir)
