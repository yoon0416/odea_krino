# 버전관리

## 1.0.2
  > - 25-12-10 17:43
  > - f6749a5

## 1.0.1
  > - 25-12-10 16:09
  > - 2cdc8e8
- WinRM을 활용한 Windows 이벤트 로그(EVTX) 원격 수집 기능 추가
- PowerShell 기반 EVTX Export(wevtutil epl) 자동화 구현
- Security / System / Application 로그 Export 성공
- 타임스탬프 + 랜덤 문자열 기반 고유 로그 디렉토리 생성 기능 추가
- ZIP 패키징 자동화 스크립트 구현 및 정상 동작 확인
  - scripts/remote_evtx_collect.py
    ```
    python3 remote_evtx_collect.py
    ```
- Mini-EDR v1 데이터 수집 파이프라인 기반 완성
```powershell
Add-LocalGroupMember -Group "Administrators" -Member "edradmin"
```

## 1.0.0 
  > - 25-12-10 14:49  
  > - 84437139a2b8b9d2b8df27c01ef13acd0378c1a4

- 전체적인 파일 디렉토리 생성  
- WinRM 연결 테스트 스크립트 생성 및 정상 동작 확인 (scripts/winrm_test.py)
  ```linux
  ┌──(kali㉿kali)-[~/openedr_v1/scripts]
  └─$ python3 winrm_test.py 
  
  === WinRM 연결 테스트 ===
  Target IP: 192.168.200.104   
  Username: edradmin
  Password: 
  [+] Endpoint: http://192.168.200.104:5985/wsman
  [+] 연결 테스트 중...
  /usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
    arc4 = algorithms.ARC4(self._key)
  hostname: DESKTOP-0N915IG
  
  whoami: desktop-0n915ig\edradmin
  
  [+] WinRM 연결 성공!
  ```
