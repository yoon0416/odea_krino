# Main version 
> - v3.0.0 
> - server 1pc, agent 1pc
> - 버전 2.1 이후 귀찮아서 커밋명, 날짜 누락
---

# 릴리즈 노트

## 3.0.0 (Research / Local Only)

- LLM 기반 DFIR 분석 가능성 검증을 위한 v3 연구 단계 진입
- 대용량 모델 파일로 인해 GitHub 미업로드 (Local 환경 전용 연구)

### Environment
- New VMware Kali Linux (Server) 환경 구성
- Git clone 및 기본 파이프라인 세팅 완료
- Local Windows 11 환경에서 LLM 추론 테스트 수행
- Base Model: LLaMA 3.1 8B (Base)
- Framework: HuggingFace Transformers
- Precision: bfloat16
- Inference only (Fine-tuning / LoRA 미적용)

### Research Scope
- LLM 기반 DFIR / OSINT 질의응답 성능 평가
- 영어 입력/출력과 한국어 입력/출력 성능 비교 실험
- 자동 보고서(v3 목표) 이전 단계의 기초 추론 능력 검증

### Key Findings
- 영어 입력/출력 성능이 한국어 대비 명확히 우수함
- 영어:
  - 문장 구조 안정
  - DFIR / 보안 용어 인식 가능
  - 반복 및 붕괴 현상 제한적
  - 기초 수준의 실무 QA 가능
- 한국어:
  - 심각한 반복(loop) 및 문장 붕괴 발생
  - 보안 개념 오류 다수
  - 답변 중단 및 토큰 붕괴 빈번
  - 현 단계 실무 활용 불가

### Conclusion
- 본 Base Model은 영어 기준 DFIR 분석 엔진으로 발전 가능성 확인
- 한국어는 Base Model 기준 학습 데이터 및 토크나이저 한계로 성능 미달
- v3 단계에서는 영어 DFIR QA 안정화를 우선 목표로 설정

### Next Plan (v3.x)
- 영어 DFIR 전용 QA 데이터셋 구축
- 영어 기준 LoRA / QLoRA 파인튜닝 검토
- 한국어 DFIR는 별도 단계로 분리하여 후순위 연구
- 영어 분석 결과 → 한국어 요약 구조 검토 (단일 모델 통합 금지)

## 이슈
> ## v2.2.1
> - MISP attribute 이슈
> - kali liux(server) 터짐
> - 더이상 v2 패치 없이 v2.2.0에서 마무리 후 바로 v3 연구시작

## 2.2.0
- MISP Event JSON 1차 가공 완료
  > MISP 분석 및 상관분석을 위한 입력 준비 완료

## 2.1.4
- IOC v2 마지막 정규화 완료
  > 추가 정규화는 현재 예정 없음

## 2.1.3
- MISP에 던질 IOC 버전으로 2차 정규화
  > 추가 정규화 진행필요

## 2.1.2
- MISP에 던질 IOC 버전으로 1차 정규화
  > 추가 정규화 진행필요

## 2.1.1
- 각 항목마다 흩어져있던 json 통합버전 v1
  > 추가 정규화 진행필요

## 2.1.0 **중요**
- 레파지토리 odea_krino로 변경.

## 2.1.0
  > - 2025-12-11 15:51
  > - a31ebd1
- Velociraptor Query 기반 포렌식 아티팩트 수집 엔진(v2.1) 추가
  - 기존 collect 모드 대신 Windows 환경에서도 100% 동작하는 query 모드로 전면 재작성
  - WinRM 환경에서 안정적으로 실행되며 ZIP 업로드/다운로드 문제 완전 제거
  - Velociraptor artifact 함수(VQL) 직접 호출 방식으로 JSONL 기반 포렌식 결과 수집

- 수집되는 아티팩트 총 45개 이상 (대규모 포렌식 스택 자동화)
  - **실행 흔적 계열**
    - Prefetch, ShimCache, Amcache, JumpLists, LNK Files, RecentDocs
  - **파일시스템 포렌식**
    - MFT, USN Journal, RecycleBin
  - **브라우저 포렌식**
    - Chrome History/Downloads/Cookies  
    - Edge History/Downloads/Cookies
  - **포렌식 이벤트 로그**
    - EvtxFast, Security, System, Application, PowerShell, RemoteDesktop
  - **기기/네트워크 흔적**
    - USBDevices, FirewallLogs, DNSCache, RDPConnections
  - **시스템/레지스트리**
    - Autoruns, RunKeys, StartupApproved, InstalledPrograms, Shellbags, SRUM
  - **기타 시스템 정보**
    - Processes, Services, Drivers, Netstat, OS Info, Installed Patches

- 결과물 저장 구조 표준화
  - `~/openedr_v1/evidence/v2_report/<user_YYYYMMDD_HHMM>/velociraptor/*.jsonl`
  - 각 아티팩트별로 독립 JSONL 파일 생성
  - v3(자동 보고서 생성)용 데이터 모델의 기반 완성

- 기술적 개선사항
  - Velociraptor Offline Collector 부재 문제를 query 모드로 해결
  - WinRM User Token 권한 기반에서도 동작 가능한 아티팩트만 선별
  - 실패한 아티팩트 자동 로깅 + 성공/실패 분리 출력
  - main.py 기존 구조 변경 없이 모듈만 교체하여 호환성 유지

- Mini-EDR v2의 핵심 목표 완성
  - EVTX 기반 행위 탐지 + Sigma
  - 시스템 상태 기반 OSQuery 스윕
  - 포렌식 아티팩트 기반 Velociraptor Query
  - 모든 결과를 하나의 evidence root에 통합 저장
## 2.0.1
  > - 2025-12-11 12:54
  > - 2e55260
- evtx와 json 저장위치 v2버전으로 저장경로 바꿈

## 2.0.0
  > - 2025-12-11 11:50
  > - 9cc4ccd
- 수동으로 실행하던 각 기능들 통합으로 자동화
  
## 1.1.0
  > - 2025-12-10 20:35
  > - 3eb7ae6
  > - 모든 검사 항목 테스트 성공적으로 완료 ( 모든 생성형 ai에게 같은 json던지고 결과분석) 

- Windows Osquery 기반 원격 시스템 스윕 기능 추가
  - WinRM을 이용해 원격 Windows에서 osqueryi.exe 실행
  - 약 37개 정찰/DFIR 쿼리 자동 실행 후 JSON으로 수집
  - 결과는 `evidence/osquery/sweep_YYYYMMDD_HHMMSS/` 구조로 저장
- 수집 항목 예시
  - 프로세스/소켓/네트워크 세션/리스닝 포트
  - 서비스·드라이버·커널드라이버
  - 사용자·그룹·로그온 세션·로그인 사용자
  - 자동 실행 항목·스케줄러 작업
  - OS/패치/설치 프로그램/시스템 정보
  - 디스크·파티션·마운트
  - 보안 제품 상태(windows_security_products)
  - Run 키·RDP 관련 레지스트리
  - DNS·인터페이스 설정
  - USB 디바이스 / 이력
  - Chrome 확장/히스토리/쿠키
  - Prefetch, Shimcache, Amcache, PowerShell 이벤트/스크립트 등 DFIR 테이블
- Mini-EDR v1 아키텍처 정리
  - EVTX 기반 탐지(Chainsaw + Sigma)
  - Osquery 기반 상태/포렌식 스윕
  - 모든 결과를 JSON으로 표준화하여 후속 LLM 분석 준비

---

## 1.0.4
  > - 25-12-11 10:22
  > - ee8948f
- chainsaw+sigma 분석 후 json 저장 성공
  - scripts/analyze_evtx.py
- 이그노어 항목 추가

## 1.0.3
  > - 25-12-11 09:56
  > - beb663a
- 다운로드 한 zip파일 압축해제 자동화까지 성공
- 기존 remote_evtx.py 에 소스코드 추가

## 1.0.2
  > - 25-12-10 17:43
  > - f6749a5
- evidence/raw 폴더 Git 추적 제외 처리 (.gitignore 추가)
- WinRM 기반 ZIP 다운로드 시 Windows 경로 전체가 파일명으로 저장되던 문제 수정
  - zip_path에서 파일명 추출 시 Windows 경로 구분자(\) → (/ )로 변환하여 basename 처리
- ZIP 다운로드 안정성 개선
- Mini-EDR v1 파이프라인 구조 정리 및 준비 완료

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
# 향후 방향

## v1.2 (보류)
- yara 추가


