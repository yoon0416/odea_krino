# Krino: ODEA 포렌식 인텔리전스 프레임워크
> OPEN-SOURCE • DFIR • EDR • AI  
> 안정화된 릴리즈는 GitHub Releases 섹션에 기록됨 | 2025.12.10 ~  
> 파일 타임스탬프 기준: UTC-5 (EST)

---

## 오픈소스 기반 EDR + DFIR + LLM + 위협 인텔리전스 시스템

**ODEA Krino**는 WinRM 기반 원격 수집,  
Chainsaw 및 Sigma 룰을 활용한 행위 기반 탐지,  
Osquery 기반 시스템 텔레메트리 수집,  
Velociraptor 기반 DFIR 아티팩트 수집을 통합한 플랫폼이다.

본 프로젝트는 개별 도구의 사용 자체보다는  
**엔드 투 엔드 아키텍처 검증과 자동화 파이프라인 설계**를 중심으로  
**AI 기반 Threat Intelligence 및 DFIR 자동화 연구**를 수행하는 것을 목표로 한다.

> 본 프로젝트에서 가장 중요하게 보는 것은  
> 병목 현상을 끝까지 해결하는 것 자체가 아니라,  
> 도구 변경이나 방향 수정이 필요하더라도  
> 궁극적인 목표에 도달하기 위한 올바른 판단을 내리는 것이다.

> 1인 아키텍처 설계 및 구현 환경에서는  
> 코드의 완성도와 빠른 MVP 도출 사이에서  
> 명확한 우선순위 설정이 필수적이다.

> ODEA KRINO 프로젝트는 완성도에 집착하기보다  
> MVP 구현을 최우선으로 삼고,  
> 병목 현상이 발생하더라도 다음 단계로 지속적으로 전진하는 것을 지향한다.

---

본 README는 **Full Architecture v1.5** 문서로서,  
AI 세팅, 데이터 구조, 파이프라인 설계, LLM 통합 전략을 포함하며  
**v1부터 v6까지의 전체 로드맵**을 정의한다.

현재 연구 단계: **v3 ~ v6**  
~~v2.2부터 MISP Threat Intelligence Pipeline 포함 예정~~  
> Attribute 이슈로 인해 LLM 학습 이후 단계에서 진행 예정

- [로드맵](https://github.com/yoon0416/odea_krino/blob/main/roadmap.md)
- [라이선스](https://github.com/yoon0416/odea_krino/blob/main/LICENSE)
- [버전 히스토리](https://github.com/yoon0416/odea_krino/blob/main/version.md)
- [기능 명세서](https://github.com/yoon0416/odea_krino/blob/main/%EA%B8%B0%EB%8A%A5%EB%AA%85%EC%84%B8%EC%84%9C.md)
- [Krino AI 아키텍처](https://github.com/yoon0416/odea_krino/blob/main/Krino%20AI%20Architecture.md)

---

# 1. 오픈소스 구성 요소

- Chainsaw  
  https://github.com/WithSecureLabs/chainsaw

- Sigma Rules  
  https://github.com/SigmaHQ/sigma

- Osquery  
  https://github.com/osquery/osquery

- Velociraptor  
  https://github.com/Velocidex/velociraptor

- MISP (Threat Intelligence Platform)  
  https://github.com/MISP/MISP

---

# 2. 디렉터리 구조

```
odea_krino/
│
├── tools/
│ ├── chainsaw/
│ ├── sigma/
│ ├── osquery/
│ └── yara/
│
├── collectors/
│ ├── windows/
│ └── linux/
│
├── pipelines/
│ ├── collect/
│ ├── merge/
│ └── analyze/
│
├── evidence/
│ ├── raw/
│ └── processed/
│
├── rules/
│ ├── sigma/
│ └── yara/
│
├── models/
│ ├── datasets/
│ ├── adapters/
│ └── configs/
│
├── scripts/
├── config/
└── docs/
```

---

# 3. 시스템 환경 개요

## 소프트웨어 / 호스트
- Windows 11 (Agent)
- Kali Linux / Ubuntu (Server)
- Python 3.x
- WinRM 원격 실행
- Chainsaw + Sigma
- Osquery
- YARA 4.5+
- Velociraptor
- MISP (v2.2+)
- Pandoc (PDF 출력)
- Hugging Face Transformers
- llama.cpp / llama-cpp-python

## AI / 하드웨어
- GPU: RTX 4070 Ti (12GB)
- 권장 모델: Llama 3 8B
- 파인튜닝 방식: QLoRA 4-bit
- 양자화: GGUF 4-bit / 8-bit

## 스토리지 구성
- Evidence JSON 저장소
- DFIR 데이터셋 저장소
- Threat Intelligence 데이터셋 (v5+)
- Attack Pattern 지식 베이스 (v6)

---

# 4. 연구 목표

본 연구는 다음 목표를 가진다.

1. 원격 보안 데이터 수집 아키텍처 구축  
2. Sigma 기반 행위 탐지 자동화  
3. Osquery 기반 정형 텔레메트리 확보  
4. Velociraptor 기반 DFIR 아티팩트 수집  
5. Evidence JSON 통합(result.json)  
6. LLM 기반 위협 분석 보고서 자동 생성  
7. MISP 기반 Threat Intelligence 강화(v2.2+)  
8. DFIR 타임라인 재구성(v4)  
9. 적응형 모니터링 및 위험도 산정(v5)  
10. 공격 학습 AI 및 룰 자동 생성(v6)  

---

# 5. 기본 아키텍처

```
Windows Agent ── WinRM ──> Central Server
| |
| Evidence Aggregation
| |
Chainsaw / Sigma LLM Threat Intelligence Engine
Osquery 자동 보고서 생성기 (MD / PDF)
Velociraptor MISP Threat Intelligence 연계 (v2.2+)
```

---

# 6. 핵심 구성 요소

## 6.1 WinRM 원격 실행
에이전트 설치 없이 Windows 원격 실행 가능.

- Osquery 실행
- Chainsaw 실행
- DFIR 아티팩트 수집
- JSON 출력

---

## 6.2 Chainsaw + Sigma
EVTX 로그 기반 고속 행위 탐지.

출력:
- sigma_findings.json
- evtx_hunt.json

탐지 예시:
- 권한 상승
- 원격 코드 실행
- 의심스러운 PowerShell
- 계정 공격
- 측면 이동

---

## 6.3 Osquery
운영체제 내부 상태를 테이블 기반으로 조사.

- 프로세스
- 네트워크 소켓
- 서비스
- 레지스트리 키
- 자동 실행 항목

---

## 6.4 Velociraptor
아티팩트 기반 고급 DFIR 데이터 수집.

- Shimcache
- Amcache
- Prefetch
- SRUM

---

# 7. Evidence 파이프라인 아키텍처

## 7.1 데이터 흐름

1. Chainsaw EVTX 분석  
2. Osquery 정형 텔레메트리 수집  
3. Velociraptor DFIR 아티팩트 수집  
4. Agent → Server JSON 업로드  
5. Evidence JSON 병합(result.json)  
6. MISP 입력 전송(v2.2+)  
7. Threat Intelligence 강화  
8. LLM 기반 분석 및 보고서 생성  

---

## 7.2 Evidence 구조

```
evidence/
raw/
sigma.json
processes.json
network.json
autoruns.json
runkeys.json
velociraptor.json
processed/
result.json
```

---

## 7.3 result.json 스키마


```
{
"raw": {
"sigma": [],
"processes": [],
"network": [],
"autoruns": [],
"runkeys": [],
"velociraptor": []
},
"metadata": {
"hostname": "",
"collected_at": ""
},
"ioc": {
"hashes": [],
"domains": [],
"ips": [],
"file_paths": [],
"process_cmd": [],
"registry_keys": [],
"yara_hits": [],
"sigma_hits": []
}
}
```

---

# 8. AI 아키텍처 (전체 스택)

## 8.1 모델 전략
- Llama 3 8B
- DeepSeek 7B / 8B
- Mistral 7B
- Phi-3

추론 환경:
- 4-bit GGUF
- KV Cache 최적화
- FlashAttention

---

## 8.2 QLoRA 파인튜닝

환경:
- RTX 4070 Ti
- 배치 크기: 1 ~ 2
- 학습률: 1e-5 ~ 2e-5

파이프라인:
```
Base Model (4-bit)
|
QLoRA
|
LoRA Adapters
|
Fine-tuned Security LLM
```

---

## 8.3 DFIR 데이터셋 구성

- Evidence JSON
- CoT 기반 DFIR 지시문
- 공격 시나리오 재구성
- TTP 추론
- IOC 분석
- 위험도 평가

---

## 8.4 배포 구조

```
+-----------------------+
| Security LLM Engine |
| - Reasoning Module |
| - DFIR Timeline |
| - Rule Generator |
| - Risk Scoring |
+-----------------------+
|
Local Inference
|
result.json
```

---

# 9. 자동 보고서 생성

생성 항목:
- 요약
- 의심 행위
- 프로세스 분석
- 네트워크 이벤트
- 지속성 증거
- 공격 타임라인(v4+)
- 공격자 시나리오(v4+)
- TTP 분류
- 대응 권고
- IOC 요약

출력 형식:
- Markdown
- TXT
- PDF

---

# 10. 버전 로드맵 (v1 ~ v6)

- v1 — 정적 Mini-EDR
- v2 — 자동화 파이프라인 EDR
- v2.2 — MISP 연동
- v3 — AI 내장형 EDR
- v4 — DFIR 타임라인 재구성
- v5 — 위험도 산정 및 적응형 모니터링
- v6 — 공격 학습 AI

---

# 11. 결론

ODEA Krino는 오픈소스 기반 EDR 아키텍처에  
AI, DFIR, Threat Intelligence(MISP)를 결합하여 다음을 가능하게 하는  
통합 연구 플랫폼이다.

- 원격 데이터 수집
- 행위 기반 탐지
- DFIR 텔레메트리 확보
- Threat Intelligence 강화
- 공격 타임라인 재구성
- 룰 자동 생성
- 적응형 모니터링
