# openedr_v1
---
# AI-Driven EDR Research Project (Full Architecture v1.5)
### Open-Source EDR + DFIR + LLM Threat Intelligence System

본 문서는 WinRM 기반 원격 수집, Chainsaw/Sigma 기반 행위 탐지,  
Osquery 기반 시스템 상태 분석을 중심으로  
LLM 기반 Threat Intelligence 시스템을 연구·구축하기 위한  
v1~v6 전체 아키텍처 로드맵을 정의한다.

본 버전(v1.5)은 기존 문서 대비 **AI 세팅·학습·추론·데이터 구성·최적화 전략을 전체 포함한 Full Version**이다. <br>
또한 현재 버전은 v1이다.
---
## 디렉토리리
```
openedr_v1/
│
├── tools/                 # 외부 도구(Chainsaw, Sigma, Osquery, YARA 등)
│   ├── chainsaw/
│   ├── sigma/
│   ├── osquery/
│   └── yara/
│
├── collectors/            # WinRM·SSH 기반 원격 수집 스크립트 (v1~v2 핵심)
│   ├── windows/
│   └── linux/             # (필요하면)
│
├── pipelines/             # v2~v3 자동화 파이프라인 엔진
│   ├── collect/
│   ├── merge/
│   └── analyze/
│
├── evidence/              # 수집된 JSON, EVTX, 로그 (절대 깃추적 X)
│   ├── raw/
│   └── processed/
│
├── rules/                 # Sigma/YARA 커스텀 룰 (연구 자산)
│   ├── sigma/
│   └── yara/
│
├── models/                # LLM 관련 데이터 (v3~v6)
│   ├── datasets/
│   ├── adapters/
│   └── configs/
│
├── scripts/               # 실험 스크립트 / 툴 자동화 샘플
│
├── config/                # YAML/INI 설정들 (hosts, winrm.conf 등)
│
├── docs/                  # 문서 (아키텍처, 실험 로그, PDF)
│
└── tests/                 # 유닛테스트 / 통합 테스트 (나중 v2~v3)

```
---

# 0. System Environment Overview

## Software / Host
- Windows 11 (Agent)
- Kali Linux / Ubuntu (Server)
- Python 3.x
- WinRM Remote Execution
- Chainsaw + Sigma Rules
- Osquery
- YARA (v4.5+ option)
- Pandoc (PDF Export)
- Hugging Face Transformers  
- llama.cpp / llama-cpp-python

## AI / Hardware
- RTX 4070 Ti 12GB VRAM (개인 연구 환경)
- Llama 3 8B (기본 추천)
- QLoRA 4-bit Fine-tuning Pipeline
- FlashAttention / KV-Cache 사용
- 4-bit / 8-bit GGUF Quantized Models

## Storage
- Evidence JSON Repository  
- DFIR Dataset Repository  
- Rule Generation Dataset  
- Attack Pattern Data (v6)

---

# 1. Research Objective

본 연구는 기존 룰 기반 EDR을 넘어  
AI 기반 Threat Intelligence + DFIR 자동화 시스템을 구축하는 것을 목표로 한다.

목표 요약:

1. 원격 보안 데이터 수집 구조 구축  
2. Sigma 기반 행위 탐지 자동화  
3. Osquery 기반 정형 텔레메트리 확보  
4. Evidence JSON 구조 통합 설계  
5. LLM 기반 위협 보고서 자동화  
6. LLM 기반 시나리오 생성 및 DFIR 재구성(v4)  
7. Adaptive Security Monitoring(v5)  
8. Attack Learning AI 및 룰 자동 생성(v6)

---

# 2. Baseline Architecture

```
Windows Agent ── WinRM ──> Central Server
  |                                |
  |                     Evidence Aggregation
  |                                |
Chainsaw/Sigma            LLM Threat Intelligence
Osquery                    Report Generation (MD/PDF)
JSON Export               DFIR Timeline Engine(v4)
```

---

# 3. Core Components

## 3.1 WinRM Remote Execution
EDR Agent 없이도 Windows 원격 제어 가능.  
수집 도구 실행 및 파일 회수에 사용.

- Osquery 실행  
- Chainsaw 실행  
- JSON Export  
- 결과 파일 다운로드

---

## 3.2 Chainsaw + Sigma
EVTX 이벤트 로그 기반의 행위 탐지 엔진.

출력:
- sigma_findings.json
- evtx_hunt.json

탐지 범위:
- 권한 상승
- 원격 코드 실행
- 악성 스크립트 실행
- 네트워크 스캔
- Lateral Movement 시그널
- 계정 관련 공격

---

## 3.3 Osquery
운영체제 내부 API를 추상화한 테이블 기반 보안 텔레메트리 수집.

수집 테이블:
- processes
- process_open_sockets
- registry
- services
- startup_items

출력 JSON:
- processes.json
- autoruns.json
- runkeys.json
- network.json

---

# 4. Evidence Pipeline Architecture

## 4.1 Data Flow
1. Chainsaw → EVTX 분석  
2. Osquery → 시스템 상태 수집  
3. Agent → Server로 JSON 다운로드  
4. Evidence 디렉토리 구성  
5. Evidence JSON 병합(result.json)  
6. LLM 기반 분석 및 자동 보고서

## 4.2 Evidence Structure
```
evidence/
  sigma.json
  processes.json
  network.json
  autoruns.json
  runkeys.json
  metadata.json
  result.json
```

## 4.3 Result JSON Schema
```json
{
  "sigma": [],
  "processes": [],
  "network": [],
  "autoruns": [],
  "runkeys": [],
  "metadata": {
    "hostname": "",
    "collected_at": ""
  }
}
```

---

# 5. AI Architecture (Full Stack)

본 섹션은 이번 버전에서 “가장 크게 강화된 부분”이다.

LLM 기반 Threat Intelligence 엔진을 구축하기 위한 전체 AI 구조를 다룬다.

---

# 5.1 Model Selection Strategy

모델 후보:
- Llama 3 8B (Strong reasoning)
- DeepSeek 7B / 8B (Fast, efficient)
- Mistral 7B (High throughput)
- Phi-3 (Lightweight)
- Mixtral (Optional v6 이상)

권장 모델:
- Llama 3 8B  
장점:
- 추론 정확도 우수
- 논리적 CoT 성능 높음
- RTX 4070 Ti 환경에서 최적

양자화:
- 4-bit GGUF → 추론 최적  
- QLoRA 4-bit → 학습 가능  

---

# 5.2 QLoRA Fine-tuning Pipeline

학습 환경:
- GPU: RTX 4070 Ti (12GB)
- Batch Size: 1~2
- Gradient Accumulation: 8~16
- Learning Rate: 1e-5 ~ 2e-5
- Target Modules: Query/Key/Value matrices (Attention Layers)

아키텍처 개요:
```
Base Model (4-bit quantized)
        |
     QLoRA
        |
   LoRA Adapters
        |
   Fine-tuned Security Model
```

---

# 5.3 Dataset Design (Security DFIR Dataset)

Dataset 구조는 시스템 품질의 핵심이다.

### 1) Evidence JSON Input
Osquery + Sigma + Network + Autoruns 조합.

### 2) CoT Reasoning Instruction
예:
```
아래 JSON은 Windows Obfuscated Load 공격 시나리오의 일부분이다.
프로세스 트리를 우선 구성하고,
공격자 실행 흐름을 시간순으로 정리한 뒤,
잠재적 공격 기법(TTP)을 기술하라.
```

### 3) Target Output
- 공격 시나리오
- DFIR 분석
- TTP 추론
- IOC 리스트
- 위험도 평가
- 대응 권고

### 4) 학습 데이터 구성 (예)
```
{
  "instruction": "Evidence JSON을 기반으로 공격 흐름을 재구성하라.",
  "input": "{ ... evidence json ... }",
  "output": "1) 탐지 개요 ... 2) 공격 흐름 ... 3) TTP ... 4) IOC ..."
}
```

---

# 5.4 Inference Optimization (추론 최적화)

개인 GPU 기반 최적화 요소:

- 4-bit Quantization  
- KV-Cache 최적화  
- Sliding Window Attention  
- prompt template 통일  
- multi-turn context 제한  
- chain-of-thought 압축 버전 사용

---

# 5.5 Deployment Structure

v3~v6에서 AI는 다음과 같이 배치된다.

```
+----------------------+
| Security LLM Engine  |
|  - Reasoning Module  |
|  - DFIR Timeline     |
|  - Rule Generator    |
|  - Risk Scoring      |
+----------------------+
          |
   Local Inference
          |
  result.json 분석
```

---

# 5.6 RAG (Retrieval Augmented Generation) Optional

DFIR 지식 보강을 위해 다음 문서들을 RAG Knowledge Base로 구축 가능:

- MITRE ATT&CK  
- CISA Alerts  
- MSRC Security Updates  
- KISA 분석보고서  
- 공격자 TTP 블로그  
- Incident Response 문서  

RAG는 v6에서 선택적으로 활성화 가능.

---

# 6. Automated Reporting

구성:
1. Summary  
2. Suspicious Behavior  
3. Process Analysis  
4. Network Events  
5. Persistence Evidence  
6. Attack Timeline (v4+)  
7. Attacker Scenario (v4+)  
8. TTP Classification  
9. Recommendations  
10. IOC 리스트  

출력:
- Markdown  
- TXT  
- PDF  

---

# 7. Version Roadmap (v1 ~ v6)

v3까지는 시스템 구축 단계이며  
v4부터 AI-DFIR 연구 단계로 확장된다.  
v5~v6는 AI 기반 Threat Intelligence의 핵심이다.

---

# v1 — Static Mini-EDR  
- WinRM 원격 실행  
- Chainsaw 단독 실행  
- Osquery 단독 실행  
- Evidence JSON 수동 병합  
- 보고서 LLM 수동 요청  

---

# v2 — Automated Pipeline EDR  
- Python 스크립트로 전체 자동화  
- 연속 파이프라인: 수집 → 병합 → 분석  
- CLI 기반 EDR 완성

---

# v3 — Embedded AI EDR  
- 오픈소스 LLM 오프라인 통합  
- Evidence JSON → AI → 보고서 자동 생성  
- 추론 최적화(4-bit)

---

# v4 — DFIR Timeline Reconstruction Engine  
- Evidence 기반 시간 순서 재구성  
- 프로세스 트리 AI 추론  
- 네트워크 흐름 파악  
- Persistence Map  
- v4.5: YARA, 메모리 분석 일부 포함  

본 단계부터 학술적 가치 급상승.

---

# v5 — Risk Scoring & Adaptive Monitoring  
- Host Trust Score  
- Risk Level 별 텔레메트리 수집량 조절  
- DFIR 모듈 자동 활성화  
- 폴링 주기 동적 변경  

Adaptive EDR의 핵심 구조.

---

# v6 — Attack Learning AI (Trainable Threat Intelligence)  
- AI가 공격 로그 패턴 학습  
- 시뮬레이션 공격 데이터 생성  
- Sigma/YARA 룰 자동 생성  
- 룰 자동 튜닝(FP/FN 감소)  
- OSINT 기반 TTP 학습  
- RAG 기반 지식 확장 옵션  

본 단계는 석사~박사 초기 연구 수준의 난이도를 가짐.

---

# 8. Conclusion

본 연구 로드맵(v1~v6)은 오픈소스 기반 EDR 기술을  
AI·DFIR·Threat Intelligence와 결합하여

1) 원격 수집  
2) 행위 기반 탐지  
3) 텔레메트리 분석  
4) 자동 보고서  
5) DFIR 타임라인 생성  
6) Adaptive Monitoring  
7) Threat Intelligence AI  

까지 발전시키는 체계적 연구 프로젝트이다.

특히 v4 이후는 학술 가치가 매우 높으며  
v6은 국내 선행 연구가 거의 없어 연구실·대학원 진학 시 강력한 독창성을 가진다.

---

# End of Document
