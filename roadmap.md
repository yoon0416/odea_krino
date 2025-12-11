# Krino: The ODEA Forensic Intelligence Framework  
## Project Roadmap (v1 ~ v6)

본 문서는 Krino의 전체 개발·연구 로드맵을 정의한다.  
Krino는 Open-Source DFIR/EDR 기반 위에 AI·Threat Intelligence·Timeline Reconstruction을 결합한  
고급 Forensic Intelligence 연구 프레임워크이다.

---

# Current Status

- **Current Architecture Implemented:** v2  
- **Research & Development Phase:** v3 ~ v6  
- **MISP Integration:** v2.2 예정  
- **AI Integration:** v3부터 본격 적용  

---

# Version Overview

Krino는 총 6단계로 구성되며,  
각 단계는 “EDR → DFIR → AI → Threat Intelligence → Attack Learning” 순으로 확장된다.

| Version | Stage | Description |
|--------|--------|-------------|
| **v1** | Static Mini-EDR | 기본 수집·탐지 기능 (수동) |
| **v2** | Automated Pipeline EDR | 전체 자동화 파이프라인 구축 |
| **v2.2** | TI Integration | MISP 기반 Threat Intelligence 강화 |
| **v3** | Embedded AI EDR | 로컬 LLM 기반 자동 분석 |
| **v4** | DFIR Timeline Reconstruction | 공격 흐름 재구성 AI |
| **v5** | Adaptive Monitoring | Risk 기반 동적 모니터링 |
| **v6** | Attack Learning AI | 공격 패턴 학습 및 룰 자동 생성 |

---

# v1 — Static Mini-EDR (Completed)

### 목표
- WinRM 기반 원격 명령 실행  
- Chainsaw 단독 실행  
- Osquery 단독 실행  
- Evidence JSON 수동 병합  
- LLM 수동 분석  

### 산출물
- `sigma_findings.json`  
- `processes.json`  
- `network.json`  
- `autoruns.json`  
- `velociraptor.json`  

---

# v2 — Automated Pipeline EDR (Completed)

### 목표
- 수집 → 병합 → 분석 자동화  
- CLI 기반 EDR 구조  
- Evidence JSON 자동 생성 (`result.json`)  
- Sigma/YARA 기반 탐지 자동화  

### 핵심 기능
- WinRM 자동 수집 스크립트  
- Evidence Aggregation Pipeline  
- Sigma/YARA 룰 기반 탐지  

---

#  v2.2 — MISP Threat Intelligence Integration (In Progress)

### 목표
- IOC 자동 추출  
- MISP Input 자동 전송  
- MISP Output 기반 Threat Intel 강화  
- APT/TTP 매핑  

### 기능
- Hash/Domain/IP 자동 추출  
- MISP Event 생성  
- Threat Score 기반 LLM 분석 강화  

---

# v3 — Embedded AI EDR ( Research Phase)

### 목표
- 로컬 LLM 완전 통합  
- Evidence → LLM → Report 자동 생성  
- DFIR CoT 기반 Reasoning  

### AI 기능
- Suspicious Behavior Explanation  
- IOC Correlation  
- TTP Classification  
- Markdown/PDF 자동 보고서 생성  

### 모델 전략
- Llama 3 8B  
- QLoRA 4-bit Fine-tuning  
- GGUF 4-bit Inference  

---

# v4 — DFIR Timeline Reconstruction (Research Phase)

### 목표
- 공격 타임라인 자동 재구성  
- Process Tree AI 추론  
- Persistence Map 생성  
- Network Storyline 생성  

### 기능
- Event Ordering  
- Temporal Reasoning  
- Attack Scenario Reconstruction  

---

# v5 — Risk Scoring & Adaptive Monitoring (Research Phase)

### 목표
- Host Trust Score 산출  
- Risk 기반 텔레메트리 조절  
- DFIR 모듈 자동 활성화  

### 기능
- Risk Score Engine  
- Dynamic Telemetry Control  
- Adaptive DFIR Collection  

---

# v6 — Attack Learning AI (Research Phase)

### 목표
- 공격 패턴 학습  
- Sigma/YARA 룰 자동 생성  
- Threat Simulation  
- RAG 기반 지식 확장  

### 기능
- Attack Pattern Embedding  
- Rule Generation AI  
- Threat Replay Simulation  

---

# Long-Term Vision

Krino의 최종 목표는 다음과 같다:

1. **AI 기반 DFIR 자동화 엔진**  
2. **Threat Intelligence + DFIR 융합 분석 플랫폼**  
3. **공격 타임라인 자동 재구성 시스템**  
4. **Risk 기반 적응형 모니터링 엔진**  
5. **공격 패턴 학습 기반 룰 자동 생성 AI**  

Krino는 단순한 EDR이 아니라  
**AI-Driven Forensic Intelligence Framework**로 발전하는 것을 목표로 한다.

---

# License & Contribution

- 본 프로젝트는 연구 목적의 오픈소스 프로젝트이다.  
- 외부 기여는 v3 이후 단계에서 허용될 예정이다.  

---

# Author

**Krino: The ODEA Forensic Intelligence Framework**  
Developed & Designed by: *[Yoon Gi, Ahn]*  
Research Focus: DFIR · EDR · AI · Threat Intelligence

