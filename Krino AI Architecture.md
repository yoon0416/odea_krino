# Krino AI Architecture  
## AI-Driven DFIR & Threat Intelligence Engine

본 문서는 Krino: The ODEA Forensic Intelligence Framework의  
AI 구성 요소(v3~v6)를 정의한다.  
Krino의 AI는 DFIR 데이터(result.json)를 기반으로  
위협 분석, 공격 타임라인 재구성, 룰 생성까지 수행하는  
고급 Forensic Intelligence 엔진이다.

---

# 1. AI Integration Overview

Krino의 AI는 다음 4단계로 확장된다:

1. **v3 — Embedded AI EDR**  
2. **v4 — DFIR Timeline Reconstruction AI**  
3. **v5 — Risk Scoring & Adaptive Monitoring AI**  
4. **v6 — Attack Learning & Rule Generation AI**

각 단계는 이전 단계의 데이터를 기반으로 고도화된다.

---

# 2. Model Strategy

Krino는 로컬 환경에서 실행 가능한  
경량·고성능 LLM을 중심으로 설계되었다.

### 추천 모델
- **Llama 3 8B** (기본)
- DeepSeek 7B / 8B
- Mistral 7B
- Phi-3
- Mixtral (optional)

### 추론 전략
- GGUF 4-bit / 8-bit
- KV Cache 최적화
- FlashAttention
- Sliding Window Attention

### 파인튜닝 전략
- QLoRA 4-bit
- LoRA Adapter 기반 모듈화
- Security/DFIR Instruction Dataset 사용

---

# 3. Evidence → AI 분석 파이프라인

Krino의 AI는 다음 입력을 기반으로 분석을 수행한다:

### 입력 데이터(result.json)
- Sigma Findings  
- Process List  
- Network Events  
- Autoruns / Runkeys  
- Velociraptor Artifacts  
- IOC (Hash, Domain, IP 등)  
- Metadata (Hostname, Timestamp)

### 출력 데이터
- Suspicious Behavior Summary  
- IOC Correlation  
- TTP Classification  
- 공격 시나리오 설명  
- DFIR 보고서(MD/PDF)  
- 타임라인(v4~)  
- Risk Score(v5~)  
- Rule Generation(v6~)

---

# 4. v3 — Embedded AI EDR (AI 기반 자동 분석)

### 목표
- Evidence → LLM → Report 자동화
- DFIR CoT 기반 Reasoning
- Threat Intelligence 강화 분석

### 기능
- 의심 행위 설명
- IOC 상관 분석
- MITRE ATT&CK 매핑
- Markdown/PDF 보고서 자동 생성

### 예시 출력
- 공격자 의도 분석  
- 프로세스 기반 공격 흐름  
- 네트워크 이상 행위  
- IOC 기반 위험도 평가  

---

# 5. v4 — DFIR Timeline Reconstruction AI

### 목표
- 공격 타임라인 자동 재구성
- Process Tree AI 추론
- Persistence Map 생성
- Network Storyline 생성

### 기능
- 이벤트 시간 정렬
- Temporal Reasoning
- 공격 단계별 설명
- 공격자 행동 흐름 시각화(텍스트 기반)

### 예시
```
[2025-12-10 14:22] Suspicious PowerShell 실행  
[2025-12-10 14:23] 외부 C2 서버 연결  
[2025-12-10 14:24] 계정 정보 탈취 시도  
[2025-12-10 14:25] Lateral Movement 탐지  
```

---

# 6. v5 — Risk Scoring & Adaptive Monitoring AI

### 목표
- Host Trust Score 산출
- Risk 기반 텔레메트리 조절
- DFIR 모듈 자동 활성화

### 기능
- 위험도 기반 DFIR 수집량 조절  
- 고위험 시 Velociraptor Artifact 자동 수집  
- 저위험 시 Osquery만 유지  

### Risk Score 예시
- 0~30: Low  
- 31~60: Medium  
- 61~100: High  

---

# 7. v6 — Attack Learning & Rule Generation AI

### 목표
- 공격 패턴 학습
- Sigma/YARA 룰 자동 생성
- Threat Simulation
- RAG 기반 지식 확장

### 기능
- 공격 패턴 Embedding  
- 유사 공격 탐지  
- 룰 자동 생성  
- Threat Replay Simulation  

### Sigma 룰 자동 생성 예시
```
title: Suspicious PowerShell with EncodedCommand
logsource:
  product: windows
  service: powershell
detection:
  selection:
    CommandLine|contains: "-EncodedCommand"
condition: selection
level: high
```

---

# 8. Dataset 구성 전략

Krino AI는 다음 데이터셋을 기반으로 학습/추론한다:

### DFIR Dataset
- Evidence JSON  
- Process/Network Telemetry  
- Velociraptor Artifacts  

### Instruction Dataset
- DFIR CoT  
- 공격 시나리오 재구성  
- IOC 분석  
- TTP 매핑  
- Risk 평가  

### Threat Intelligence Dataset
- MISP Export  
- MITRE ATT&CK  
- CISA Alerts  
- KISA 보고서  

---

# 9. Prompt Template (기본)

```
You are a DFIR & Threat Intelligence Analyst.
Analyze the following evidence and generate a detailed forensic report.

[Evidence JSON]
{{result.json}}

Tasks:
1. Identify suspicious behavior
2. Correlate IOC
3. Map TTP (MITRE ATT&CK)
4. Reconstruct attack scenario
5. Provide recommendations
```

---

# 10. Long-Term AI Vision

Krino AI의 최종 목표는 다음과 같다:

1. **AI 기반 DFIR 자동화 엔진**  
2. **공격 타임라인 자동 재구성 시스템**  
3. **Risk 기반 적응형 모니터링**  
4. **공격 패턴 학습 기반 룰 자동 생성**  
5. **Threat Intelligence + DFIR 융합 분석 플랫폼**

Krino는 단순한 EDR이 아니라  
**AI-Driven Forensic Intelligence Framework**로 발전하는 것을 목표로 한다.

