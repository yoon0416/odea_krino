# Krino: The ODEA Forensic Intelligence Framework
> OPEN-SOURCE • DFIR • EDR • AI  <br>
> Architecture v2 | 2025.12.10 ~
> Current file timestamps: UTC-5 (EST)

### **중요 라이선스 고지**
> ODEA Krino 프레임워크의 소스 코드는 AGPL-3.0 라이선스를 따릅니다. <br>
> 그러나 AI 모델 학습 데이터셋, 설정 파일, 파인튜닝 산출물,
> 모델 가중치(Weights)는 디지털 포렌식 및 EDR R&D 과정에서 생성된 독점 연구 자산입니다.
>
> 이 자산에 대한 모든 독점적 권리는 안윤기(Yoon Gi, Ahn)에게 있으며,  
> 안윤기가 원할 경우에 한해 소속 회사로 권리가 이전될 수 있습니다.
>
> 해당 자산은 오픈소스가 아니며, 명시적 허가 없이는 사용·복제·수정·배포할 수 없습니다.

> - Krino는 Velociraptor의 소스 코드 또는 바이너리를 포함·통합·링크·수정·배포하지 않습니다.
> Velociraptor의 AGPL-3.0 라이선스는 ODEA Krino 프레임워크에 전파되지 않으며,  
> 본 프로젝트는 해당 라이선스의 강제 공개 의무의 적용을 받지 않습니다.

---

# AI-Driven DFIR & EDR Research Platform  
## Open-Source EDR + DFIR + LLM + Threat Intelligence System

**ODEA Krino**는 WinRM 기반 원격 수집, Chainsaw/Sigma 기반 행위 탐지, 
Osquery 기반 시스템 텔레메트리, Velociraptor 기반 DFIR 아티팩트 수집을 통합하여   <br>
**AI 기반 Threat Intelligence 및 DFIR 자동화 연구**를 수행하기 위한 플랫폼이다.
> - 코드의 완성도와 edr+DFIR 직접 구현보단 빠른 결과 도출 및 LLM 학습에 목표를 둔다.

본 README는 **AI 세팅, 데이터 구성, 파이프라인 구조, LLM 통합 전략**을 포함한  
Full Architecture v1.5 문서이며, v1~v6 전체 로드맵을 정의한다.

현재 아키텍처 구현 완료: **v2.1.0**  
연구 단계: **v3 ~ v6**  
v2.2부터 **MISP Threat Intelligence Pipeline**이 포함될 예정이다.

- [loadmap](https://github.com/yoon0416/odea_krino/blob/main/roadmap.md)
- [LICENSE](https://github.com/yoon0416/odea_krino/blob/main/LICENSE)
- [version(추후 릴리즈노트)](https://github.com/yoon0416/odea_krino/blob/main/version.md)
- [기능명세서](https://github.com/yoon0416/odea_krino/blob/main/%EA%B8%B0%EB%8A%A5%EB%AA%85%EC%84%B8%EC%84%9C.md)
- [Krino AI Architecture](https://github.com/yoon0416/odea_krino/blob/main/Krino%20AI%20Architecture.md)
  
---

# 1. Open-Source Components

- **Chainsaw**  
  https://github.com/WithSecureLabs/chainsaw  
- **Sigma Rules**  
  https://github.com/SigmaHQ/sigma  
- **Osquery**  
  https://github.com/osquery/osquery  
- **Velociraptor**  
  https://github.com/Velocidex/velociraptor  
- **MISP (Threat Intelligence Platform)**  
  https://github.com/MISP/MISP  

---

# 2. Directory Structure

```
odea_krino/                     
│
├── tools/                      # Chainsaw, Sigma, Osquery, YARA, Velociraptor 등
│   ├── chainsaw/
│   ├── sigma/
│   ├── osquery/
│   └── yara/
│
├── collectors/                 # WinRM·SSH 기반 원격 수집 스크립트
│   ├── windows/
│   └── linux/
│
├── pipelines/                  # v2~v3 자동화 파이프라인
│   ├── collect/                # 데이터 수집
│   ├── merge/                  # Evidence JSON 병합
│   └── analyze/                # LLM/TI 분석
│
├── evidence/                   # 수집된 로그/JSON (git 추적 금지)
│   ├── raw/
│   └── processed/
│
├── rules/                      # Sigma/YARA 커스텀 룰
│   ├── sigma/
│   └── yara/
│
├── models/                     # LLM 학습/추론 관련
│   ├── datasets/
│   ├── adapters/
│   └── configs/
│
├── scripts/                    # 실험용 스크립트
├── config/                     # hosts, winrm.conf 등
└── docs/                       # 아키텍처 문서, 연구 로그
```

---

# 3. System Environment Overview

## Software / Host
- Windows 11 (Agent)
- Kali Linux / Ubuntu (Server)
- Python 3.x
- WinRM Remote Execution
- Chainsaw + Sigma
- Osquery
- YARA 4.5+
- Velociraptor
- MISP (v2.2+)
- Pandoc (PDF Export)
- Hugging Face Transformers
- llama.cpp / llama-cpp-python

## AI / Hardware
- GPU: RTX 4070 Ti (12GB)
- Recommended Model: **Llama 3 8B**
- Fine-tuning: **QLoRA 4-bit**
- Quantization: **GGUF 4/8-bit**

## Storage Layout
- Evidence JSON Repository  
- DFIR Dataset Repository  
- Threat Intelligence Dataset (v5~)  
- Attack Pattern Knowledge Base (v6)

---

# 4. Research Objectives

본 연구는 다음을 목표로 한다:

1. 원격 보안 데이터 수집 구조 구축  
2. Sigma 기반 행위 탐지 자동화  
3. Osquery 기반 정형 텔레메트리 확보  
4. Velociraptor 기반 DFIR 아티팩트 수집  
5. Evidence JSON 통합(result.json)  
6. LLM 기반 위협 보고서 자동 생성  
7. MISP 기반 Threat Intelligence 강화(v2.2+)  
8. DFIR Timeline Reconstruction(v4)  
9. Adaptive Monitoring 및 Risk Scoring(v5)  
10. Attack Learning AI 및 룰 자동 생성(v6)

---

# 5. Baseline Architecture

```
Windows Agent ── WinRM ──> Central Server
  |                                |
  |                     Evidence Aggregation
  |                                |
Chainsaw/Sigma            LLM Threat Intelligence Engine
Osquery                   Automated Report Generator (MD/PDF)
Velociraptor              MISP Threat Intel Enrichment (v2.2+)
```

---

# 6. Core Components

## 6.1 WinRM Remote Execution
Agent 설치 없이 Windows 원격 조작 가능.

기능:
- Osquery 실행  
- Chainsaw 실행  
- DFIR 아티팩트 수집  
- JSON Export  

---

## 6.2 Chainsaw + Sigma
EVTX 기반 고속 행위 탐지.

출력:
- `sigma_findings.json`
- `evtx_hunt.json`

탐지 예:
- Privilege Escalation  
- RCE  
- Suspicious PowerShell  
- Account Attacks  
- Lateral Movement  

---

## 6.3 Osquery
운영체제 내부를 테이블 기반으로 조사.

수집 대상:
- Processes  
- Network Sockets  
- Services  
- Registry Keys  
- Startup Items  

---

## 6.4 Velociraptor
Artifacts 기반 고급 DFIR 데이터 수집.

예:
- Shimcache  
- Amcache  
- Prefetch  
- SRUM  

---

# 7. Evidence Pipeline Architecture

## 7.1 Data Flow

1. Chainsaw → EVTX 분석  
2. Osquery → 정형 텔레메트리  
3. Velociraptor → DFIR 아티팩트  
4. Agent → Server JSON 업로드  
5. Evidence JSON 병합(result.json)  
6. MISP Input 전송 (v2.2~)  
7. MISP Output 기반 TI 강화  
8. LLM 기반 분석 및 보고서 생성  

---

## 7.2 Evidence Structure

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

## 7.3 result.json Schema

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

# 8. AI Architecture (Full Stack)

## 8.1 Model Strategy
- Llama 3 8B  
- DeepSeek 7B/8B  
- Mistral 7B  
- Phi-3  

Inference:
- 4-bit GGUF  
- KV Cache 최적화  
- FlashAttention  

---

## 8.2 QLoRA Fine-tuning

환경:
- RTX 4070 Ti  
- Batch Size: 1~2  
- LR: 1e-5 ~ 2e-5  

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

## 8.3 DFIR Dataset 구성

- Evidence JSON  
- CoT 기반 DFIR Instruction  
- 공격 시나리오 재구성  
- TTP 추론  
- IOC 분석  
- 위험도 평가  

---

## 8.4 Deployment Structure

```
+-----------------------+
| Security LLM Engine   |
|  - Reasoning Module   |
|  - DFIR Timeline      |
|  - Rule Generator     |
|  - Risk Scoring       |
+-----------------------+
          |
      Local Inference
          |
      result.json
```

---

# 9. Automated Reporting

생성 요소:
- Summary  
- Suspicious Behavior  
- Process Analysis  
- Network Events  
- Persistence Evidence  
- Attack Timeline (v4+)  
- Attacker Scenario (v4+)  
- TTP Classification  
- Recommendations  
- IOC Summary  

출력:
- Markdown  
- TXT  
- PDF  

---

# 10. Version Roadmap (v1 ~ v6)

### (✓) v1 — Static Mini-EDR  
### (✓) v2 — Automated Pipeline EDR  
###  v2.2 — MISP Integration  
###  v3 — Embedded AI EDR  
###  v4 — DFIR Timeline Reconstruction  
###  v5 — Risk Scoring & Adaptive Monitoring  
###  v6 — Attack Learning AI  

---

# 11. Conclusion

ODEA Krino는 오픈소스 기반 EDR 구조에  
**AI · DFIR · Threat Intelligence(MISP)** 를 결합하여

- 원격 수집  
- 행위 탐지  
- DFIR 텔레메트리  
- Threat Intel 강화  
- 공격 타임라인 재구성  
- 룰 자동 생성  
- 적응형 모니터링  

까지 확장하는 고급 연구 플랫폼이다.



---

