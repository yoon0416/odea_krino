# Krino: The ODEA Forensic Intelligence Framework
> OPEN-SOURCE • DFIR • EDR • AI  <br>
> Stable releases are documented in the GitHub Releases section | 2025.12.10 ~  <br>
> Current file timestamps: UTC-5 (EST) <br>

> Initial inference performance evaluation of the v3.0.0 LLM base model is currently in progress.  
All LLM-related source code is being researched and version-controlled in a private repository.  
The initial base model setup, inference test scripts, configuration details, and directory structure will be published in this repository at a later stage.


---

## Open-Source EDR + DFIR + LLM + Threat Intelligence System

**ODEA Krino** is a platform that integrates WinRM-based remote collection,
behavior-based detection using Chainsaw and Sigma rules,
system telemetry via Osquery,
and DFIR artifact collection using Velociraptor.

The project is designed to conduct research on  
**AI-driven Threat Intelligence and DFIR automation**, with a focus on validating end-to-end architecture rather than individual tools.

> The most important aspect of this project is not whether a bottleneck
> can be fully resolved, but whether the right decision is made to reach
> the ultimate goal—even if that requires changing tools or direction.

> In a single-architect design and implementation environment,
> clear prioritization between code completeness and rapid MVP delivery
> is required.

> ODEA KRINO prioritizes MVP realization over perfection
> and continues progressing to the next stage whenever bottlenecks are encountered.

---

This README represents **Full Architecture v1.5**,
covering AI setup, data structure, pipeline design, and LLM integration strategy.
It defines the complete roadmap from **v1 to v6**.

Current research phase: **v3 ~ v6**  
~~The MISP Threat Intelligence Pipeline was planned from v2.2~~  
> Due to attribute-related issues, MISP integration will proceed after LLM training.

- [Wiki](https://github.com/yoon0416/odea_krino/wiki)
- [Roadmap](https://github.com/yoon0416/odea_krino/wiki/Krino-Roadmap)
- [LICENSE](https://github.com/yoon0416/odea_krino/blob/main/LICENSE)
- [Version History](https://github.com/yoon0416/odea_krino/blob/main/version.md) + [releases](https://github.com/yoon0416/odea_krino/releases)
- [Functional Specification](https://github.com/yoon0416/odea_krino/blob/main/%EA%B8%B0%EB%8A%A5%EB%AA%85%EC%84%B8%EC%84%9C.md)
- [Krino AI Architecture](https://github.com/yoon0416/odea_krino/wiki/Krino-AI-Architecture)

---

# 1. Open-Source Components

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

# 2. Directory Structure

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

# 3. System Environment Overview

## Software / Host
- Windows 11 (Agent)
- Kali Linux / Ubuntu (Server)
- Python 3.x
- WinRM remote execution
- Chainsaw + Sigma
- Osquery
- YARA 4.5+
- Velociraptor
- MISP (v2.2+)
- Pandoc (PDF export)
- Hugging Face Transformers
- llama.cpp / llama-cpp-python

## AI / Hardware
- GPU: RTX 4070 Ti (12GB)
- Recommended model: Llama 3 8B
- Fine-tuning method: QLoRA 4-bit
- Quantization: GGUF 4-bit / 8-bit

## Storage Layout
- Evidence JSON repository
- DFIR dataset repository
- Threat Intelligence dataset (v5+)
- Attack pattern knowledge base (v6)

---

# 4. Research Objectives

1. Establish a remote security data collection architecture
2. Automate behavior-based detection using Sigma rules
3. Acquire structured telemetry using Osquery
4. Collect DFIR artifacts using Velociraptor
5. Integrate evidence into a unified JSON format (result.json)
6. Generate LLM-based threat analysis reports
7. Enhance Threat Intelligence using MISP (v2.2+)
8. DFIR timeline reconstruction (v4)
9. Adaptive monitoring and risk scoring (v5)
10. Attack-learning AI and automated rule generation (v6)

---

# 5. Baseline Architecture

```
Windows Agent ── WinRM ──> Central Server
| |
| Evidence Aggregation
| |
Chainsaw / Sigma LLM Threat Intelligence Engine
Osquery Automated Report Generator (MD / PDF)
Velociraptor MISP Threat Intelligence Enrichment (v2.2+)
```

---

# 6. Core Components

## 6.1 WinRM Remote Execution
Remote Windows execution without installing an agent.

- Osquery execution
- Chainsaw execution
- DFIR artifact collection
- JSON export

---

## 6.2 Chainsaw + Sigma
High-speed behavior-based detection using EVTX logs.

Outputs:
- sigma_findings.json
- evtx_hunt.json

Detection examples:
- Privilege escalation
- Remote code execution
- Suspicious PowerShell activity
- Account abuse
- Lateral movement

---

## 6.3 Osquery
Table-based inspection of operating system state.

- Processes
- Network sockets
- Services
- Registry keys
- Startup items

---

## 6.4 Velociraptor
Artifact-based DFIR data collection.

- Shimcache
- Amcache
- Prefetch
- SRUM

---

# 7. Evidence Pipeline Architecture

## 7.1 Data Flow

1. Chainsaw EVTX analysis
2. Osquery structured telemetry
3. Velociraptor DFIR artifacts
4. Agent to server JSON upload
5. Evidence JSON merge (result.json)
6. MISP input submission (v2.2+)
7. Threat Intelligence enrichment
8. LLM-based analysis and report generation

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
- DeepSeek 7B / 8B
- Mistral 7B
- Phi-3

Inference:
- 4-bit GGUF
- KV cache optimization
- FlashAttention

---

## 8.2 QLoRA Fine-tuning

Environment:
- RTX 4070 Ti
- Batch size: 1 to 2
- Learning rate: 1e-5 to 2e-5

Pipeline:
```
Pipeline:
Base Model (4-bit)
|
QLoRA
|
LoRA Adapters
|
Fine-tuned Security LLM
```

---

## 8.3 DFIR Dataset Composition

- Evidence JSON
- Chain-of-Thought DFIR instructions
- Attack scenario reconstruction
- TTP inference
- IOC analysis
- Risk evaluation

---

## 8.4 Deployment Structure

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

# 9. Automated Reporting

Generated sections:
- Summary
- Suspicious behavior
- Process analysis
- Network events
- Persistence evidence
- Attack timeline (v4+)
- Attacker scenario (v4+)
- TTP classification
- Recommendations
- IOC summary

Output formats:
- Markdown
- TXT
- PDF

---

# 10. Version Roadmap (v1 ~ v6)

- v1 — Static Mini-EDR
- v2 — Automated Pipeline EDR
- v2.2 — MISP Integration
- v3 — Embedded AI EDR
- v4 — DFIR Timeline Reconstruction
- v5 — Risk Scoring and Adaptive Monitoring
- v6 — Attack Learning AI

---

# 11. Conclusion

ODEA Krino extends an open-source EDR architecture by integrating
AI, DFIR, and Threat Intelligence (MISP) to support:

- Remote data collection
- Behavior-based detection
- DFIR telemetry acquisition
- Threat Intelligence enrichment
- Attack timeline reconstruction
- Automated rule generation
- Adaptive monitoring

as a unified research platform.
