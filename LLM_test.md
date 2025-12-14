## 프로젝트 개요: Llama 3.1 8B 전문 모델 구축

### 1. 목표 모델 및 환경

* **모델:** Meta Llama 3.1 8B Base Model
* **하드웨어:** NVIDIA RTX 4070 Ti (12GB VRAM)
* **주요 기술:** QLoRA (Quantized Low-Rank Adaptation)를 통한 파인튜닝 (**필수**)
* **최종 목표:** 사이버 보안, DFIR, 법률, IT 등 10개 전문 분야에서 **GPT-4 수준의 깊이와 정확도**를 갖춘 로컬 기반 전문가 모델 구축.

### 2. 초기 추론 능력 테스트 현황 및 결과 (Base Model)

| 구분 | 내용 | 시사점 |
| :--- | :--- | :--- |
| **언어 설정** | 초기 **한글** 인풋/아웃풋 시도 $\rightarrow$ **성능 저하로 포기**. | Llama 3.1 Base 모델은 한국어 성능이 취약하므로, **고품질의 영어 데이터셋**으로 학습하는 것이 필수적입니다. |
| **현재 진행** | **영어** 인풋/아웃풋으로 전환하여 진행 중. | **최종 응답을 한글로 원하는 경우**, 튜닝 시 **영어 질문/영어 응답** 데이터셋과 **영문 $\rightarrow$ 한글 번역 쌍** 데이터셋을 일부 포함하는 전략을 고려해야 합니다. |
| **코드 버전** | 2025년 12월 15일자 테스트 코드 수정 완료. | `bfloat16`, `max_new_tokens=512`, `repetition_penalty=1.15`, `do_sample=False` 설정으로 추론 일관성과 긴 답변 능력을 확보했습니다. |

### 3. 테스트 및 튜닝 계획 (로드맵)

총 10개 도메인에 걸쳐 각 300문제씩 (**총 3,000문제**) 테스트를 진행하며, 모델의 최적 성능 지점을 찾을 예정입니다.

#### A. 테스트 도메인 (10개 분야)

* **전문 분야 (핵심):** 사이버 시큐리티, DFIR, 법
* **기반 분야:** 컴퓨터 사이언스, IT (네트워크/OS), 수학, 인공지능, 개발, 클라우드, 금융

#### B. 로드맵 단계

| 단계 | 목표 및 작업 | 기술/전략 | 기대 효과 |
| :--- | :--- | :--- | :--- |
| **1단계** | **초기 추론 능력 확인** (현재 진행) | Base Model ($bfloat16$, 영어) | 튜닝이 필요한 지점(Format, Accuracy, Depth) 식별. |
| **2단계** | **Instruction 튜닝 (SFT)** | **QLoRA 필수** (4-bit). 10개 분야 고품질 Q/A 데이터셋 준비. | 모델이 **질문의 형식과 답변 규칙**을 따르도록 정렬. (가장 중요한 첫 번째 튜닝) |
| **3단계** | **성능 최적화 및 비교** | 튜닝된 모델에 대해 $Temperature$ 및 $repetition\_penalty$ 등 **추론 하이퍼파라미터** 미세 조정. | **최적의 추론 속도 및 정확도 균형점** 확보. |
| **4단계** | **정렬 튜닝 (Alignment)** | **DPO/RLAIF** 등 선호도 기반 튜닝. | 답변의 **신뢰성, 안전성, 실무적 적합성**을 GPT-4 수준으로 끌어올림. |
| **5단계** | **최종 학습 및 배포** | 최종적으로 검증된 QLoRA 설정을 이용해 **전체 데이터셋 학습** 시작. | 로컬 환경에 전문 모델 배포. |


```run_infer_cybersecurity.py
# 튜닝테스트 CYBERSECURITY FULL-SPECTRUM INFERENCE TEST 300문제

from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from datetime import datetime

MODEL_DIR = r"D:\krino_llm_train\model\llama-3.1-8b-base"

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_DIR,
    dtype=torch.bfloat16,
    device_map="auto"
)
model.eval()

# ===== 전체 테스트 시작 시간 (시스템 기준) =====
global_start_time = datetime.now()
print(f"\n[+] 전체 테스트 시작 시간 : {global_start_time.isoformat(timespec='seconds')}\n")


def ask(q):
    start_time = datetime.now()

    prompt = f"""Question:
{q}

Answer:
"""

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=512,            # ← 120 → 512로 변경 (긴 답변도 끝까지!)
            do_sample=False,               # 결정적 추론 (네가 원하는 대로 유지)
            repetition_penalty=1.15,       # ← 1.1 → 1.15 (반복 덜 하게)
            no_repeat_ngram_size=3,         # 문구 반복 방지
            # early_stopping=True 제거 ← 긴 설명 강제 종료 방지
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.eos_token_id
        )

    gen = outputs[0][inputs["input_ids"].shape[-1]:]
    answer = tokenizer.decode(gen, skip_special_tokens=True)

    end_time = datetime.now()
    elapsed_sec = (end_time - start_time).total_seconds()
    generated_tokens = len(gen)  # ← 추가: 토큰 수 확인 편함

    print("=" * 80)
    print(f"[질문 시작 시간] {start_time.isoformat(timespec='seconds')}")
    print(f"[질문 종료 시간] {end_time.isoformat(timespec='seconds')}")
    print(f"[추론 소요 시간] {elapsed_sec:.2f} 초")
    print(f"[생성된 토큰] {generated_tokens} tokens")  # ← 추가
    print(f"[질문] {q}")
    print(f"[응답] {answer.strip()}")
    print("=" * 80 + "\n")

    # =========================================================
# CYBERSECURITY FULL-SPECTRUM INFERENCE TEST (TOTAL 300)
# =========================================================

# ---------------------------
# Short Answer (1–120)
# ---------------------------
ask("What is cybersecurity?")
ask("What is information security?")
ask("What is the CIA triad?")
ask("What is confidentiality?")
ask("What is integrity?")
ask("What is availability?")
ask("What is threat modeling?")
ask("What is a vulnerability?")
ask("What is an exploit?")
ask("What is risk in cybersecurity?")
ask("What is attack surface?")
ask("What is penetration testing?")
ask("What is red teaming?")
ask("What is blue teaming?")
ask("What is purple teaming?")
ask("What is offensive security?")
ask("What is defensive security?")
ask("What is Kali Linux?")
ask("What is Metasploit?")
ask("What is Nmap?")
ask("What is Burp Suite?")
ask("What is SQL injection?")
ask("What is command injection?")
ask("What is XSS?")
ask("What is CSRF?")
ask("What is authentication bypass?")
ask("What is privilege escalation?")
ask("What is lateral movement?")
ask("What is persistence?")
ask("What is C2 communication?")
ask("What is malware?")
ask("What is ransomware?")
ask("What is a trojan?")
ask("What is a rootkit?")
ask("What is a backdoor?")
ask("What is fileless malware?")
ask("What is phishing?")
ask("What is spear phishing?")
ask("What is social engineering?")
ask("What is brute force attack?")
ask("What is credential stuffing?")
ask("What is EDR?")
ask("What is XDR?")
ask("What is SIEM?")
ask("What is SOC?")
ask("What is log correlation?")
ask("What is threat detection?")
ask("What is behavioral detection?")
ask("What is signature-based detection?")
ask("What is heuristic detection?")
ask("What is DFIR?")
ask("What is digital forensics?")
ask("What is incident response?")
ask("What is evidence preservation?")
ask("What is chain of custody?")
ask("What is disk forensics?")
ask("What is memory forensics?")
ask("What is network forensics?")
ask("What is Windows Event Log?")
ask("What is Sysmon?")
ask("What is Sigma rule?")
ask("What is MITRE ATT&CK?")
ask("What is TTP?")
ask("What is IOC?")
ask("What is threat intelligence?")
ask("What is OSQuery?")
ask("What is Velociraptor?")
ask("What is Chainsaw?")
ask("What is USN Journal?")
ask("What is NTFS?")
ask("What is MFT?")
ask("What is Prefetch?")
ask("What is Amcache?")
ask("What is Shimcache?")
ask("What is Windows Registry?")
ask("What is PowerShell logging?")
ask("What is process injection?")
ask("What is DLL hijacking?")
ask("What is living-off-the-land?")
ask("What is LOLBins?")
ask("What is sandbox evasion?")
ask("What is anti-forensics?")
ask("What is obfuscation?")
ask("What is packer?")
ask("What is malware sandbox?")
ask("What is reverse engineering?")
ask("What is static analysis?")
ask("What is dynamic analysis?")
ask("What is vulnerability scanning?")
ask("What is CVE?")
ask("What is CVSS?")
ask("What is patch management?")
ask("What is zero-day?")
ask("What is exploit kit?")
ask("What is botnet?")
ask("What is DDoS?")
ask("What is network segmentation?")
ask("What is zero trust?")
ask("What is MFA?")
ask("What is endpoint hardening?")
ask("What is security monitoring?")
ask("What is alert fatigue?")
ask("What is false positive?")
ask("What is false negative?")
ask("What is threat hunting?")
ask("What is detection engineering?")
ask("What is security baseline?")
ask("What is incident containment?")
ask("What is eradication?")
ask("What is recovery?")
ask("What is post-incident review?")

# ---------------------------
# Descriptive (121–210)
# ---------------------------
ask("Explain the difference between information security and cybersecurity.")
ask("Describe the CIA triad with practical examples.")
ask("Explain how threat modeling helps reduce risk.")
ask("Describe the lifecycle of a cyber attack.")
ask("Explain penetration testing versus red teaming.")
ask("Describe common tools used in Kali Linux.")
ask("Explain how Nmap is used in reconnaissance.")
ask("Describe common web application attack vectors.")
ask("Explain privilege escalation techniques.")
ask("Describe lateral movement within a network.")
ask("Explain persistence mechanisms used by malware.")
ask("Describe how command-and-control works.")
ask("Explain differences between malware types.")
ask("Describe ransomware attack phases.")
ask("Explain phishing detection techniques.")
ask("Describe how social engineering bypasses controls.")
ask("Explain the role of EDR in endpoint protection.")
ask("Describe how SIEM aggregates security data.")
ask("Explain behavioral detection versus signature detection.")
ask("Describe SOC analyst responsibilities.")
ask("Explain the DFIR process lifecycle.")
ask("Describe evidence handling best practices.")
ask("Explain disk versus memory forensics.")
ask("Describe how Windows Event Logs support investigations.")
ask("Explain the role of Sysmon in detection.")
ask("Describe Sigma rules and their benefits.")
ask("Explain MITRE ATT&CK framework usage.")
ask("Describe how threat intelligence improves detection.")
ask("Explain OSQuery use cases in security.")
ask("Describe how Velociraptor supports DFIR.")
ask("Explain Chainsaw role in log analysis.")
ask("Describe NTFS artifacts useful for forensics.")
ask("Explain USN Journal forensic value.")
ask("Describe Prefetch artifacts and limitations.")
ask("Explain Registry artifacts in investigations.")
ask("Describe PowerShell logging importance.")
ask("Explain process injection techniques.")
ask("Describe DLL hijacking attack paths.")
ask("Explain LOLBins and their abuse.")
ask("Describe malware evasion techniques.")
ask("Explain anti-forensics strategies.")
ask("Describe static malware analysis.")
ask("Explain dynamic malware analysis.")
ask("Describe vulnerability management lifecycle.")
ask("Explain CVSS scoring limitations.")
ask("Describe patch management challenges.")
ask("Explain zero-day exploitation risks.")
ask("Describe botnet command structures.")
ask("Explain DDoS mitigation strategies.")
ask("Describe network segmentation benefits.")
ask("Explain zero trust security model.")
ask("Describe MFA implementation challenges.")
ask("Explain endpoint hardening techniques.")
ask("Describe security monitoring workflows.")
ask("Explain alert fatigue causes.")
ask("Describe false positives versus false negatives.")
ask("Explain threat hunting methodologies.")
ask("Describe detection engineering practices.")
ask("Explain security baselines importance.")
ask("Describe incident containment strategies.")
ask("Explain malware eradication steps.")
ask("Describe recovery phase after incidents.")
ask("Explain lessons learned process.")
ask("Describe how attackers abuse legitimate tools.")
ask("Explain why visibility is critical in security.")
ask("Describe how attackers evade EDR.")
ask("Explain detection gaps in endpoint security.")
ask("Describe how log tampering affects investigations.")
ask("Explain cloud security challenges.")
ask("Describe container security risks.")
ask("Explain identity-based attacks.")
ask("Describe credential theft techniques.")
ask("Explain how memory-only malware operates.")
ask("Describe how attackers bypass AV.")
ask("Explain the importance of time synchronization.")
ask("Describe forensic timelines.")
ask("Explain correlation of multiple data sources.")
ask("Describe challenges in large-scale SOC operations.")
ask("Explain security automation benefits.")
ask("Describe threat intelligence false positives.")
ask("Explain proactive versus reactive security.")
ask("Describe security maturity models.")

# ---------------------------
# Scenario-Based (211–300)
# ---------------------------
ask("An endpoint triggers suspicious PowerShell activity. How should analysts investigate?")
ask("A ransomware alert appears on multiple hosts. What immediate steps should be taken?")
ask("An attacker gains initial access via phishing. How can lateral movement be detected?")
ask("EDR misses a fileless attack. Why might this occur?")
ask("A SOC receives thousands of alerts daily. How should alert fatigue be addressed?")
ask("Logs indicate credential dumping activity. What artifacts confirm this?")
ask("An attacker deletes event logs. How can DFIR still proceed?")
ask("A suspicious DLL is loaded by a trusted process. What attack is likely?")
ask("USN Journal shows file deletions. How is this useful in investigations?")
ask("A malware sample evades sandbox detection. What techniques might it use?")
ask("An attacker uses living-off-the-land binaries. How should detection adapt?")
ask("Memory analysis reveals injected code. What techniques caused this?")
ask("A C2 channel uses HTTPS. How can it still be detected?")
ask("A compromised host shows no disk artifacts. What forensic approach is needed?")
ask("An exploit uses a zero-day. How should defenders respond?")
ask("Threat intelligence indicates active exploitation. How should SOC adjust?")
ask("A vulnerability scan reports critical CVEs. What is the remediation priority?")
ask("A system shows abnormal parent-child process relationships. What does this suggest?")
ask("A user reports suspicious login alerts. How should investigation proceed?")
ask("An attacker uses scheduled tasks for persistence. How is this detected?")
ask("A registry key change indicates malware persistence. What key areas matter?")
ask("A network shows beaconing traffic. How is this analyzed?")
ask("An endpoint disables security services. What attacker action is this?")
ask("A SOC analyst suspects false positives. How can they validate?")
ask("EDR generates an alert but lacks context. What data sources help?")
ask("A malware outbreak spreads rapidly. What containment actions apply?")
ask("Logs from multiple hosts show similar behavior. What does this indicate?")
ask("An attacker clears Prefetch files. What evidence may remain?")
ask("PowerShell logging is disabled. What risk does this create?")
ask("A threat actor uses encoded commands. How can detection work?")
ask("An incident involves both Windows and Linux systems. How should response differ?")
ask("A phishing campaign bypasses email security. Why?")
ask("An attacker uses legitimate admin credentials. How can misuse be detected?")
ask("SOC detects suspicious DNS queries. What is analyzed next?")
ask("A compromised endpoint communicates with rare domains. What action is taken?")
ask("A forensic image is incomplete. What legal risks arise?")
ask("An attacker tampers with timestamps. How can this be identified?")
ask("EDR policy blocks legitimate activity. How should tuning occur?")
ask("A DFIR team must preserve volatile data. What is collected first?")
ask("An incident occurs in cloud infrastructure. What artifacts differ?")
ask("A SOC misses early indicators. How can detection engineering improve?")
ask("Attackers abuse remote administration tools. How are they detected?")
ask("A system shows abnormal service creation. What does this imply?")
ask("Threat hunters find no alerts but suspicious behavior. What next?")
ask("An endpoint is reimaged prematurely. What evidence is lost?")
ask("A malware sample is packed. How is analysis performed?")
ask("An attacker disables Windows Defender. What logs show this?")
ask("A network segmentation failure enables spread. What went wrong?")
ask("An EDR upgrade breaks detections. How is this mitigated?")
ask("A SOC lacks visibility into PowerShell. What risk exists?")
ask("An attacker uses WMI for persistence. How is this detected?")
ask("A DFIR case requires legal admissibility. What steps are critical?")
ask("An incident response team delays containment. What risks increase?")
ask("A threat actor uses time-based evasion. How can this be countered?")
ask("An endpoint shows abnormal DLL search order usage. What attack is this?")
ask("SOC automation closes alerts incorrectly. What danger exists?")
ask("An attacker uses cloud credentials to persist. How is this detected?")
ask("A detection rule produces many false positives. How should it be refined?")
ask("An organization lacks EDR coverage. What attack paths open?")
ask("An advanced attacker avoids known IOCs. What detection strategy helps?")
ask("A DFIR report is challenged in court. What documentation matters?")
ask("An incident response ends without lessons learned. What opportunity is lost?")
ask("Attackers blend in with normal user behavior. How can detection evolve?")

```


