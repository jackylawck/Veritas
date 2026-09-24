# ⚖️ Veritas Legal, Privacy & AI Regulatory Compliance Framework
# 法律、隱私與人工智能監管合規架構

> **Document Version / 文件版本:** 2.0 (Statutory Edition)  
> **Effective Date / 生效日期:** September 2026  
> **Jurisdictions Covered / 適用法域:** Global (EU, HKSAR, US, PRC, Singapore, UK, Commonwealth)  
> **Standard Alignment / 標準對齊:** ISO/IEC 27001:2022, ISO/IEC 27701:2019, ISO/IEC 42001:2023 (Scope Statement), OASIS STIX 2.1  

---

## 1. Executive Summary / 執行摘要

Veritas ("揭偽") is an open-source, deterministic, sovereign threat intelligence mirror providing machine-readable STIX 2.1 feeds aggregating statutory fraud bulletins.  
This document formalizes the legal posture, data protection compliance, and regulatory boundary justifications to safeguard project maintainers, downstream consumers, and enterprise integrators.

Veritas（「揭偽」）為一開源、確定性、主權威脅情報鏡像庫，旨在將法定機構之防偽防詐公報結構化為 OASIS STIX 2.1 機讀情報。  
本文件確立本專案之法律地位、資料隱私合規性與監管管轄邊界判定，為專案維護者、下游使用者及企業集成端提供法定抗辯與法律保障。

---

## 2. Artificial Intelligence Regulatory Justification (Negative Scope Statement)
## 人工智能法規管轄評估（負面清單與不適用性判定）

### 2.1 European Union AI Act (Regulation (EU) 2024/1689)
* **Applicability Finding / 判定結論:** **OUT OF SCOPE / 完全不適用**
* **Statutory Ground / 法理依據:**  
  According to Article 3(1) of the EU AI Act, an "AI system" is defined as a machine-based system that is designed to operate with varying levels of autonomy and that may exhibit adaptiveness after deployment, and that, for explicit or implicit objectives, infers from the input it receives how to generate outputs such as predictions, content, recommendations, or decisions.  
  **Veritas operates exclusively on deterministic, heuristic, and rule-based ETL (Extract, Transform, Load) pipelines (regular expressions, string matching, and cryptographic hashing via RFC 4122 UUIDv5). It contains zero machine learning models, zero statistical inferences, zero neural networks, and zero generative capabilities.** Therefore, Veritas does not qualify as an AI System, General Purpose AI (GPAI), or High-Risk AI system under Annex III.
* **中文說明:**  
  依據《歐盟人工智能法》(EU AI Act) 第 3(1) 條之定義，本專案僅使用確定性正規表達式與密碼學雜湊演算法（UUIDv5）進行數據轉換，**絕無任何自主推論、統計學習、神經網絡或內容生成機制**。本專案依法非屬 AI 系統，免除該法項下之一切備案、高風險審查及註冊義務。

### 2.2 Cyberspace Administration of China (CAC) AI Regulations / 國家網信辦相關規定
* **Applicability Finding / 判定結論:** **EXEMPT / 不受管轄**
* **Statutory Ground / 法理依據:**  
  Veritas does not fall under the *Interim Measures for the Management of Generative Artificial Intelligence Services* (《生成式人工智能服務管理暫行辦法》) or algorithm recommendation filing requirements, as the platform does not provide generative text/media services to the public, nor does it employ algorithmic recommendation engines within the territory of the PRC.
* **中文說明:**  
  本專案不具備生成式 AI 演算法，亦未在中國境內提供演算法推薦或公眾生成式服務，不屬於網信辦《生成式人工智能服務管理暫行辦法》之管轄對象。

### 2.3 ISO/IEC 42001:2023 (Artificial Intelligence Management System - AIMS)
* **Statement of Non-Applicability (SoNA) / 不適用性聲明:**  
  Because no artificial intelligence models are trained, tuned, developed, or deployed in Veritas, ISO/IEC 42001 certification and operational controls are formally designated as **Non-Applicable**.
* **中文說明:**  
  由於本專案無任何 AI 模型之訓練、微調、開發或運行，依 ISO 審計規範，正式將 ISO/IEC 42001 控制項列為**不適用 (Non-Applicable)**。

---

## 3. Data Protection, Privacy & Personal Data (Zero-PII Compliance)
## 資料保護、個人隱私與個資條例合規（零個資宣告）

### 3.1 Personal Data (Privacy) Ordinance (Cap. 486, Hong Kong SAR) / 香港《個人資料（私隱）條例》
* **Finding / 判定:** **FULLY COMPLIANT / 完全合規**
* **Legal Analysis / 法律分析:**  
  Under Section 2 of Cap. 486, "personal data" refers to data relating directly or indirectly to a living individual, from which it is practicable for the identity of the individual to be directly or indirectly ascertained.  
  Veritas exclusively mirrors:
  1. Names of corporations, unincorporated syndicates, and fraudulent business platforms declared by statutory bodies;
  2. Technical indicators of compromise (IoC) strictly limited to domain names, URLs, and server endpoints.  
  **No natural person identifiers, IP addresses associated with residential subscribers, biometric data, identification numbers, or private communications are ingested or retained.**
* **中文說明:**  
  依據香港法例第 486 章第 2 條，本專案僅收錄法定機構公告之法人機構名稱、可疑涉詐商業實體及技術性失陷指標（網域名稱），**絕不收集、處理或儲存任何自然人之可識別身分資料（PII）**，完全符合私隱專員公署（PCPD）合規標準。

### 3.2 Regulation (EU) 2016/679 (General Data Protection Regulation - GDPR)
* **Finding / 判定:** **OUT OF MATERIAL SCOPE (Recital 14) / 排除在物質管轄外**
* **Legal Analysis / 法律分析:**  
  * Recital 14 of GDPR explicitly establishes that protection afforded by this Regulation does not apply to the processing of personal data which concerns legal persons, including corporations and established enterprises.
  * Technical IoCs published by Veritas are cryptographic attributes of cyber infrastructure deployed for unlawful conduct. Under Article 6(1)(f), even where an IoC theoretically resolves to an individual registrant, processing is justified by the legitimate interest of sovereign defense and collective cybersecurity (Recital 49).
* **中文說明:**  
  依據 GDPR 序言第 14 條，本條例不保護法人與商業實體資料；技術性 IoC 之處理依據 GDPR 第 6(1)(f) 條及序言第 49 條，具備維護網絡安全之最高合法利益（Legitimate Interest）。

### 3.3 ISO/IEC 27701:2019 Privacy Information Management (PIMS) Alignment
* Veritas enforces **Privacy by Design and by Default** through irreversible cryptographic deduplication, data minimization, and immediate rejection of non-entity metadata fields during the ETL phase.

---

## 4. Information Security & Supply Chain Integrity (ISO/IEC 27001 Alignment)
## 資訊安全與供應鏈完整性架構（ISO/IEC 27001 對齊）

While Veritas operates as an open-source decentralized repository, its technical controls align with ISO/IEC 27001:2022 Annex A:
1. **A.8.9 Configuration Management:** Zero external dependencies (Vanilla Python standard libraries only), eliminating third-party supply chain vectors (e.g., PyPI typosquatting).
2. **A.8.24 Use of Cryptography:** All hot and cold STIX 2.1 bundles are cryptographically signed using **Sigstore Cosign**, ensuring immutable provenance and verifiable non-repudiation.
3. **A.8.28 Secure Coding:** Full compliance with deterministic UUIDv5 RFC 4122 namespacing and zero dynamic execution risks.

---

## 5. Sovereign Provenance, Warranties & Legal Safe Harbor
## 主權來源憑證、免責聲明與安全港條款

### 5.1 Mirroring Nature (OSINT Provenance) / 鏡像性質說明
Veritas is an automated, secondary technological relay mirror. All alerts originate from official gazettes and statutory bulletins published by sovereign entities (e.g., HKMA, SFC, HKPF, MAS, US CFTC, FBI IC3, UK FCA, DE BaFin, FR AMF).  
**Veritas does not generate, adjudicate, censor, or modify the factual determinations made by sovereign authorities.**

Veritas 僅為自動化技術鏡像中繼站，所有數據均忠實轉錄自各國主權監管機構之法定公報。Veritas 自身不做出任何事實認定、調查裁判或內容篡改。

### 5.2 "AS-IS" Warranty Disclaimer / 「現狀」無擔保免責
THE SOFTWARE AND INFORMATION ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, ACCURACY, AND NON-INFRINGEMENT.  
IN NO EVENT SHALL THE MAINTAINERS, CONTRIBUTORS, OR AFFILIATED ENTITIES BE LIABLE FOR ANY CLAIM, DAMAGES, LOSS OF DATA, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE USE OF THIS INFORMATION.

本專案之程式碼與威脅情報均按「原樣 (AS-IS)」提供，不提供任何明示或暗示之擔保（包括但不限於準確性、商用性或特定目的適用性）。在任何情況下，專案發起人與維護者均不承擔因使用或依賴此情報而產生之任何直接、間接、附隨或衍生性法律損害賠償責任。

### 5.3 Safe Harbor & Takendown Protocol / 安全港與異議下架機制
If any entity believes an Indicator of Compromise (IoC) or corporate entity has been recorded erroneously due to an upstream sovereign bulletin retraction or amendment:
1. Please inspect the upstream official gazette reference URL appended to the STIX Report SDO.
2. Submit an official cryptographic GitHub Issue with supporting statutory documentation.
3. Once confirmed with the relevant sovereign authority's official rectification, Veritas will apply an updated revocation status in the next scheduled pipeline epoch.

若任何實體認為情報因上游主權公報之撤回或更正而存在錯誤：
1. 請查閱該 STIX Report 附帶之官方原始公報連結；
2. 提交附帶官方主權證明之 GitHub Issue；
3. 一旦確認主管機關已撤回或修正，Veritas 將於下一次管線週期同步狀態。

---

*Authored and Ratified for Veritas Open-Source Project Integrity.*  
*由 Veritas 專案維護團隊制定並發布。*
