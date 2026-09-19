#  Verdict

> **Autonomous Cross-Source Vulnerability Intelligence & Discrepancy Detection Agent**  
> *Track: AI Agents · Built for SerpApi India Hackathon 2026*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![SerpApi](https://img.shields.io/badge/Ingestion-SerpApi-orange.svg?style=flat-square)](https://serpapi.com)
[![Google Gemini](https://img.shields.io/badge/Synthesis-Gemini_Flash-4285F4.svg?style=flat-square&logo=google)](https://ai.google.dev)
[![Pydantic](https://img.shields.io/badge/Validation-Pydantic_v2-E92063.svg?style=flat-square&logo=pydantic)](https://docs.pydantic.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

---

##  Overview

When a new critical vulnerability breaks, security and incident response teams face a recurring dilemma:
- **Static database lag:** CVSS scores remain frozen for months; NVD backlogs delay real-world risk metrics.
- **Vendor downplaying:** Official security bulletins often classify issues as *"Important"* or claim a patch is *"Complete"* (e.g., Log4j 2.15.0 or Tomcat 2026 `CVE-2026-34486`).
- **Threat intelligence disconnect:** Live threat feeds, CISA KEV alerts, and independent researchers uncover active in-the-wild exploitation and patch bypasses within hours of release.

**Verdict** is an autonomous security intelligence agent that bridges this gap. It queries **Google Search** (for authoritative vendor bulletins and NVD disclosures) and **Google News** (for live weaponization, exploit PoCs, and threat intelligence) concurrently via **SerpApi**. It then applies structured **Gemini AI synthesis** to evaluate whether vendor disclosures align with reality or exhibit a **dangerous discrepancy**, delivering an immediate, defensible intelligence dossier with verbatim citations.

---

## System Architecture

```
                                      ┌──────────────────────────────────────────────┐
                                      │        User Query (CVE-ID or Software)       │
                                      └──────────────────────┬───────────────────────┘
                                                             │
                                                             ▼
                                      ┌──────────────────────────────────────────────┐
                                      │   Deterministic Pre-Check Gate (< 0.4s)      │
                                      │   (Detects unindexed/fake CVEs; 0 token cost)│
                                      └──────────────────────┬───────────────────────┘
                                                             │ Real / Indexed
                                                             ▼
                                      ┌──────────────────────────────────────────────┐
                                      │  Parallel Ingestion Engine (ThreadPool)     │
                                      │                 [SerpApi]                    │
                                      └──────────────┬────────────────┬──────────────┘
                                                     │                │
                          ┌──────────────────────────┴────┐      ┌────┴──────────────────────────┐
                          │   Google Search (Engine)      │      │     Google News (Engine)      │
                          │   Official Vendor Advisories  │      │  Active Exploitation, PoCs,   │
                          │   & Security Bulletins        │      │  CISA KEV, Threat Intel       │
                          └──────────────────────────┬────┘      └────┬──────────────────────────┘
                                                     │                │
                                                     └────────┬───────┘
                                                              ▼
                                      ┌──────────────────────────────────────────────┐
                                      │    Schema-Enforced Gemini Synthesis Engine   │
                                      │   (Temperature=0.0 · Strict Citation Guard)  │
                                      └──────────────────────┬───────────────────────┘
                                                             │
                                                             ▼
                                      ┌──────────────────────────────────────────────┐
                                      │        Contradiction Analysis Logic          │
                                      │    (True Bypass vs. Complementary Omission)  │
                                      └──────────────────────┬───────────────────────┘
                                                             │
                                                             ▼
                                      ┌──────────────────────────────────────────────┐
                                      │       Editorial Dossier UI & REST API        │
                                      │     Severity Stamp · CVSS · Citations        │
                                      └──────────────────────────────────────────────┘
```

---

## Key Capabilities

-  **Concurrent Dual-Channel Retrieval:** Dispatches parallel HTTP workers to fetch authoritative vendor documentation and active threat news in a single pass via SerpApi.
- **True Discrepancy Detection:** Differentiates between *true contradictions* (e.g., vendor claims an issue is remediated while researchers bypass it) versus *complementary disclosures* (vendor details the bug, news confirms exploitation).
- **Zero-Hallucination Citation Anchor:** Every external claim in the final dossier must map directly to a verified URL and verbatim snippet from the retrieved evidence.
- **Deterministic Pre-Check Guard:** Synthetic or non-existent identifiers (e.g., `CVE-2099-99999`) short-circuit deterministically in ~0.35s without making costly LLM API calls.
- **25-Case Incident Dossier Catalog:** Integrated searchable directory of curated benchmarks spanning 2026 zero-days, classic supply chain backdoors, AI framework flaws, and controls.
- **1-Click Markdown Dossier Export:** Generate and copy clean, formatted Markdown briefings directly to the clipboard for security teams.

---

## Interactive Incident Dossier Catalog

<details>
<summary><strong>🔍 Click to expand the 25 curated benchmark cases included in Verdict</strong></summary>

| CVE Identifier | Software Component | Classification Tag | Evaluation Benchmark Rationale |
|:---|:---|:---|:---|
| **CVE-2021-44228** | Apache Log4j 2 ("Log4Shell") | `Patch Discrepancy` | Vendor fix 2.15.0 was incomplete and bypassed, requiring 2.16.0+. |
| **CVE-2026-34486** | Apache Tomcat EncryptInterceptor | `Regression Discrepancy` | Fresh August 2026 flaw bypassing prior CVE-2026-29146 fix; active KEV alerts. |
| **CVE-2026-9198** | IBM Langflow Agentic AI Platform | `AI Framework Flaw` | Superuser token minting via `/api/v1/auto_login`; vendor & news aligned. |
| **CVE-2026-28318** | SolarWinds Serv-U File Server | `Aligned Control` | Unauthenticated single-request DoS crash; disclosures align without contradiction. |
| **CVE-2024-3094** | XZ Utils / liblzma | `Supply Chain Backdoor` | Multi-year sleeper backdoor targeting OpenSSH server authentication. |
| **CVE-2024-6387** | OpenSSH Server ("regreSSHion") | `Signal Race RCE` | Signal race condition in default sshd granting remote root on glibc Linux. |
| **CVE-2023-34362** | Progress MOVEit Transfer | `Ransomware 0-Day` | Pre-auth SQL injection weaponized by CL0P ransomware in global extortion. |
| **CVE-2023-4863** | Google Chrome & libwebp | `In-The-Wild 0-Day` | Lossless WebP buffer overflow abused in commercial spyware campaigns. |
| **CVE-2024-21413** | Microsoft Outlook ("MonikerLink") | `Protocol Bypass` | Protected View bypass leaking local NTLM credentials over SMB upon preview. |
| **CVE-2023-27997** | Fortinet FortiOS ("XORtigate") | `SSL-VPN Pre-Auth RCE` | Critical heap overflow in FortiGate SSL-VPN exploited before patches. |
| **CVE-2024-21887** | Ivanti Connect Secure | `Gateway RCE` | Command injection chained with auth bypass (CVE-2023-46805) by state actors. |
| **CVE-2022-22965** | Spring Framework ("Spring4Shell") | `Framework RCE` | Class loader manipulation via HTTP parameter binding on Apache Tomcat. |
| **CVE-2024-1709** | ConnectWise ScreenConnect | `Pre-Auth Admin Bypass` | Path traversal in `/SetupWizard.aspx` creating unauthorized root admin accounts. |
| **CVE-2023-38831** | WinRAR ZIP Processing | `Zero-Day Exploited` | Shell execution triggered by opening weaponized ZIP archives disguised as PDFs. |
| **CVE-2023-20198** | Cisco IOS XE Web UI | `Zero-Day Implant` | In-the-wild zero-day deploying malicious Lua configuration implants. |
| **CVE-2023-23397** | Microsoft Outlook | `Zero-Click Exploit` | Reminder sound file path triggering outbound SMB credential exfiltration. |
| **CVE-2021-34527** | Windows Print Spooler ("PrintNightmare")| `Patch Discrepancy` | Out-of-band security patch failed to remediate the flaw; immediate bypasses. |
| **CVE-2021-26855** | Microsoft Exchange ("ProxyLogon") | `Exchange SSRF RCE` | Pre-auth SSRF chained by HAFNIUM actors to breach thousands of servers. |
| **CVE-2022-30190** | Windows Support Tool ("Follina") | `Zero-Click Office RCE` | MSDT protocol handler RCE executing PowerShell even with macros disabled. |
| **CVE-2023-4911** | GNU C Library ("Looney Tunables") | `Local Root Escalation`| Buffer overflow in `GLIBC_TUNABLES` granting instant root on default Linux. |
| **CVE-2024-38077** | Windows Remote Desktop Licensing | `Unauthenticated RCE` | Critical zero-click unauthenticated heap overflow on Windows Server RDL. |
| **CVE-2017-0144** | Microsoft Windows SMBv1 ("EternalBlue")| `Nation-State RCE` | Leaked NSA cyber weapon powering the WannaCry and NotPetya pandemics. |
| **CVE-2014-0160** | OpenSSL TLS ("Heartbleed") | `Memory Disclosure` | Memory disclosure leaking private server encryption keys and session tokens. |
| **CVE-2019-19781** | Citrix ADC & Gateway ("Shitrix") | `Path Traversal RCE` | Directory traversal allowing arbitrary perl execution under `nobody` user. |
| **CVE-2099-99999** | Synthetic Non-Existent Identifier | `Pre-Check Control` | Adversarial test verifying ~0.35s short-circuit, zero citations, and zero token burn. |

</details>

---

## Quickstart Guide

### 1. Clone the Repository

```bash
git clone https://github.com/codespace-design/Verdict.git
cd Verdict
```

### 2. Set Up Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Secrets

Copy the `.env.example` template to create your `.env` file:

```bash
cp .env.example .env
```

Open `.env` and insert your API keys:

```env
# SerpApi Key (https://serpapi.com/manage-api-key)
SERPAPI_KEY=your_serpapi_key_here

# Google Gemini API Key (https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=your_gemini_api_key_here
```

> **Where to get free keys:**
> - **SerpApi:** Free tier provides 100 searches/month at [serpapi.com](https://serpapi.com).
> - **Google Gemini:** Free tier available at [Google AI Studio](https://aistudio.google.com).

### 5. Launch the Application

```bash
python main.py
```

The server will start on **`http://localhost:8000`**.

Open your browser to:
- **Web Interface:** [http://localhost:8000](http://localhost:8000)
- **Swagger API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check:** [http://localhost:8000/health](http://localhost:8000/health)

---

## 🔌 API Reference

### `POST /analyze`
Performs live dual ingestion and synthesis on a vulnerability query.

**Request Payload:**
```json
{
  "query": "CVE-2026-34486"
}
```

<details>
<summary><strong>📥 Click to view sample JSON response</strong></summary>

```json
{
  "query": "CVE-2026-34486",
  "elapsed_seconds": 3.82,
  "fetch_seconds": 1.45,
  "synthesis_seconds": 2.37,
  "report": {
    "cve_id": "CVE-2026-34486",
    "vulnerability_name": "Apache Tomcat EncryptInterceptor Session Exposure",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "exploitation_status": "ACTIVELY_EXPLOITED",
    "has_source_disagreement": true,
    "disagreement_details": "Apache Software Foundation classified the flaw as an Important update resolving a session leak, whereas CISA KEV and threat researchers reported immediate bypass of the prior CVE-2026-29146 patch with weaponized proof-of-concept exploits in the wild.",
    "executive_summary": "CVE-2026-34486 represents an incomplete fix for earlier interceptor issues in Apache Tomcat, resulting in active session hijacking attacks across exposed clusters.",
    "vendor_posture": "The vendor advisory advises upgrading to Tomcat 10.1.34 / 11.0.2 to address EncryptInterceptor bypasses.",
    "threat_intelligence": "CISA added CVE-2026-34486 to the Known Exploited Vulnerabilities catalog following active exploitation and public exploit availability.",
    "recommended_action": "Apply official vendor upgrade to 10.1.34/11.0.2 immediately. Restrict administrative cluster ports to private subnets.",
    "citations": [
      {
        "title": "Apache Tomcat Security Advisory - August 2026",
        "url": "https://tomcat.apache.org/security-10.html",
        "snippet_evidence": "A regression in EncryptInterceptor allowed remote session tampering."
      }
    ]
  },
  "fetch_warnings": []
}
```
</details>

---

### `GET /health`
Returns system operational status and Gemini AI readiness.

**Response:**
```json
{
  "status": "ok",
  "gemini_ready": true
}
```

---

## Testing & Validation

Verdict includes automated test suites covering fetch resilience, synthesis schema conformance, and deterministic short-circuit logic:

```bash
# Run the complete test suite
pytest test/ -v

# Or run individual verification scripts
python test/test_consistency.py
python test/test_fetch.py
```

---

## Design Philosophy

Verdict avoids generic AI dashboard clichés in favor of a bespoke **Editorial Dossier System**:
- **Palette:** Warm paper (`#EAE7DE`), deep ink (`#211E1A`), soft ink (`#5A554C`), hairline borders (`#C9C2AF`), oxblood (`#7A2E2E`), moss green (`#3F5A42`), and amber (`#96650F`).
- **Typography:** Display serif (`Fraunces`) for editorial authority, modern sans (`Source Sans 3`) for dense readability, and technical mono (`IBM Plex Mono`) for telemetry data and CVE IDs.
- **Visuals:** Crisp monochrome vector SVGs — zero cartoon emojis or generic SaaS shadows.


