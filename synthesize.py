"""
synthesize.py - AI Vulnerability Synthesis & Disagreement Detection Engine for Verdict.

Leverages Google Gemini with native structured outputs (Pydantic schema) to compare
official vendor advisories against live real-world exploitation news ingested via SerpApi.
Explicitly identifies, flags, and details source contradictions.
"""

import json
import os
import sys
import time
from enum import Enum
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from fetch import fetch_vulnerability_data, SerpApiFetchError

# Ensure Windows console handles UTF-8 gracefully
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Load environment variables
load_dotenv()

# Candidate models in order of priority (handles temporary 503 demand spikes)
FALLBACK_MODELS = [
    "gemini-flash-lite-latest",
    "gemini-flash-latest",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash-lite",
]


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ExploitationStatus(str, Enum):
    ACTIVELY_EXPLOITED = "ACTIVELY_EXPLOITED"
    POC_PUBLIC = "POC_PUBLIC"
    SUSPECTED = "SUSPECTED"
    NO_EVIDENCE_OF_EXPLOITATION = "NO_EVIDENCE_OF_EXPLOITATION"


class CitationSourceType(str, Enum):
    OFFICIAL_ADVISORY = "OFFICIAL_ADVISORY"
    NEWS_THREAT_INTEL = "NEWS_THREAT_INTEL"
    EXPLOIT_POC = "EXPLOIT_POC"
    OTHER = "OTHER"


class Citation(BaseModel):
    title: str = Field(..., description="Title of the advisory, article, or intelligence report.")
    url: str = Field(..., description="Exact URL to the cited source extracted from research context.")
    source_type: CitationSourceType = Field(..., description="Category of the source.")
    snippet_evidence: str = Field(..., description="Key excerpt or evidence confirming this finding.")


class VerdictReport(BaseModel):
    cve_id: str = Field(..., description="Standard CVE identifier (e.g. CVE-2021-44228) or target package.")
    vulnerability_name: str = Field(..., description="Common or descriptive name (e.g. Log4Shell, MOVEit SQLi).")
    severity: SeverityLevel = Field(..., description="Synthesized real-world severity assessment.")
    cvss_score: Optional[float] = Field(None, description="Official or estimated CVSS base score (0.0 to 10.0).")
    exploitation_status: ExploitationStatus = Field(..., description="Current real-world exploitation posture.")
    has_source_disagreement: bool = Field(
        ...,
        description=(
            "True if official vendor disclosures and live news/threat intelligence contradict each other "
            "regarding severity, active exploitation status, or patch completeness. False if consistent."
        ),
    )
    disagreement_details: Optional[str] = Field(
        None,
        description=(
            "If has_source_disagreement is True, an explicit explanation of who says what (e.g., vendor claimed "
            "unexploited, but threat intel reports active weaponization or CISA KEV listing)."
        ),
    )
    executive_summary: str = Field(
        ...,
        description="High-density, plain-language summary for software engineers explaining root cause and real attack vectors.",
    )
    vendor_posture: str = Field(
        ...,
        description="Summary of official vendor claims, patch availability, and official severity.",
    )
    threat_intelligence: str = Field(
        ...,
        description="Summary of live threat intelligence, observed attacker behaviors, ransomware groups, and in-the-wild telemetry.",
    )
    recommended_action: str = Field(
        ...,
        description="Direct, prioritized remediation steps for developers and sysadmins (patch versions, config changes, workarounds).",
    )
    citations: List[Citation] = Field(
        ...,
        description="Citations referencing real URLs and sources from the ingested search data.",
    )

    def to_markdown(self) -> str:
        """Render the Verdict report as a polished, human-readable Markdown document."""
        badge_disagreement = ""
        if self.has_source_disagreement:
            badge_disagreement = (
                "\n> [!WARNING]\n"
                "> **SOURCE DISAGREEMENT DETECTED**\n"
                f"> {self.disagreement_details}\n"
            )

        cvss_str = f" (CVSS: {self.cvss_score})" if self.cvss_score is not None else ""

        lines = [
            f"# Verdict Report: {self.cve_id} — {self.vulnerability_name}",
            f"**Severity**: `{self.severity.value}`{cvss_str} | **Exploitation Status**: `{self.exploitation_status.value}`",
            badge_disagreement,
            "## Executive Summary",
            self.executive_summary,
            "",
            "## Official Vendor Posture",
            self.vendor_posture,
            "",
            "## Live Threat Intelligence & Real-World Activity",
            self.threat_intelligence,
            "",
            "## Recommended Developer Action",
            self.recommended_action,
            "",
            "## Verified Citations",
        ]

        for idx, cite in enumerate(self.citations, 1):
            lines.append(
                f"{idx}. **[{cite.title}]({cite.url})** `[{cite.source_type.value}]`\n"
                f"   *Evidence*: {cite.snippet_evidence}"
            )

        return "\n".join(lines)


SYSTEM_INSTRUCTION = """
You are Verdict, an elite AI security research assistant built for the SerpApi Hackathon.
Your mission is to synthesize two distinct information streams for a given software vulnerability:
1. Official vendor advisories and CVE database records (NVD, vendor security bulletins).
2. Live news reports, threat intelligence blogs, and proof-of-concept exploits from real-world telemetry.

CRITICAL DIRECTIVE — SOURCE DISAGREEMENT DETECTION:
You must explicitly compare what the vendor states versus what live threat intelligence reveals.
Look for:
- Exploitation Contradiction: Vendor explicitly claims 'no known exploitation' or 'theoretical vulnerability', but threat researchers or CISA confirm active in-the-wild weaponization.
- Severity / Scope Contradiction: Vendor downplayed severity (e.g. Medium), but real-world attacks achieved unauthenticated Remote Code Execution.
- Patch Incompleteness / Bypass: Vendor claimed an initial patch fixed the issue, but subsequent news reports bypasses or incomplete remediation (e.g., Log4j 2.15.0 was incomplete and required 2.16.0+). If an initial patch was incomplete or bypassed, you MUST flag `has_source_disagreement: True`.

IMPORTANT DISTINCTION — OMISSION IS NOT DISAGREEMENT:
Only set `has_source_disagreement = True` for genuine contradiction — where an official or vendor claim is refuted, bypassed, or contradicted by another source.
Do NOT set it True merely because the vendor advisory omits information (such as not commenting on exploitation status) that the news separately provides. Omission is not disagreement. If the vendor does not claim the flaw is unexploited or low risk, news reporting active exploitation is complementary context, NOT a contradiction. If sources are consistent or complementary without contradiction, set `has_source_disagreement: False` and `disagreement_details: null`.

CONSISTENCY CHECK:
Before finalizing recommended_action, cross-check it against vendor_posture and
disagreement_details. If any source indicates an earlier patch version was incomplete
or later superseded, recommended_action MUST reference the latest fully-effective
version — never an earlier version already known to be insufficient.

CITATION INTEGRITY & NON-EXISTENT VULNERABILITIES:
- Extract citations directly from the provided search & news context.
- Use the exact URLs and titles provided. Never invent or hallucinate URLs.
- Pair each citation with a concise snippet of evidence supporting your verdict.
- If the target CVE/vulnerability does not exist, or if the search results contain only placeholder links (e.g. empty cve.org records or unrelated CVEs matched by fuzzy search), you MUST return an empty citations list (`[]`). Do NOT cite placeholder records or irrelevant fuzzy matches for non-existent queries.
"""


def get_gemini_client(api_key: Optional[str] = None) -> genai.Client:
    """Initialize Google Gemini client."""
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        raise ValueError(
            "GEMINI_API_KEY is not set. Please add it to your .env file or obtain one free at aistudio.google.com."
        )
    return genai.Client(api_key=key)


def check_evidence_sufficiency(query: str, fetch_data: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """Determine whether ingested research contains substantive vulnerability data or only empty placeholders."""
    raw_adv = fetch_data.get("raw_advisories", [])
    raw_news = fetch_data.get("raw_news", [])

    # If completely empty across both Search and News
    if not raw_adv and not raw_news:
        return False, f"No advisories or news articles were found matching '{query}'."

    clean_q = query.strip().upper()
    if clean_q.startswith("CVE-"):
        has_news = len(raw_news) > 0
        has_substantive_advisory = False

        for item in raw_adv:
            title = item.get("title", "").upper()
            snippet = item.get("snippet", "").strip()

            # Skip generic auto-generated empty cve.org meta descriptions
            if snippet.lower() == f"vulnerability detail for {clean_q.lower()}." or not snippet:
                continue

            # Check if this advisory actually pertains to the queried CVE
            if clean_q in title or clean_q in snippet.upper():
                has_substantive_advisory = True
                break

        if not has_news and not has_substantive_advisory:
            return False, f"Identifier '{query}' does not correspond to any published vulnerability or active exploitation reports (only unpopulated placeholders or fuzzy matches detected)."

    return True, None


def make_insufficient_evidence_verdict(query: str, reason: str) -> VerdictReport:
    """Construct a deterministic VerdictReport without invoking the LLM when evidence is absent."""
    return VerdictReport(
        cve_id=query.strip(),
        vulnerability_name="Unverified / Non-existent Vulnerability",
        severity=SeverityLevel.UNKNOWN,
        cvss_score=None,
        exploitation_status=ExploitationStatus.NO_EVIDENCE_OF_EXPLOITATION,
        has_source_disagreement=False,
        disagreement_details=None,
        executive_summary=(
            f"Automated ingestion found no published advisories or real-world exploitation telemetry for '{query.strip()}'. "
            f"The identifier appears non-existent, unindexed, or misidentified."
        ),
        vendor_posture="No official vendor advisory, security bulletin, or valid CVE record could be verified.",
        threat_intelligence="No live news, threat intelligence, or proof-of-concept exploits detected.",
        recommended_action="Verify the CVE ID or package name. No remediation action required.",
        citations=[],
    )


def synthesize_verdict(
    query: str,
    fetch_data: Optional[Dict[str, Any]] = None,
    client: Optional[genai.Client] = None,
    preferred_model: Optional[str] = None,
) -> VerdictReport:
    """Synthesize vulnerability research into an authoritative VerdictReport using Google Gemini.

    Args:
        query: CVE identifier (e.g. 'CVE-2021-44228') or package name.
        fetch_data: Optional pre-fetched dictionary from fetch_vulnerability_data(). If None,
                    fetch_vulnerability_data() will be called automatically.
        client: Optional pre-configured genai.Client.
        preferred_model: Optional model name override.

    Returns:
        VerdictReport: Strongly-typed Pydantic model with structured risk assessment.

    Raises:
        ValueError: If query is empty or GEMINI_API_KEY is missing.
        RuntimeError: If Gemini API calls fail across all candidate models.
    """
    if not query or not query.strip():
        raise ValueError("Query string cannot be empty.")

    # Ingest research context if not provided
    if fetch_data is None:
        fetch_data = fetch_vulnerability_data(query, output="md")

    # Deterministic short-circuit: skip LLM entirely if evidence is absent or placeholder
    is_sufficient, reason = check_evidence_sufficiency(query, fetch_data)
    if not is_sufficient:
        return make_insufficient_evidence_verdict(query, reason or "Insufficient evidence")

    gemini_client = client or get_gemini_client()
    research_context = fetch_data.get("markdown", "")

    prompt = (
        f"Synthesize the following live research data for target vulnerability '{query.strip()}':\n\n"
        f"{research_context}\n\n"
        f"Perform an exhaustive comparative analysis between the official vendor disclosures and live news. "
        f"Identify if source disagreement exists, determine true real-world severity and exploitation status, "
        f"and output a complete VerdictReport according to the schema."
    )

    models_to_try = [preferred_model] if preferred_model else FALLBACK_MODELS
    last_error: Optional[Exception] = None

    for model_name in models_to_try:
        try:
            response = gemini_client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    response_mime_type="application/json",
                    response_schema=VerdictReport,
                    temperature=0.0,
                ),
            )

            # Parse JSON into validated Pydantic model
            raw_text = response.text
            data_dict = json.loads(raw_text)
            return VerdictReport(**data_dict)

        except Exception as e:
            last_error = e
            print(f"[WARN] {model_name} failed: {e}", file=sys.stderr)
            # If 503 or model error, retry with the next fallback model
            continue

    raise RuntimeError(
        f"Failed to synthesize verdict across all candidate models ({models_to_try}). Last error: {last_error}"
    )


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"=== Verdict AI Synthesis Engine: Analyzing '{target}' ===")

    start = time.time()
    try:
        report = synthesize_verdict(target)
        elapsed = round(time.time() - start, 2)
        print(f"\n[Synthesis complete in {elapsed}s]\n")
        print(report.to_markdown())
    except Exception as e:
        print(f"\n[SYNTHESIS ERROR] {e}")
        sys.exit(1)
