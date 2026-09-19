"""
main.py - Verdict API Server.
 
Exposes a single /analyze endpoint that ties fetch.py (SerpApi ingestion) and
synthesize.py (Gemini synthesis) together into one request/response cycle.
"""
import sys
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fetch import fetch_vulnerability_data, SerpApiFetchError
from synthesize import (
    synthesize_verdict,
    VerdictReport,
    get_gemini_client,
    check_evidence_sufficiency,
    make_insufficient_evidence_verdict,
)

# Ensure Windows console handles UTF-8 gracefully
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
 
app = FastAPI(
    title="Verdict API",
    description="AI agent that cross-verifies vulnerability risk using live SerpApi search data.",
    version="1.0.0",
)
 
# Allow a local/static frontend to call this API during dev and demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
 
# Initialize the Gemini client once at startup, not per-request
try:
    gemini_client = get_gemini_client()
except ValueError as e:
    # Server still starts so /health works, but /analyze will report the real error
    gemini_client = None
    print(f"[WARN] Gemini client not initialized: {e}", file=sys.stderr)
 
 
class AnalyzeRequest(BaseModel):
    query: str = Field(..., description="CVE ID (e.g. 'CVE-2021-44228') or package/technology name.")
 
 
class AnalyzeResponse(BaseModel):
    elapsed_seconds: float
    fetch_seconds: float
    synthesis_seconds: float
    report: VerdictReport
    fetch_warnings: list[str] = Field(default_factory=list)
 
 
@app.get("/health")
def health():
    """Simple liveness check, and confirms whether the Gemini client is ready."""
    return {
        "status": "ok",
        "gemini_ready": gemini_client is not None,
    }
 
 
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """Run the full Verdict pipeline: fetch live SerpApi data, then synthesize a report."""
    query = request.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
 
    if gemini_client is None:
        raise HTTPException(
            status_code=503,
            detail="Gemini client is not configured. Check GEMINI_API_KEY in your .env file.",
        )
 
    start = time.time()
 
    # Step 1: fetch live data from SerpApi (Search + News, in parallel)
    try:
        fetch_data = fetch_vulnerability_data(query, output="md")
    except SerpApiFetchError as e:
        raise HTTPException(
            status_code=e.status_code or 502,
            detail=f"SerpApi fetch failed: {e}",
        )
 
    fetch_elapsed = float(fetch_data.get("elapsed_seconds", round(time.time() - start, 2)))

    # Step 1.5: Deterministic pre-check — short-circuit if evidence is absent or placeholder
    is_sufficient, reason = check_evidence_sufficiency(query, fetch_data)
    if not is_sufficient:
        total_elapsed = round(time.time() - start, 2)
        warnings = fetch_data.get("errors", [])
        warnings.append(f"Deterministic short-circuit: {reason}")
        return AnalyzeResponse(
            elapsed_seconds=total_elapsed,
            fetch_seconds=fetch_elapsed,
            synthesis_seconds=0.0,
            report=make_insufficient_evidence_verdict(query, reason or "Insufficient evidence"),
            fetch_warnings=warnings,
        )

    # Step 2: synthesize the verdict from the fetched data
    synth_start = time.time()
    try:
        report = synthesize_verdict(query, fetch_data=fetch_data, client=gemini_client)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=f"Gemini synthesis failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected synthesis error: {e}")
 
    synthesis_elapsed = round(time.time() - synth_start, 2)
    total_elapsed = round(time.time() - start, 2)
 
    return AnalyzeResponse(
        elapsed_seconds=total_elapsed,
        fetch_seconds=fetch_elapsed,
        synthesis_seconds=synthesis_elapsed,
        report=report,
        fetch_warnings=fetch_data.get("errors", []),
    )
 
 
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)