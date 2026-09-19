"""
fetch.py - Real-time Vulnerability Data Ingestion Engine for Verdict.

Queries Google Search (for vendor advisories and official disclosures) and
Google News (for active exploitation, PoCs, and real-world threat intelligence)
via SerpApi in parallel. Formats results into structured JSON or clean Markdown
for downstream LLM synthesis.
"""

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Union

import serpapi
from dotenv import load_dotenv

# Ensure Windows console handles UTF-8 gracefully
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Load environment variables from .env
load_dotenv()


class SerpApiFetchError(Exception):
    """Custom exception representing SerpApi ingestion failures."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def get_serpapi_client(api_key: Optional[str] = None) -> serpapi.Client:
    """Initialize and return a SerpApi client instance.
    
    Raises:
        SerpApiFetchError: If no API key is provided and SERPAPI_KEY is not in environment.
    """
    key = api_key or os.getenv("SERPAPI_KEY")
    if not key:
        raise SerpApiFetchError(
            "SERPAPI_KEY is not set. Please add it to your .env file or pass it directly.",
            status_code=401,
        )
    return serpapi.Client(api_key=key)


def _format_advisories_markdown(advisories: List[Dict[str, Any]]) -> str:
    """Format advisory search results into clean markdown."""
    if not advisories:
        return "*(No official vendor advisories or CVE records found)*\n"

    lines = []
    for idx, item in enumerate(advisories, 1):
        title = item.get("title", "Untitled Source")
        link = item.get("link", "#")
        snippet = item.get("snippet", "No description available.").strip()
        source = item.get("source") or item.get("displayed_link", "web")
        date = item.get("date", "")
        date_str = f" | {date}" if date else ""

        lines.append(f"{idx}. **[{title}]({link})** ({source}{date_str})")
        lines.append(f"   > {snippet}\n")
    return "\n".join(lines)


def _format_news_markdown(news_items: List[Dict[str, Any]]) -> str:
    """Format news search results into clean markdown."""
    if not news_items:
        return "*(No live news or active exploitation reports found)*\n"

    lines = []
    for idx, item in enumerate(news_items, 1):
        title = item.get("title", "Untitled Report")
        link = item.get("link", "#")
        snippet = item.get("snippet", "No summary available.").strip()
        source = item.get("source", "news")
        date = item.get("date", "")
        date_str = f" | {date}" if date else ""

        lines.append(f"{idx}. **[{title}]({link})** ({source}{date_str})")
        lines.append(f"   > {snippet}\n")
    return "\n".join(lines)


def fetch_advisories(
    query: str,
    num_results: int = 5,
    output: str = "md",
    client: Optional[serpapi.Client] = None,
) -> Union[str, List[Dict[str, Any]]]:
    """Fetch official vendor advisories, NVD entries, and CVE references via Google Search.

    Args:
        query: CVE identifier (e.g. 'CVE-2021-44228') or package vulnerability query.
        num_results: Maximum number of organic search results to return (default: 5).
        output: 'md' for formatted markdown, or 'json' for raw structured list.
        client: Optional pre-configured SerpApi Client instance.

    Returns:
        Formatted markdown string (if output='md') or list of result dicts (if output='json').

    Raises:
        SerpApiFetchError: If authentication fails, rate limits hit, or request times out.
    """
    if not query or not query.strip():
        raise ValueError("Query string cannot be empty.")

    serp_client = client or get_serpapi_client()
    search_query = f"{query.strip()} advisory OR nvd OR cve"

    try:
        response = serp_client.search({
            "engine": "google",
            "q": search_query,
            "num": num_results,
        })
    except serpapi.HTTPError as e:
        status = getattr(e, "status_code", None)
        if status == 401:
            raise SerpApiFetchError(f"Invalid SerpApi API key: {e.error}", status_code=401)
        elif status == 429:
            raise SerpApiFetchError(f"SerpApi rate limit exceeded or quota exhausted: {e.error}", status_code=429)
        raise SerpApiFetchError(f"SerpApi HTTP Error ({status}): {e.error}", status_code=status)
    except serpapi.TimeoutError as e:
        raise SerpApiFetchError(f"SerpApi request timed out while querying advisories: {e}", status_code=408)
    except Exception as e:
        raise SerpApiFetchError(f"Unexpected error during advisory search: {e}")

    raw_results = response.get("organic_results", [])[:num_results]
    parsed: List[Dict[str, Any]] = []

    for r in raw_results:
        parsed.append({
            "title": r.get("title", "").strip(),
            "link": r.get("link", "").strip(),
            "snippet": r.get("snippet", "").strip(),
            "source": r.get("displayed_link", ""),
            "date": r.get("date", ""),
        })

    if output == "md":
        return _format_advisories_markdown(parsed)
    return parsed


def fetch_news(
    query: str,
    num_results: int = 5,
    output: str = "md",
    client: Optional[serpapi.Client] = None,
) -> Union[str, List[Dict[str, Any]]]:
    """Fetch live exploitation reports, PoCs, and security news via Google News.

    Args:
        query: CVE identifier (e.g. 'CVE-2021-44228') or package vulnerability query.
        num_results: Maximum number of news results to return (default: 5).
        output: 'md' for formatted markdown, or 'json' for raw structured list.
        client: Optional pre-configured SerpApi Client instance.

    Returns:
        Formatted markdown string (if output='md') or list of result dicts (if output='json').

    Raises:
        SerpApiFetchError: If authentication fails, rate limits hit, or request times out.
    """
    if not query or not query.strip():
        raise ValueError("Query string cannot be empty.")

    serp_client = client or get_serpapi_client()
    news_query = f'{query.strip()} exploited OR "active exploitation" OR PoC'

    try:
        response = serp_client.search({
            "engine": "google_news",
            "q": news_query,
        })
    except serpapi.HTTPError as e:
        status = getattr(e, "status_code", None)
        if status == 401:
            raise SerpApiFetchError(f"Invalid SerpApi API key: {e.error}", status_code=401)
        elif status == 429:
            raise SerpApiFetchError(f"SerpApi rate limit exceeded or quota exhausted: {e.error}", status_code=429)
        raise SerpApiFetchError(f"SerpApi HTTP Error ({status}): {e.error}", status_code=status)
    except serpapi.TimeoutError as e:
        raise SerpApiFetchError(f"SerpApi request timed out while querying news: {e}", status_code=408)
    except Exception as e:
        raise SerpApiFetchError(f"Unexpected error during news search: {e}")

    raw_news = response.get("news_results", [])[:num_results]
    parsed: List[Dict[str, Any]] = []

    for r in raw_news:
        source_val = r.get("source", {})
        source_name = source_val.get("name", "") if isinstance(source_val, dict) else str(source_val)

        parsed.append({
            "title": r.get("title", "").strip(),
            "link": r.get("link", "").strip(),
            "snippet": r.get("snippet", "").strip(),
            "source": source_name,
            "date": r.get("date", ""),
        })

    if output == "md":
        return _format_news_markdown(parsed)
    return parsed


def fetch_vulnerability_data(
    query: str,
    num_advisories: int = 5,
    num_news: int = 5,
    output: str = "md",
    client: Optional[serpapi.Client] = None,
) -> Dict[str, Any]:
    """Fetch official advisories and live exploitation news concurrently.

    Runs Google Search and Google News in parallel worker threads, reducing total
    latency while gracefully collecting partial data if one source encounters an error.

    Args:
        query: CVE identifier or software vulnerability query.
        num_advisories: Max official advisory results (default: 5).
        num_news: Max live news / exploitation results (default: 5).
        output: 'md' (Markdown formatted) or 'json' (raw structured list).
        client: Optional pre-configured SerpApi Client.

    Returns:
        Dict containing:
            - 'query': original query string
            - 'advisories': formatted markdown or list of dicts
            - 'news': formatted markdown or list of dicts
            - 'markdown': combined Markdown ready for LLM context injection
            - 'errors': list of any error messages encountered
    """
    serp_client = client or get_serpapi_client()
    errors: List[str] = []

    raw_advisories: List[Dict[str, Any]] = []
    raw_news: List[Dict[str, Any]] = []

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_advisory = executor.submit(
            fetch_advisories,
            query=query,
            num_results=num_advisories,
            output="json",
            client=serp_client,
        )
        future_news = executor.submit(
            fetch_news,
            query=query,
            num_results=num_news,
            output="json",
            client=serp_client,
        )

        try:
            raw_advisories = future_advisory.result()
        except Exception as e:
            err_msg = f"Advisory fetch error: {str(e)}"
            errors.append(err_msg)

        try:
            raw_news = future_news.result()
        except Exception as e:
            err_msg = f"News fetch error: {str(e)}"
            errors.append(err_msg)

    elapsed = round(time.time() - start_time, 2)

    adv_md = _format_advisories_markdown(raw_advisories) if raw_advisories or not errors else f"*(Error fetching advisories)*\n"
    nws_md = _format_news_markdown(raw_news) if raw_news or not errors else f"*(Error fetching live news)*\n"

    combined_markdown = (
        f"## Research Ingestion Context: {query.strip()}\n"
        f"*Ingestion completed in {elapsed}s via SerpApi (Google Search & Google News)*\n\n"
        f"### 1. Official Vendor Advisories & Vulnerability Disclosures\n"
        f"{adv_md}\n"
        f"### 2. Live News & Real-World Exploitation Reports\n"
        f"{nws_md}\n"
    )

    advisories_res = adv_md if output == "md" else raw_advisories
    news_res = nws_md if output == "md" else raw_news

    return {
        "query": query,
        "elapsed_seconds": elapsed,
        "raw_advisories": raw_advisories,
        "raw_news": raw_news,
        "advisories": advisories_res,
        "news": news_res,
        "markdown": combined_markdown,
        "errors": errors,
    }


if __name__ == "__main__":
    target_cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"=== Verdict Data Ingestion: Querying '{target_cve}' ===")
    
    try:
        data = fetch_vulnerability_data(target_cve, output="md")
        print(f"Completed in {data['elapsed_seconds']}s\n")
        print(data["markdown"])
        if data["errors"]:
            print(f"Warnings/Errors: {data['errors']}")
    except SerpApiFetchError as e:
        print(f"\n[FATAL FETCH ERROR] Code {e.status_code}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[UNEXPECTED ERROR] {e}")
        sys.exit(1)
