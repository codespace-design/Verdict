import os
import serpapi
from dotenv import load_dotenv

load_dotenv()
client = serpapi.Client(api_key=os.getenv("SERPAPI_KEY"))

query = "CVE-2021-44228"

try:
    print("=== SEARCH ===")
    search_results = client.search({"engine": "google", "q": f"{query} advisory"})
    for r in search_results.get("organic_results", [])[:2]:
        print(r["title"], "-", r["link"])

    print("\n=== NEWS ===")
    news_results = client.search({"engine": "google_news", "q": f"{query} exploited"})
    for r in news_results.get("news_results", [])[:2]:
        print(r["title"], "-", r["link"])

    print("\n=== SCHOLAR ===")
    scholar_results = client.search({"engine": "google_scholar", "q": query})
    for r in scholar_results.get("organic_results", [])[:2]:
        print(r.get("title"), "-", r.get("link"))

except serpapi.HTTPError as e:
    if e.status_code == 401:
        print("Invalid API key:", e.error)
    elif e.status_code == 429:
        print("Rate limit hit or out of searches:", e.error)
    else:
        print(f"HTTP error ({e.status_code}):", e.error)
except serpapi.TimeoutError as e:
    print("Request timed out:", e)