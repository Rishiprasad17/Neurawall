"""
debug_benchmark.py — Find exactly what is causing false positives
Run while neurawall is running.
Usage: python debug_benchmark.py
"""

import asyncio
import csv
import random
from urllib.parse import unquote_plus
import httpx

BASE_URL    = "http://127.0.0.1:8000"
DATASET     = r"C:\neurawall\csic_dataset\csic_database.csv"
RANDOM_SEED = 42


def extract_payload(url: str, content: str) -> str:
    parts = []
    clean_url = url.split(" HTTP")[0] if " HTTP" in url else url
    if "?" in clean_url:
        qs = clean_url.split("?", 1)[1]
        parts.append(unquote_plus(qs))
    if content and content.strip():
        parts.append(unquote_plus(content.strip().split(" HTTP")[0]))
    path = clean_url.split("?")[0].replace("http://localhost:8080", "")
    decoded_path = unquote_plus(path)
    if any(c in decoded_path for c in ["../", "..", "~"]):
        parts.append(decoded_path)
    return " | ".join(parts)[:500] if parts else unquote_plus(url[:300])


async def debug():
    print("Loading normal traffic samples...")
    normal = []
    with open(DATASET, encoding="latin-1") as f:
        reader = csv.reader(f)
        header = next(reader)
        url_idx     = header.index("URL")
        content_idx = header.index("content")
        for i, row in enumerate(reader):
            if len(row) <= url_idx: continue
            if row[0].strip().lower() != "normal": continue
            url     = row[url_idx].strip()
            content = row[content_idx].strip() if content_idx < len(row) else ""
            payload = extract_payload(url, content)
            normal.append({"id": i, "payload": payload, "url": url})

    random.seed(RANDOM_SEED)
    sample = random.sample(normal, 50)

    print(f"Testing 50 normal requests — printing any that get blocked...\n")

    blocked_count = 0
    async with httpx.AsyncClient() as client:
        for entry in sample:
            resp = await client.post(
                f"{BASE_URL}/data",
                json={"msg": entry["payload"]},
                timeout=10.0,
            )
            if resp.status_code == 403:
                blocked_count += 1
                reason = resp.json().get("reason", "unknown")
                print(f"BLOCKED [{entry['id']}]")
                print(f"  URL    : {entry['url'][:100]}")
                print(f"  Payload: {entry['payload'][:150]}")
                print(f"  Reason : {reason}")
                print()

    print(f"Result: {blocked_count}/50 normal requests blocked")
    print(f"FP rate: {blocked_count/50*100:.1f}%")


if __name__ == "__main__":
    asyncio.run(debug())
