"""
debug_what_blocks.py — Print exactly what normal requests Guardrail blocks and why
"""
import asyncio
import csv
import random
from urllib.parse import unquote_plus
import httpx

BASE_URL    = "http://127.0.0.1:8000"
DATASET     = r"C:\guardrail\csic_dataset\csic_database.csv"
RANDOM_SEED = 42


def extract_payload(url, content):
    parts = []
    clean_url = url.split(" HTTP")[0] if " HTTP" in url else url
    if "?" in clean_url:
        parts.append(unquote_plus(clean_url.split("?", 1)[1]))
    if content and content.strip():
        parts.append(unquote_plus(content.strip().split(" HTTP")[0]))
    return " | ".join(parts)[:500] if parts else unquote_plus(url[:300])


async def debug():
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
            normal.append({"id": i, "payload": extract_payload(url, content)})

    random.seed(RANDOM_SEED)
    sample = random.sample(normal, 500)

    print(f"Testing 500 normal requests...\n")
    blocked = []
    async with httpx.AsyncClient() as client:
        for entry in sample:
            resp = await client.post(
                f"{BASE_URL}/data",
                json={"msg": entry["payload"]},
                timeout=10.0,
            )
            if resp.status_code == 403:
                reason = resp.json().get("reason", "unknown")
                blocked.append({
                    "id": entry["id"],
                    "payload": entry["payload"],
                    "reason": reason
                })

    print(f"Blocked: {len(blocked)}/500\n")
    print("First 10 blocked normal requests:")
    for b in blocked[:10]:
        print(f"\n  [{b['id']}] Reason: {b['reason']}")
        print(f"  Payload: {b['payload'][:150]}")

    # Count by reason
    from collections import Counter
    reasons = Counter(b["reason"] for b in blocked)
    print(f"\nBreakdown by reason:")
    for reason, count in reasons.most_common():
        print(f"  {count:4d}x  {reason}")


if __name__ == "__main__":
    asyncio.run(debug())
