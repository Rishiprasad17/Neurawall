"""
debug_labels.py — Check what the benchmark is actually labelling
"""
import csv
import random
from urllib.parse import unquote_plus

DATASET     = r"C:\neurawall\csic_dataset\csic_database.csv"
RANDOM_SEED = 42
SAMPLE_SIZE = 500

ATTACK_KEYWORDS = [
    "'", "DROP", "SELECT", "UNION", "INSERT", "DELETE",
    "<script", "<SCR", "alert(", "onerror", "javascript:",
    "../", "..\\", "etc/passwd", "system32",
    "; rm", "| cat", "whoami", "exec(", "eval(",
    "OR 1=1", "' OR", "1=1",
]

def is_real_attack(text):
    t = text.lower()
    return any(k.lower() in t for k in ATTACK_KEYWORDS)

def extract_payload(url, content):
    parts = []
    clean_url = url.split(" HTTP")[0] if " HTTP" in url else url
    if "?" in clean_url:
        parts.append(unquote_plus(clean_url.split("?", 1)[1]))
    if content and content.strip():
        parts.append(unquote_plus(content.strip().split(" HTTP")[0]))
    return " | ".join(parts)[:500] if parts else unquote_plus(url[:300])

normal, attacks = [], []
with open(DATASET, encoding="latin-1") as f:
    reader = csv.reader(f)
    header = next(reader)
    url_idx     = header.index("URL")
    content_idx = header.index("content")
    method_idx  = header.index("Method")
    for i, row in enumerate(reader):
        if len(row) <= url_idx: continue
        cls     = row[0].strip()
        url     = row[url_idx].strip()
        content = row[content_idx].strip() if content_idx < len(row) else ""
        payload = extract_payload(url, content)
        is_normal = cls.lower() == "normal"
        entry = {"id": i, "cls": cls, "payload": payload,
                 "is_attack": not is_normal}
        if is_normal:
            normal.append(entry)
        elif is_real_attack(payload):
            attacks.append(entry)

random.seed(RANDOM_SEED)
sample_normal  = random.sample(normal,  min(SAMPLE_SIZE, len(normal)))
sample_attacks = random.sample(attacks, min(SAMPLE_SIZE, len(attacks)))
all_samples    = sample_normal + sample_attacks
random.shuffle(all_samples)

# Check what is labelled as normal but contains attack keywords
print(f"Sample size: {len(all_samples)}")
print(f"Labelled normal : {sum(1 for x in all_samples if not x['is_attack'])}")
print(f"Labelled attack : {sum(1 for x in all_samples if x['is_attack'])}")
print()

# Show first 10 "normal" samples with their payloads
print("=== First 10 NORMAL samples ===")
normals = [x for x in all_samples if not x["is_attack"]][:10]
for n in normals:
    print(f"[{n['id']}] cls={n['cls']} | {n['payload'][:100]}")

print()
print("=== First 10 ATTACK samples ===")
att = [x for x in all_samples if x["is_attack"]][:10]
for a in att:
    print(f"[{a['id']}] cls={a['cls']} | {a['payload'][:100]}")

# Check if any "normal" samples contain attack keywords
print()
print("=== Normal samples that contain attack keywords ===")
found = 0
for n in [x for x in all_samples if not x["is_attack"]]:
    if is_real_attack(n["payload"]):
        print(f"  [{n['id']}] {n['payload'][:100]}")
        found += 1
    if found >= 10:
        break
print(f"Total: {found}")
