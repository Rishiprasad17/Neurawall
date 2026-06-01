import csv
import re
from urllib.parse import unquote_plus

path = r"C:\neurawall\csic_dataset\csic_database.csv"

ALL_PATTERNS = [
    (r"(DROP|TRUNCATE|ALTER)\s+TABLE\s+\w+",    "DROP TABLE"),
    (r"UNION\s+(ALL\s+)?SELECT\s+\w+",           "UNION SELECT"),
    (r";\s*(DROP|DELETE|INSERT|UPDATE)\s+",       "semicolon+cmd"),
    (r"waitfor\s+delay\s+",                       "waitfor delay"),
    (r"SLEEP\s*\(\s*\d+\s*\)",                   "SLEEP()"),
    (r"';\s*--",                                  "quote;--"),
    (r"'\s*OR\s+'\w+'\s*=\s*'\w+'",             "OR equals"),
    (r"1\s*=\s*1\s*--",                          "1=1--"),
    (r"'\s*DELETE\s+FROM\s+\w+",                 "DELETE FROM"),
    (r"';\s*(SELECT|INSERT|UPDATE|DROP)",         "quote;SELECT"),
    (r"<\s*script[\s>\/]",                        "script tag"),
    (r"javascript\s*:\s*\w",                      "javascript:"),
    (r"onerror\s*=",                              "onerror="),
    (r"\.\./\.\./",                               "../../"),
    (r"etc/passwd",                               "etc/passwd"),
    (r"windows/system32",                         "system32"),
    (r";\s*rm\s+-rf",                             "rm -rf"),
    (r"\|\s*(bash|sh|python)",                    "pipe shell"),
]

compiled = [(re.compile(p, re.IGNORECASE), name) for p, name in ALL_PATTERNS]

found = 0
with open(path, encoding="latin-1") as f:
    reader = csv.reader(f)
    header = next(reader)
    url_idx     = header.index("URL")
    content_idx = header.index("content")

    for i, row in enumerate(reader):
        if len(row) <= url_idx:
            continue
        if row[0].strip().lower() != "normal":
            continue

        url     = unquote_plus(row[url_idx].split(" HTTP")[0])
        qs      = url.split("?")[1] if "?" in url else ""
        content = unquote_plus(row[content_idx]) if content_idx < len(row) else ""
        combined = qs + " " + content

        for pat, name in compiled:
            if pat.search(combined):
                print(f"Pattern  : [{name}]")
                print(f"Payload  : {combined[:120]}")
                print()
                found += 1
                break

        if found >= 15:
            break

print(f"Total FP samples found: {found}")
