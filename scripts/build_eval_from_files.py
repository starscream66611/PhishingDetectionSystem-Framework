from __future__ import annotations

import csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

PHISH_FILE = DATA_DIR / "openphish_feed.txt"
LEGIT_FILE = DATA_DIR / "tranco_top_1000.txt"
OUT_CSV = DATA_DIR / "dataset_eval.csv"

def read_lines(p: Path) -> list[str]:
    lines = []
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            lines.append(s)
    # dedupe
    return list(dict.fromkeys(lines))

def main():
    phishing = read_lines(PHISH_FILE)[:1000]
    legit_domains = read_lines(LEGIT_FILE)[:1000]
    legit_urls = [f"https://{d}/" for d in legit_domains]

    rows = [{"url": u, "label": "phishing"} for u in phishing]
    rows += [{"url": u, "label": "legitimate"} for u in legit_urls]

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "label"])
        w.writeheader()
        w.writerows(rows)

    print("saved:", OUT_CSV, "rows:", len(rows))

if __name__ == "__main__":
    main()