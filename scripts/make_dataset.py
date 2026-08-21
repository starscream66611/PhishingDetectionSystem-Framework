from __future__ import annotations

import csv
import random
from pathlib import Path

import requests
from tranco import Tranco

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
OUT_CSV = DATA_DIR / "dataset_eval.csv"

OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Feed tambahan (lebih banyak biasanya)
PHISHSTATS_FEED = "https://phishstats.info:2096/api/phishing?_sort=-date&_size=1000"
URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/text_recent/"  # malicious URLs (campur)

def _dedupe_keep_order(urls: list[str]) -> list[str]:
    return list(dict.fromkeys(urls))

def fetch_openphish() -> list[str]:
    r = requests.get(OPENPHISH_FEED, timeout=30, headers={"User-Agent": "PhishingDetector/1.0"})
    r.raise_for_status()
    urls = []
    for line in r.text.splitlines():
        u = line.strip()
        if u and not u.startswith("#"):
            urls.append(u)
    return _dedupe_keep_order(urls)

def fetch_phishstats() -> list[str]:
    # phishstats API returns JSON list
    r = requests.get(PHISHSTATS_FEED, timeout=30, headers={"User-Agent": "PhishingDetector/1.0"})
    r.raise_for_status()
    data = r.json()
    urls = []
    for item in data:
        u = (item.get("url") or "").strip()
        if u:
            urls.append(u)
    return _dedupe_keep_order(urls)

def fetch_urlhaus() -> list[str]:
    r = requests.get(URLHAUS_RECENT, timeout=30, headers={"User-Agent": "PhishingDetector/1.0"})
    r.raise_for_status()
    urls = []
    for line in r.text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # format biasanya: URL
        urls.append(s)
    return _dedupe_keep_order(urls)

def fetch_tranco(limit: int = 1000) -> list[str]:
    t = Tranco(cache=True, cache_dir=str(DATA_DIR / ".tranco_cache"))
    latest = t.list()
    domains = latest.top(limit)
    urls = []
    for d in domains:
        d = (d or "").strip().lower()
        if d:
            urls.append(f"https://{d}/")
    return urls

def main(phish_n: int = 1000, legit_n: int = 1000, seed: int = 42) -> None:
    random.seed(seed)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    phishing_all: list[str] = []
    print("[fetch] openphish...")
    phishing_all += fetch_openphish()
    print("[fetch] phishstats...")
    try:
        phishing_all += fetch_phishstats()
    except Exception as e:
        print(f"[warn] phishstats failed: {e}")
    print("[fetch] urlhaus...")
    try:
        phishing_all += fetch_urlhaus()
    except Exception as e:
        print(f"[warn] urlhaus failed: {e}")

    phishing_all = _dedupe_keep_order(phishing_all)

    if len(phishing_all) < phish_n:
        print(f"[warn] total phishing cuma {len(phishing_all)} (kurang dari target {phish_n})")

    phishing = phishing_all[:phish_n]
    legit = fetch_tranco(legit_n)

    rows = [{"url": u, "label": "phishing"} for u in phishing] + [
        {"url": u, "label": "legitimate"} for u in legit
    ]
    random.shuffle(rows)

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "label"])
        w.writeheader()
        w.writerows(rows)

    print(f"[ok] phishing: {len(phishing)} (pool={len(phishing_all)})")
    print(f"[ok] legitimate: {len(legit)}")
    print(f"[ok] total rows: {len(rows)}")
    print(f"[ok] saved to: {OUT_CSV}")

if __name__ == "__main__":
    main(phish_n=1000, legit_n=1000)