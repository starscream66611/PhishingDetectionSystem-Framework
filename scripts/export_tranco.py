from __future__ import annotations
from pathlib import Path
from tranco import Tranco

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
OUT = DATA_DIR / "tranco_top_1000.txt"

def main(n: int = 1000):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    t = Tranco(cache=True, cache_dir=str(DATA_DIR / ".tranco_cache"))
    latest = t.list()
    domains = latest.top(n)
    OUT.write_text("\n".join(domains) + "\n", encoding="utf-8")
    print("saved:", OUT)

if __name__ == "__main__":
    main(1000)