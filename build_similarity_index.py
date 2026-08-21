from __future__ import annotations

import pickle
from collections import defaultdict
from pathlib import Path

from app.core.url_utils import clean_host, extract_registered_domain

DATA_DIR = Path(__file__).resolve().parent / "data"
REF_FILE = DATA_DIR / "reference_domains.txt"
OUT_FILE = DATA_DIR / "reference_index.pkl"

CHAR_SUBS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
})


def normalize_visual(text: str) -> str:
    return (text or "").lower().translate(CHAR_SUBS)


def core_domain_from_registered(host: str) -> str:
    reg = extract_registered_domain(host)
    parts = reg.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return reg


def trigrams(text: str) -> set[str]:
    s = f"__{text}__"
    if len(s) < 3:
        return {s}
    return {s[i:i+3] for i in range(len(s) - 2)}


def main():
    if not REF_FILE.exists():
        raise FileNotFoundError(f"Reference file tidak ditemukan: {REF_FILE}")

    raw_domains = []
    with open(REF_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                raw_domains.append(line)

    unique_regs = []
    seen = set()

    for d in raw_domains:
        h = clean_host(d)
        reg = extract_registered_domain(h)
        if reg and reg not in seen:
            seen.add(reg)
            unique_regs.append(reg)

    domains = []
    trigram_index: dict[str, list[int]] = defaultdict(list)

    for idx, reg in enumerate(unique_regs):
        core = core_domain_from_registered(reg)
        core_visual = normalize_visual(core)
        grams = sorted(trigrams(core_visual))

        domains.append({
            "domain": reg,
            "core": core,
            "core_visual": core_visual,
            "length": len(core_visual),
            "grams": grams,
        })

        for g in grams:
            trigram_index[g].append(idx)

    payload = {
        "domains": domains,
        "trigram_index": dict(trigram_index),
    }

    with open(OUT_FILE, "wb") as f:
        pickle.dump(payload, f)

    print(f"Total raw domains       : {len(raw_domains)}")
    print(f"Unique registered domain: {len(unique_regs)}")
    print(f"Index saved to          : {OUT_FILE}")


if __name__ == "__main__":
    main()