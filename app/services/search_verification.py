from __future__ import annotations

from pathlib import Path
import tldextract


DATA_DIR = Path(__file__).resolve().parents[2] / "data"
REFERENCE_DOMAINS_PATH = DATA_DIR / "reference_domains.txt"


BUILTIN_REFERENCE_DOMAINS = [
    "google.com",
    "facebook.com",
    "instagram.com",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "paypal.me",
    "amazon.com",
    "netflix.com",
    "telegram.org",
    "whatsapp.com",
    "binance.com",
    "coinbase.com",
    "bca.co.id",
    "bri.co.id",
    "bni.co.id",
    "bankmandiri.co.id",
    "ovo.id",
    "dana.id",
    "shopee.co.id",
    "tokopedia.com",
    "binus.ac.id",
    "okx.com",
]


BRAND_TO_OFFICIAL_DOMAINS = {
    "google": ["google.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "telegram": ["telegram.org"],
    "whatsapp": ["whatsapp.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "bca": ["bca.co.id"],
    "bri": ["bri.co.id"],
    "bni": ["bni.co.id"],
    "mandiri": ["bankmandiri.co.id"],
    "ovo": ["ovo.id"],
    "dana": ["dana.id"],
    "shopee": ["shopee.co.id", "shopee.com"],
    "tokopedia": ["tokopedia.com"],
    "binus": ["binus.ac.id"],
    "okx": ["okx.com"],
}


def _normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if value.startswith("http://"):
        value = value[7:]
    elif value.startswith("https://"):
        value = value[8:]
    value = value.strip("/")

    if value.startswith("www."):
        value = value[4:]

    return value


def _extract_registered_domain(host: str) -> str:
    host = _normalize_domain(host)
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    elif ext.domain:
        return ext.domain.lower()
    return host.lower()


def _load_reference_domains() -> list[str]:
    domains = []

    if REFERENCE_DOMAINS_PATH.exists():
        try:
            with open(REFERENCE_DOMAINS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    domains.append(_extract_registered_domain(line))
        except Exception:
            pass

    if not domains:
        domains = [_extract_registered_domain(d) for d in BUILTIN_REFERENCE_DOMAINS]

    return sorted(set(domains))


def analyze_search_verification(
    registered_domain: str,
    brand_hits: list[str] | None = None,
    lexical_tokens: list[str] | None = None,
) -> dict:
    brand_hits = [b for b in (brand_hits or []) if b in BRAND_TO_OFFICIAL_DOMAINS]
    lexical_tokens = lexical_tokens or []

    if not brand_hits:
        return {
            "V": 0.0,
            "flags": {
                "offline_verification_not_needed": 1,
            },
            "features": {
                "reason": "no_brand_hits",
            },
        }

    reg_domain = _extract_registered_domain(registered_domain)
    refs = _load_reference_domains()

    brand = brand_hits[0]
    official_domains = sorted(set(
        _extract_registered_domain(d)
        for d in BRAND_TO_OFFICIAL_DOMAINS.get(brand, [])
    ))

    exact_official_match = int(reg_domain in official_domains)
    official_present_in_reference = int(any(d in refs for d in official_domains))
    brand_token_present = int(brand in lexical_tokens or brand in reg_domain)
    brand_domain_mismatch = int((not exact_official_match) and brand_token_present)

    related_reference_domains = [
        d for d in refs
        if brand in d.split(".")[0] or d in official_domains
    ][:10]

    flags = {
        "offline_brand_detected": int(brand_token_present),
        "offline_exact_official_match": exact_official_match,
        "offline_official_domain_in_reference": official_present_in_reference,
        "offline_brand_domain_mismatch": brand_domain_mismatch,
    }

    score = 0.0

    if flags["offline_brand_detected"]:
        score += 0.05

    if flags["offline_official_domain_in_reference"]:
        score += 0.10

    if flags["offline_brand_domain_mismatch"]:
        score += 0.22

    if (
        flags["offline_brand_detected"]
        and flags["offline_official_domain_in_reference"]
        and flags["offline_brand_domain_mismatch"]
    ):
        score += 0.18

    if flags["offline_exact_official_match"]:
        score = 0.0

    score = max(0.0, min(1.0, score))

    return {
        "V": round(score, 6),
        "flags": flags,
        "features": {
            "brand": brand,
            "registered_domain": reg_domain,
            "official_domains": official_domains,
            "related_reference_domains": related_reference_domains,
            "lexical_tokens": lexical_tokens[:5],
        },
    }