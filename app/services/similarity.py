from __future__ import annotations

from functools import lru_cache
import logging
from pathlib import Path
import pickle
import re
from urllib.parse import urlparse

from app.core.tld_utils import extract_tld_parts

LOGGER = logging.getLogger(__name__)


DATA_DIR = Path(__file__).resolve().parents[2] / "data"
INDEX_PATH = DATA_DIR / "reference_index.pkl"
REFERENCE_DOMAINS_PATH = DATA_DIR / "reference_domains.txt"


BUILTIN_REFERENCE_DOMAINS = [
    "google.com",
    "paypal.com",
    "apple.com",
    "microsoft.com",
    "office.com",
    "live.com",
    "outlook.com",
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "dropbox.com",
    "onedrive.live.com",
    "drive.google.com",
    "docs.google.com",
    "icloud.com",
    "adobe.com",
    "canva.com",
    "zoom.us",
    "discord.com",
    "steamcommunity.com",
    "tiktok.com",
    "spotify.com",
    "reddit.com",
    "yahoo.com",
    "yandex.ru",
    "booking.com",
    "airbnb.com",
    "ebay.com",
    "aliexpress.com",
    "facebook.com",
    "instagram.com",
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
    "gopay.co.id",
    "dana.id",
    "shopee.co.id",
    "tokopedia.com",
    "binus.ac.id",
    "youtube.com",
]

PUBLIC_HOSTING_DOMAINS = {
    "github.io",
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "firebaseapp.com",
    "web.app",
    "000webhostapp.com",
    "blogspot.com",
    "wixsite.com",
    "weebly.com",
    "glitch.me",
    "surge.sh",
}


VISUAL_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
})


PRIORITY_BRANDS = {
    "google": "google.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "office": "office.com",
    "outlook": "outlook.com",
    "live": "live.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
    "linkedin": "linkedin.com",
    "twitter": "x.com",
    "x": "x.com",
    "dropbox": "dropbox.com",
    "onedrive": "onedrive.live.com",
    "icloud": "icloud.com",
    "adobe": "adobe.com",
    "canva": "canva.com",
    "zoom": "zoom.us",
    "discord": "discord.com",
    "steam": "steamcommunity.com",
    "tiktok": "tiktok.com",
    "spotify": "spotify.com",
    "reddit": "reddit.com",
    "yahoo": "yahoo.com",
    "booking": "booking.com",
    "airbnb": "airbnb.com",
    "ebay": "ebay.com",
    "aliexpress": "aliexpress.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "telegram": "telegram.org",
    "whatsapp": "whatsapp.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "bca": "bca.co.id",
    "bri": "bri.co.id",
    "bni": "bni.co.id",
    "mandiri": "bankmandiri.co.id",
    "ovo": "ovo.id",
    "gopay": "gopay.co.id",
    "dana": "dana.id",
    "shopee": "shopee.co.id",
    "tokopedia": "tokopedia.com",
    "binus": "binus.ac.id",
    "youtube": "youtube.com",
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "secure",
    "verify",
    "verification",
    "account",
    "update",
    "support",
    "signin",
    "wallet",
    "banking",
    "confirm",
    "password",
    "recovery",
    "auth",
    "payment",
    "unlock",
}

_REFERENCE_METADATA_CACHE: dict[tuple[str, ...], list[dict[str, str]]] = {}


def _normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()

    if not domain:
        return ""

    if not domain.startswith(("http://", "https://")):
        domain = "http://" + domain

    parsed = urlparse(domain)
    host = parsed.netloc.strip().lower()

    if not host:
        host = domain.replace("http://", "").replace("https://", "").strip().lower()

    if "@" in host:
        host = host.split("@")[-1]

    if ":" in host:
        host = host.split(":")[0]

    host = host.strip().strip(".")
    host = re.sub(r"^www\d*\.", "", host)

    return host


def _extract_registered_domain(host: str) -> str:
    ext = extract_tld_parts(host)
    if ext is None:
        ext = type("TldParts", (), {"domain": "", "suffix": ""})()
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    elif ext.domain:
        return ext.domain.lower()
    return host.lower()


@lru_cache(maxsize=8192)
def _extract_brand(domain: str) -> str:
    ext = extract_tld_parts(domain)
    if ext is None:
        ext = type("TldParts", (), {"domain": ""})()
    if ext.domain:
        return ext.domain.lower()
    return domain.split(".")[0].lower() if domain else ""


def _normalize_visual(text: str) -> str:
    return (text or "").lower().translate(VISUAL_MAP)


def _strip_non_alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _compress_repeated_chars(text: str) -> str:
    return re.sub(r"(.)\1{2,}", r"\1", text or "")


def _normalize_brand_token(text: str) -> str:
    text = _normalize_visual(text)
    text = _strip_non_alnum(text)
    text = _compress_repeated_chars(text)
    return text


def _sequence_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    from difflib import SequenceMatcher
    return SequenceMatcher(None, a, b).ratio()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


def _digit_count(text: str) -> int:
    return sum(1 for ch in text if ch.isdigit())


def _has_mixed_letters_digits(text: str) -> bool:
    return bool(re.search(r"(?=.*[a-z])(?=.*\d)", text or ""))


def _keyword_penalty(domain: str) -> int:
    score = 0
    lower = (domain or "").lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            score += 6
    return min(score, 24)


def _pattern_penalty(registered_host: str, host_brand: str, matched_brand: str | None = None) -> int:
    score = 0
    normalized_brand = _normalize_brand_token(host_brand)

    if _has_mixed_letters_digits(host_brand):
        score += 18

    digits = _digit_count(host_brand)
    if digits >= 1:
        score += 8
    if digits >= 2:
        score += 8

    if re.search(r"(.)\1{2,}", host_brand):
        score += 10

    if "-" in host_brand:
        score += min(host_brand.count("-") * 4, 12)

    score += _keyword_penalty(registered_host)

    if matched_brand:
        brand_norm = _normalize_brand_token(matched_brand)
        if brand_norm and normalized_brand and brand_norm != normalized_brand:
            if brand_norm in normalized_brand or normalized_brand in brand_norm:
                score += 10

            dist = _levenshtein(normalized_brand, brand_norm)
            if dist == 1:
                score += 18
            elif dist == 2:
                score += 12
            elif dist == 3 and len(brand_norm) >= 6:
                score += 6

    return min(score, 45)


def _load_reference_domains() -> list[str]:
    if INDEX_PATH.exists():
        try:
            with open(INDEX_PATH, "rb") as f:
                obj = pickle.load(f)

            if isinstance(obj, dict):
                domains = obj.get("domains")
                if isinstance(domains, list) and domains:
                    return sorted({
                        _extract_registered_domain(_normalize_domain(d))
                        for d in domains if d
                    })

            if isinstance(obj, list) and obj:
                return sorted({
                    _extract_registered_domain(_normalize_domain(d))
                    for d in obj if d
                })
        except Exception:
            pass

    if REFERENCE_DOMAINS_PATH.exists():
        try:
            domains: list[str] = []
            with open(REFERENCE_DOMAINS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        domains.append(_extract_registered_domain(_normalize_domain(line)))

            if domains:
                return sorted(set(domains))
        except Exception:
            pass

    return sorted({
        _extract_registered_domain(_normalize_domain(d))
        for d in BUILTIN_REFERENCE_DOMAINS
    })


def _best_priority_brand_match(registered_host: str) -> tuple[str | None, str | None, float]:
    host_brand = _extract_brand(registered_host)
    host_brand_norm = _normalize_brand_token(host_brand)

    best_brand = None
    best_domain = None
    best_ratio = 0.0

    for brand, legit_domain in PRIORITY_BRANDS.items():
        brand_norm = _normalize_brand_token(brand)

        seq_raw = _sequence_ratio(host_brand, brand)
        seq_norm = _sequence_ratio(host_brand_norm, brand_norm)

        dist = _levenshtein(host_brand_norm, brand_norm)
        max_len = max(len(host_brand_norm), len(brand_norm), 1)
        lev_ratio = 1.0 - (dist / max_len)

        score = max(seq_raw * 0.35 + seq_norm * 0.65, lev_ratio)

        if brand_norm and brand_norm in host_brand_norm:
            score += 0.08

        if dist == 1:
            score += 0.12
        elif dist == 2:
            score += 0.07

        score = max(0.0, min(1.0, score))

        if score > best_ratio:
            best_ratio = score
            best_brand = brand
            best_domain = legit_domain

    return best_domain, best_brand, best_ratio


def _best_reference_match(registered_host: str, refs: list[str]) -> tuple[str | None, float]:
    host_brand = _extract_brand(registered_host)
    host_brand_norm = _normalize_brand_token(host_brand)

    best_domain = None
    best_ratio = 0.0

    for ref in refs:
        ref_brand = _extract_brand(ref)
        ref_brand_norm = _normalize_brand_token(ref_brand)

        full_ratio = _sequence_ratio(registered_host, ref)
        brand_ratio = _sequence_ratio(host_brand, ref_brand)
        brand_norm_ratio = _sequence_ratio(host_brand_norm, ref_brand_norm)

        dist = _levenshtein(host_brand_norm, ref_brand_norm)
        max_len = max(len(host_brand_norm), len(ref_brand_norm), 1)
        lev_ratio = 1.0 - (dist / max_len)

        ratio = max(
            (0.20 * full_ratio) + (0.25 * brand_ratio) + (0.55 * brand_norm_ratio),
            lev_ratio
        )

        if ref_brand_norm and ref_brand_norm in host_brand_norm:
            ratio += 0.05

        if dist == 1:
            ratio += 0.10
        elif dist == 2:
            ratio += 0.06

        ratio = max(0.0, min(1.0, ratio))

        if ratio > best_ratio:
            best_ratio = ratio
            best_domain = ref

    return best_domain, best_ratio


def _prepare_reference_metadata(refs: list[str]) -> list[dict[str, str]]:
    cache_key = tuple(refs)
    cached = _REFERENCE_METADATA_CACHE.get(cache_key)
    if cached is not None:
        return cached

    metadata: list[dict[str, str]] = []
    for ref in refs:
        ref_brand = _extract_brand(ref)
        metadata.append(
            {
                "domain": ref,
                "brand": ref_brand,
                "brand_norm": _normalize_brand_token(ref_brand),
            }
        )

    _REFERENCE_METADATA_CACHE[cache_key] = metadata
    return metadata


def _best_reference_match_from_metadata(
    registered_host: str,
    reference_metadata: list[dict[str, str]],
) -> tuple[str | None, float]:
    host_brand = _extract_brand(registered_host)
    host_brand_norm = _normalize_brand_token(host_brand)

    best_domain = None
    best_ratio = 0.0

    for item in reference_metadata:
        ref = item["domain"]
        ref_brand = item["brand"]
        ref_brand_norm = item["brand_norm"]

        full_ratio = _sequence_ratio(registered_host, ref)
        brand_ratio = _sequence_ratio(host_brand, ref_brand)
        brand_norm_ratio = _sequence_ratio(host_brand_norm, ref_brand_norm)

        dist = _levenshtein(host_brand_norm, ref_brand_norm)
        max_len = max(len(host_brand_norm), len(ref_brand_norm), 1)
        lev_ratio = 1.0 - (dist / max_len)

        ratio = max(
            (0.20 * full_ratio) + (0.25 * brand_ratio) + (0.55 * brand_norm_ratio),
            lev_ratio
        )

        if ref_brand_norm and ref_brand_norm in host_brand_norm:
            ratio += 0.05

        if dist == 1:
            ratio += 0.10
        elif dist == 2:
            ratio += 0.06

        ratio = max(0.0, min(1.0, ratio))

        if ratio > best_ratio:
            best_ratio = ratio
            best_domain = ref

    return best_domain, best_ratio


def _build_reference_candidates(
    registered_host: str,
    refs: list[str],
    reference_metadata: list[dict[str, str]],
) -> list[dict[str, str]]:
    host_brand = _extract_brand(registered_host)
    host_brand_norm = _normalize_brand_token(host_brand)

    if not host_brand_norm:
        return reference_metadata[:250]

    candidates: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(item: dict[str, str]) -> None:
        ref = item["domain"]
        if ref and ref not in seen:
            candidates.append(item)
            seen.add(ref)

    # Always keep a reasonable slice of the most familiar domains from the incoming list.
    for item in reference_metadata[:400]:
        add(item)

    for item in reference_metadata:
        ref_brand_norm = item["brand_norm"]
        if not ref_brand_norm:
            continue

        same_initial = host_brand_norm[:1] == ref_brand_norm[:1]
        close_length = abs(len(host_brand_norm) - len(ref_brand_norm)) <= 3
        contains_relation = (
            host_brand_norm in ref_brand_norm
            or ref_brand_norm in host_brand_norm
        )
        quick_seq = _sequence_ratio(host_brand_norm, ref_brand_norm)

        if contains_relation or (same_initial and close_length) or quick_seq >= 0.55:
            add(item)

        if len(candidates) >= 800:
            break

    return candidates


def domain_similarity(host: str, reference_domains: list[str] | None = None) -> dict:
    host = _normalize_domain(host)
    registered_host = _extract_registered_domain(host)

    if not registered_host:
        return {
            "S": 0.0,
            "matched_domain": None,
            "matched_brand": None,
            "ratio": 0.0,
            "reason": "empty_host",
        }

    refs = reference_domains or _load_reference_domains()
    refs = sorted({
        _extract_registered_domain(_normalize_domain(d))
        for d in refs if d
    })
    reference_metadata = _prepare_reference_metadata(refs)

    if not refs:
        return {
            "S": 0.0,
            "matched_domain": None,
            "matched_brand": None,
            "ratio": 0.0,
            "reason": "no_reference_domains",
        }

    if registered_host in PUBLIC_HOSTING_DOMAINS:
        return {
            "S": 0.0,
            "matched_domain": registered_host,
            "matched_brand": _extract_brand(registered_host),
            "ratio": 0.0,
            "reason": "public_hosting_domain",
        }

    # exact root domain resmi = aman penuh
    if host in refs:
        return {
            "S": 0.0,
            "matched_domain": host,
            "matched_brand": _extract_brand(host),
            "ratio": 1.0,
            "reason": "exact_legitimate_domain",
        }

    # subdomain dari domain resmi tidak dihukum oleh similarity
    for legit_domain in refs:
        if host.endswith(f".{legit_domain}"):
            return {
                "S": 0.0,
                "matched_domain": legit_domain,
                "matched_brand": _extract_brand(legit_domain),
                "ratio": 1.0,
                "reason": "legitimate_subdomain",
            }

    for legit_domain in PRIORITY_BRANDS.values():
        if host.endswith(f".{legit_domain}"):
            return {
                "S": 0.0,
                "matched_domain": legit_domain,
                "matched_brand": _extract_brand(legit_domain),
                "ratio": 1.0,
                "reason": "legitimate_subdomain",
            }

    # exact legitimate domain dari priority brands = aman
    if host in PRIORITY_BRANDS.values():
        return {
            "S": 0.0,
            "matched_domain": host,
            "matched_brand": _extract_brand(host),
            "ratio": 1.0,
            "reason": "exact_legitimate_domain",
        }

    candidate_refs = _build_reference_candidates(registered_host, refs, reference_metadata)

    priority_domain, priority_brand, priority_ratio = _best_priority_brand_match(registered_host)
    fallback_domain, fallback_ratio = _best_reference_match_from_metadata(registered_host, candidate_refs)

    if priority_domain and priority_ratio >= max(0.78, fallback_ratio):
        matched_domain = priority_domain
        matched_brand = priority_brand
        final_ratio = priority_ratio
        reason = "similar_to_priority_brand_domain"
    else:
        matched_domain = fallback_domain
        matched_brand = _extract_brand(fallback_domain) if fallback_domain else None
        final_ratio = fallback_ratio
        reason = "similar_to_reference_domain" if fallback_domain else "no_match"

    # guard tambahan: exact full host ke domain resmi jangan dihukum similarity
    if matched_domain and host == matched_domain:
        return {
            "S": 0.0,
            "matched_domain": matched_domain,
            "matched_brand": _extract_brand(matched_domain),
            "ratio": 1.0,
            "reason": "exact_legitimate_domain",
        }

    host_brand = _extract_brand(registered_host)
    penalty = _pattern_penalty(registered_host, host_brand, matched_brand)

    score = 0.0

    if final_ratio >= 0.95:
        score = 0.82
    elif final_ratio >= 0.90:
        score = 0.68
    elif final_ratio >= 0.86:
        score = 0.55
    elif final_ratio >= 0.82:
        score = 0.40
    elif final_ratio >= 0.78:
        score = 0.26
    else:
        score = 0.0

    score += penalty / 100.0

    if matched_domain and registered_host != matched_domain and final_ratio >= 0.88:
        score += 0.12

    if matched_brand:
        host_brand_norm = _normalize_brand_token(host_brand)
        matched_brand_norm = _normalize_brand_token(matched_brand)
        dist = _levenshtein(host_brand_norm, matched_brand_norm)

        if dist in (1, 2):
            score += 0.10

    score = max(0.0, min(1.0, score))

    LOGGER.debug(
        "Similarity result for %s: matched_domain=%s ratio=%.6f score=%.6f reason=%s candidates=%s",
        registered_host,
        matched_domain,
        final_ratio,
        score,
        reason,
        len(candidate_refs),
    )

    return {
        "S": round(score, 6),
        "matched_domain": matched_domain,
        "matched_brand": matched_brand,
        "ratio": round(final_ratio, 6),
        "reason": reason,
    }
