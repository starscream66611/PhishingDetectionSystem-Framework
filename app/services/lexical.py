from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from app.core.tld_utils import extract_tld_parts


REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0 Safari/537.36"
    )
}

STOPWORDS = {
    "the", "and", "for", "you", "your", "with", "that", "this", "from", "have",
    "are", "was", "were", "will", "can", "not", "but", "all", "any", "our",
    "http", "https", "www", "com", "net", "org", "html", "php", "index",
    "home", "page", "click", "here", "please", "more", "than", "into",
    "about", "login", "sign", "verify", "account"
}

KNOWN_BRANDS = {
    "google",
    "paypal",
    "apple",
    "microsoft",
    "facebook",
    "instagram",
    "amazon",
    "netflix",
    "telegram",
    "whatsapp",
    "binance",
    "coinbase",
    "bca",
    "bri",
    "bni",
    "mandiri",
    "ovo",
    "dana",
    "shopee",
    "tokopedia",
    "binus",
    "okx",
}

SAFE_EXACT_HOSTS = {
    "google.com",
    "paypal.com",
    "apple.com",
    "microsoft.com",
    "facebook.com",
    "instagram.com",
    "amazon.com",
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
}

SUSPICIOUS_TERMS = {
    "login",
    "signin",
    "verify",
    "verification",
    "security",
    "secure",
    "password",
    "reset",
    "confirm",
    "identity",
    "unlock",
    "wallet",
    "payment",
    "billing",
    "account",
    "recovery",
    "otp",
    "2fa",
    "mfa",
}


def _safe_text(text: str | None) -> str:
    return (text or "").strip().lower()


def _get_registered_domain(value: str) -> str:
    try:
        host = urlparse(value).hostname or value
    except Exception:
        host = value

    host = (host or "").strip().lower()
    if host.startswith("www."):
        host = host[4:]

    ext = extract_tld_parts(host)
    if ext is None:
        ext = type("TldParts", (), {"domain": "", "suffix": ""})()
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


def _get_exact_host(value: str) -> str:
    try:
        host = urlparse(value).hostname or value
    except Exception:
        host = value

    host = (host or "").strip().lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _tokenize(text: str) -> list[str]:
    text = _safe_text(text)
    tokens = re.findall(r"[a-z0-9]{3,}", text)
    cleaned = []
    for t in tokens:
        if t in STOPWORDS:
            continue
        if t.isdigit():
            continue
        cleaned.append(t)
    return cleaned


def analyze_lexical(url: str, registered_domain: str) -> dict:
    flags: dict[str, int] = {}
    features: dict[str, object] = {}

    try:
        response = requests.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=8,
            allow_redirects=True,
        )
    except Exception as e:
        return {
            "L": 0.0,
            "flags": {
                "lexical_fetch_failed": 1,
            },
            "features": {
                "error": str(e),
            },
        }

    final_url = response.url
    final_domain = _get_registered_domain(final_url)
    original_domain = _get_registered_domain(registered_domain)
    exact_host = _get_exact_host(url)
    exact_safe_host = exact_host in SAFE_EXACT_HOSTS

    html = response.text or ""
    content_type = _safe_text(response.headers.get("Content-Type", ""))

    if "text/html" not in content_type and "<html" not in html.lower():
        return {
            "L": 0.0,
            "flags": {
                "lexical_non_html": 1,
            },
            "features": {
                "final_url": final_url,
                "final_domain": final_domain,
                "status_code": response.status_code,
                "content_type": content_type,
            },
        }

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.extract()

    title = _safe_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    body_text = _safe_text(soup.get_text(" ", strip=True))
    short_text = body_text[:5000]

    tokens = _tokenize(f"{title} {short_text}")
    counts = Counter(tokens)
    signature = [word for word, _ in counts.most_common(5)]

    brand_hits = sorted({b for b in KNOWN_BRANDS if b in tokens or b in title or b in short_text})
    suspicious_hits = sorted({s for s in SUSPICIOUS_TERMS if s in tokens or s in title or s in short_text})

    domain_aligned_brand_hits = [b for b in brand_hits if b in original_domain or b in final_domain]
    mismatched_brand_hits = [b for b in brand_hits if b not in original_domain and b not in final_domain]

    flags["lexical_brand_hit"] = int(len(brand_hits) >= 1)
    flags["lexical_multiple_brand_terms"] = int(len(brand_hits) >= 2)
    flags["lexical_suspicious_terms"] = int(
        len(suspicious_hits) >= 1 and (not exact_safe_host or len(mismatched_brand_hits) >= 1)
    )
    flags["lexical_multiple_suspicious_terms"] = int(
        len(suspicious_hits) >= 2 and (not exact_safe_host or len(mismatched_brand_hits) >= 1)
    )
    flags["lexical_brand_domain_mismatch"] = int(len(mismatched_brand_hits) >= 1)
    flags["lexical_brand_final_domain_mismatch"] = int(
        len(brand_hits) >= 1 and all(b not in final_domain for b in brand_hits)
    )
    flags["lexical_thin_content"] = int(len(short_text.strip()) < 80)

    score = 0.0

    if flags["lexical_brand_hit"] and len(domain_aligned_brand_hits) == 0:
        score += 0.06
    if flags["lexical_multiple_brand_terms"]:
        score += 0.06
    if flags["lexical_suspicious_terms"]:
        score += 0.03
    if flags["lexical_multiple_suspicious_terms"]:
        score += 0.05
    if flags["lexical_brand_domain_mismatch"]:
        score += 0.18
    if flags["lexical_brand_final_domain_mismatch"]:
        score += 0.14
    if flags["lexical_brand_domain_mismatch"] and flags["lexical_suspicious_terms"]:
        score += 0.12
    if flags["lexical_thin_content"]:
        score += 0.03

    score = max(0.0, min(1.0, score))

    features["title"] = title
    features["final_url"] = final_url
    features["final_domain"] = final_domain
    features["status_code"] = response.status_code
    features["top_tokens"] = signature
    features["brand_hits"] = brand_hits
    features["suspicious_hits"] = suspicious_hits
    features["token_count"] = len(tokens)

    return {
        "L": round(score, 6),
        "flags": flags,
        "features": features,
    }
