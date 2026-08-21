from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, parse_qsl

from app.core.tld_utils import extract_tld_parts


SUSPICIOUS_WORDS = {
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "account",
    "bank",
    "wallet",
    "payment",
    "billing",
    "invoice",
    "recover",
    "reset",
    "password",
    "confirm",
    "unlock",
    "suspended",
    "limited",
    "alert",
    "webscr",
    "ebayisapi",
    "auth",
    "token",
    "session",
    "validate",
    "support",
    "mfa",
    "2fa",
}

LOGIN_LIKE_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "auth",
    "authenticate",
    "reset",
    "password",
    "confirm",
    "recover",
    "unlock",
    "portal",
    "webmail",
    "session",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "ru",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "work",
    "country",
    "beauty",
    "rest",
    "fit",
    "quest",
    "cam",
    "biz",
    "info",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "lnkd.in",
    "ur0.jp",
}

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

KNOWN_BRANDS = {
    "google",
    "paypal",
    "apple",
    "microsoft",
    "instagram",
    "facebook",
    "meta",
    "amazon",
    "netflix",
    "telegram",
    "whatsapp",
    "binance",
    "coinbase",
    "bank",
    "bca",
    "bri",
    "bni",
    "mandiri",
    "ovo",
    "gopay",
    "dana",
    "shopee",
    "tokopedia",
    "github",
    "linkedin",
    "outlook",
    "office",
    "adobe",
    "discord",
    "tiktok",
    "steam",
}

REDIRECT_LIKE_PARAMS = {
    "redirect",
    "redirect_uri",
    "redir",
    "return",
    "returnto",
    "return_url",
    "url",
    "target",
    "dest",
    "destination",
    "continue",
    "next",
    "callback",
}

SUSPICIOUS_PATH_EXTENSIONS = {
    ".php",
    ".html",
    ".htm",
    ".aspx",
    ".jsp",
    ".cgi",
}

VISUAL_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


def _safe_lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _count_digits(text: str) -> int:
    return sum(ch.isdigit() for ch in text)


def _tokenize(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _contains_any(tokens: list[str], words: set[str]) -> list[str]:
    found = []
    token_set = set(tokens)
    for word in words:
        if word in token_set:
            found.append(word)
    return sorted(found)


def _extract_parts(host: str) -> dict:
    ext = extract_tld_parts(host)
    if ext is None:
        ext = type("TldParts", (), {"subdomain": "", "domain": "", "suffix": ""})()
    registered_domain = ""
    if ext.domain and ext.suffix:
        registered_domain = f"{ext.domain}.{ext.suffix}"
    elif ext.domain:
        registered_domain = ext.domain

    return {
        "subdomain": ext.subdomain or "",
        "domain": ext.domain or "",
        "suffix": ext.suffix or "",
        "registered_domain": registered_domain,
    }


def _normalize_visual(text: str) -> str:
    return (text or "").lower().translate(VISUAL_MAP)


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


def _detect_brand_obfuscation(domain_label: str) -> tuple[bool, str | None]:
    raw = _safe_lower(domain_label)
    visual = _normalize_visual(raw)

    candidates = {raw, visual}

    for part in re.split(r"[-_.]+", raw):
        part = part.strip()
        if part:
            candidates.add(part)
            candidates.add(_normalize_visual(part))

    for brand in KNOWN_BRANDS:
        for candidate in candidates:
            if candidate == brand and raw != brand:
                return True, brand

            dist = _levenshtein(candidate, brand)

            if len(brand) >= 7:
                if dist <= 2 and candidate != brand:
                    return True, brand
            elif len(brand) >= 5:
                if dist <= 1 and candidate != brand:
                    return True, brand
            elif len(brand) >= 3:
                if dist == 1 and candidate != brand:
                    return True, brand

    return False, None


def heuristic_analysis(url: str, host: str, path: str, scheme: str) -> dict:
    url = _safe_lower(url)
    host = _safe_lower(host)
    path = _safe_lower(path)
    scheme = _safe_lower(scheme)

    parsed = urlparse(url)
    query = _safe_lower(parsed.query)
    full_tail = f"{path} {query}".strip()

    parts = _extract_parts(host)
    subdomain = parts["subdomain"]
    domain = parts["domain"]
    suffix = parts["suffix"]
    registered_domain = parts["registered_domain"]

    path_tokens = _tokenize(full_tail)
    all_tokens = _tokenize(f"{host} {full_tail}")

    suspicious_words_found = _contains_any(all_tokens, SUSPICIOUS_WORDS)
    login_like_found = _contains_any(path_tokens, LOGIN_LIKE_WORDS)

    hyphen_count = host.count("-")
    dot_count = host.count(".")
    digit_count = _count_digits(host)
    url_length = len(url)
    host_length = len(host)
    path_length = len(path)
    query_length = len(query)
    at_count = host.count("@") + path.count("@") + query.count("@")
    encoded_count = len(re.findall(r"%[0-9a-f]{2}", url))
    slash_count = url.count("/")
    equals_count = url.count("=")
    has_ip = _is_ip(host)
    is_shortener = registered_domain in SHORTENER_DOMAINS
    is_public_hosting = registered_domain in PUBLIC_HOSTING_DOMAINS
    is_https = scheme == "https"
    is_http = scheme == "http"
    is_punycode = "xn--" in host or "xn--" in registered_domain

    subdomain_depth = 0
    if subdomain:
        subdomain_depth = len([x for x in subdomain.split(".") if x])

    suspicious_tld = suffix in SUSPICIOUS_TLDS if suffix else False

    brand_hits = sorted({b for b in KNOWN_BRANDS if b in all_tokens or b in domain})
    has_brand = len(brand_hits) > 0
    exact_safe_host = host in SAFE_EXACT_HOSTS
    registered_safe_domain = registered_domain in SAFE_EXACT_HOSTS
    query_keys = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    path_has_suspicious_extension = any(path.endswith(ext) for ext in SUSPICIOUS_PATH_EXTENSIONS)
    double_slash_in_path = "//" in (parsed.path or "")
    brand_in_path_only = any(brand in path_tokens for brand in KNOWN_BRANDS) and not registered_safe_domain
    redirect_param_present = any(k in REDIRECT_LIKE_PARAMS for k in query_keys)
    google_published_doc = (
        host in {"docs.google.com", "drive.google.com"}
        and (
            "/presentation/d/e/" in path
            or "/document/d/e/" in path
            or "/forms/d/e/" in path
        )
        and path.endswith("/pub")
    )

    brand_obfuscation, obfuscated_brand = _detect_brand_obfuscation(domain)

    normalized_domain = _normalize_visual(domain)
    normalized_host = _normalize_visual(host)

    brand_token_hit = False
    brand_token_name = None
    for brand in KNOWN_BRANDS:
        if brand in normalized_domain or brand in normalized_host:
            if brand not in domain and brand not in host:
                brand_token_hit = True
                brand_token_name = brand
                break

    flags: dict[str, int] = {}

    flags["no_https"] = int(not is_https)
    flags["has_ip_address"] = int(has_ip)
    flags["shortener_domain"] = int(is_shortener)
    flags["public_hosting_domain"] = int(is_public_hosting)
    flags["punycode_domain"] = int(is_punycode)
    flags["suspicious_tld"] = int(suspicious_tld)

    flags["brand_in_domain"] = int(has_brand and not registered_safe_domain)
    flags["brand_plus_suspicious_tld"] = int(has_brand and suspicious_tld and not registered_safe_domain)
    flags["brand_plus_suspicious_word"] = int(
        has_brand and len(suspicious_words_found) >= 1 and not registered_safe_domain
    )
    flags["brand_tld_mismatch"] = int(has_brand and suspicious_tld)

    flags["path_has_login_like"] = int(len(login_like_found) > 0)
    flags["suspicious_words"] = int(len(suspicious_words_found) >= 1)
    flags["multiple_suspicious_words"] = int(len(suspicious_words_found) >= 2)

    flags["suspicious_structure"] = int(
        hyphen_count >= 2
        or subdomain_depth >= 2
        or url_length > 90
        or encoded_count >= 2
        or at_count >= 1
    )

    flags["generic_domain_with_phishing_path"] = int(
        (not has_brand) and len(login_like_found) >= 1 and suspicious_tld
    )
    flags["generic_suspicious_path"] = int(
        len(login_like_found) >= 1 and query_length > 10
    )
    flags["redirect_like_parameter"] = int(redirect_param_present)
    flags["suspicious_file_path"] = int(
        path_has_suspicious_extension and (len(login_like_found) > 0 or len(suspicious_words_found) > 0)
    )
    flags["double_slash_path"] = int(double_slash_in_path)
    flags["brand_in_path_only"] = int(brand_in_path_only)
    flags["published_google_doc_path"] = int(google_published_doc)

    flags["many_digits_in_host"] = int(digit_count >= 3)
    flags["many_subdomains"] = int(subdomain_depth >= 2)
    flags["many_hyphens"] = int(hyphen_count >= 2)
    flags["long_url"] = int(url_length > 75)
    flags["very_long_url"] = int(url_length > 120)
    flags["has_at_symbol"] = int(at_count >= 1)
    flags["many_encoded_chars"] = int(encoded_count >= 2)

    flags["brand_obfuscation"] = int(brand_obfuscation)
    flags["brand_obfuscation_plus_login"] = int(brand_obfuscation and len(login_like_found) > 0)
    flags["brand_obfuscation_plus_suspicious_tld"] = int(brand_obfuscation and suspicious_tld)
    flags["digit_substitution_in_domain"] = int(bool(re.search(r"[013457@\$]", domain)))

    flags["brand_token_obfuscation"] = int(brand_token_hit)
    flags["brand_token_obfuscation_plus_login"] = int(
        brand_token_hit and len(login_like_found) > 0
    )
    flags["brand_token_obfuscation_plus_suspicious_word"] = int(
        brand_token_hit and len(suspicious_words_found) > 0
    )

    score = 0.0

    if not is_https:
        score += 0.08
    if is_http:
        score += 0.02

    if has_ip:
        score += 0.25
    if is_punycode:
        score += 0.18
    if is_shortener:
        score += 0.12
    if is_public_hosting:
        score += 0.08
    if suspicious_tld:
        score += 0.12

    if url_length > 75:
        score += 0.05
    if url_length > 120:
        score += 0.08

    if host_length > 25:
        score += 0.04
    if host_length > 35:
        score += 0.05

    if hyphen_count >= 1:
        score += 0.04
    if hyphen_count >= 2:
        score += 0.05

    if subdomain_depth >= 1:
        score += 0.03
    if subdomain_depth >= 2:
        score += 0.06
    if subdomain_depth >= 3:
        score += 0.08

    if digit_count >= 2:
        score += 0.03
    if digit_count >= 4:
        score += 0.05

    if at_count >= 1:
        score += 0.12

    if encoded_count >= 1:
        score += 0.04
    if encoded_count >= 2:
        score += 0.05

    if len(suspicious_words_found) >= 1:
        score += 0.03
    if len(suspicious_words_found) >= 2:
        score += 0.08
    if len(suspicious_words_found) >= 3:
        score += 0.06

    if len(login_like_found) >= 1:
        score += 0.03

    if has_brand and suspicious_tld and not registered_safe_domain:
        score += 0.12
    if has_brand and len(suspicious_words_found) >= 1 and not registered_safe_domain:
        score += 0.10

    if (not has_brand) and len(login_like_found) >= 1 and suspicious_tld:
        score += 0.08

    if query_length > 25:
        score += 0.04
    if redirect_param_present:
        score += 0.05
    if path_has_suspicious_extension and (len(login_like_found) >= 1 or len(suspicious_words_found) >= 1):
        score += 0.06
    if double_slash_in_path:
        score += 0.04
    if brand_in_path_only and (len(login_like_found) >= 1 or suspicious_tld or is_public_hosting):
        score += 0.08
    if google_published_doc:
        score += 0.18

    if equals_count >= 3:
        score += 0.03

    if brand_obfuscation:
        score += 0.18
    if brand_obfuscation and len(login_like_found) >= 1:
        score += 0.12
    if brand_obfuscation and suspicious_tld:
        score += 0.12
    if flags["digit_substitution_in_domain"]:
        score += 0.05

    if brand_token_hit:
        score += 0.16
    if brand_token_hit and len(login_like_found) >= 1:
        score += 0.10
    if brand_token_hit and len(suspicious_words_found) >= 1:
        score += 0.10

    if exact_safe_host and is_https and len(suspicious_words_found) == 0 and not suspicious_tld:
        score -= 0.10

    score = max(0.0, min(1.0, score))

    return {
        "H": round(score, 6),
        "flags": flags,
        "features": {
            "url_length": url_length,
            "host_length": host_length,
            "path_length": path_length,
            "query_length": query_length,
            "hyphen_count": hyphen_count,
            "dot_count": dot_count,
            "digit_count": digit_count,
            "subdomain_depth": subdomain_depth,
            "encoded_count": encoded_count,
            "slash_count": slash_count,
            "equals_count": equals_count,
            "query_keys": sorted(query_keys),
            "path_has_suspicious_extension": path_has_suspicious_extension,
            "double_slash_in_path": double_slash_in_path,
            "redirect_param_present": redirect_param_present,
            "brand_in_path_only": brand_in_path_only,
            "google_published_doc": google_published_doc,
            "has_ip": has_ip,
            "is_https": is_https,
            "is_http": is_http,
            "is_punycode": is_punycode,
            "is_shortener": is_shortener,
            "is_public_hosting": is_public_hosting,
            "suspicious_tld": suspicious_tld,
            "brand_hits": brand_hits,
            "brand_obfuscation_brand": obfuscated_brand,
            "brand_token_obfuscation_brand": brand_token_name,
            "suspicious_words_found": suspicious_words_found,
            "login_like_found": login_like_found,
            "registered_domain": registered_domain,
            "suffix": suffix,
        },
        "meta": {
            "is_safe_brand_domain": exact_safe_host,
            "is_exact_safe_host": exact_safe_host,
            "is_registered_safe_domain": registered_safe_domain,
        },
    }
