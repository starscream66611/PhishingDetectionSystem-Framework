from __future__ import annotations

from urllib.parse import urljoin, urlparse

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

SUSPICIOUS_SUBMIT_WORDS = {
    "login",
    "log in",
    "sign in",
    "signin",
    "verify",
    "verification",
    "continue",
    "confirm",
    "submit",
    "unlock",
    "validate",
    "next",
    "reset password",
}

LOGIN_LIKE_TITLE_WORDS = {
    "login",
    "sign in",
    "signin",
    "verify",
    "security check",
    "account verification",
    "password reset",
    "confirm identity",
}

GENERIC_VERIFICATION_WORDS = {
    "verify you are human",
    "security verification",
    "account verification",
    "confirm your identity",
    "unusual activity",
    "suspicious activity",
    "captcha",
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
}


def _safe_text(text: str | None) -> str:
    return (text or "").strip().lower()


def _get_registered_domain(value: str) -> str:
    try:
        host = urlparse(value).hostname or value
    except Exception:
        host = value

    host = (host or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]

    ext = extract_tld_parts(host)
    if ext is None:
        ext = type("TldParts", (), {"domain": "", "suffix": ""})()
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


def _contains_any(text: str, words: set[str]) -> bool:
    text = _safe_text(text)
    return any(w in text for w in words)


def analyze_hyperlinks(url: str, registered_domain: str) -> dict:
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
            "H_link": 0.0,
            "flags": {
                "page_fetch_failed": 1,
            },
            "features": {
                "error": str(e),
            },
        }

    final_url = response.url
    final_domain = _get_registered_domain(final_url)
    original_domain = _get_registered_domain(registered_domain)

    content_type = _safe_text(response.headers.get("Content-Type", ""))
    html = response.text or ""

    if "text/html" not in content_type and "<html" not in html.lower():
        return {
            "H_link": 0.0,
            "flags": {
                "non_html_content": 1,
            },
            "features": {
                "final_url": final_url,
                "final_domain": final_domain,
                "status_code": response.status_code,
                "content_type": content_type,
            },
        }

    soup = BeautifulSoup(html, "html.parser")

    title = _safe_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    body_text = _safe_text(soup.get_text(" ", strip=True))
    body_text_short = body_text[:3000]

    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", {"type": "password"})
    text_inputs = soup.find_all("input", {"type": ["text", "email", "tel"]})
    hidden_inputs = soup.find_all("input", {"type": "hidden"})
    buttons = soup.find_all(["button", "input"])
    anchors = soup.find_all("a", href=True)

    features["form_count"] = len(forms)
    features["password_input_count"] = len(password_inputs)
    features["text_input_count"] = len(text_inputs)
    features["hidden_input_count"] = len(hidden_inputs)
    features["anchor_count"] = len(anchors)
    features["title"] = title
    features["final_url"] = final_url
    features["final_domain"] = final_domain
    features["status_code"] = response.status_code

    # -----------------------------
    # Login / credential indicators
    # -----------------------------
    flags["has_password_input"] = int(len(password_inputs) >= 1)
    flags["has_login_form"] = int(len(forms) >= 1 and len(password_inputs) >= 1)
    flags["many_sensitive_inputs"] = int((len(password_inputs) + len(text_inputs)) >= 3)

    # submit wording
    suspicious_submit_wording = 0
    for btn in buttons:
        text = ""
        if btn.name == "button":
            text = _safe_text(btn.get_text(" ", strip=True))
        else:
            text = _safe_text(btn.get("value", ""))

        if _contains_any(text, SUSPICIOUS_SUBMIT_WORDS):
            suspicious_submit_wording = 1
            break

    flags["suspicious_submit_wording"] = suspicious_submit_wording

    # title signals
    flags["login_like_title"] = int(_contains_any(title, LOGIN_LIKE_TITLE_WORDS))
    flags["verification_page"] = int(_contains_any(body_text_short, {"verification", "verify", "confirm identity"}))
    flags["generic_verification_page"] = int(_contains_any(body_text_short, GENERIC_VERIFICATION_WORDS))
    flags["suspicious_challenge_page"] = int(
        _contains_any(body_text_short, {"captcha", "i am not a robot", "cloudflare"}) and
        _contains_any(body_text_short, {"login", "verify", "account", "password"})
    )

    # empty / low content
    flags["empty_page"] = int(len(body_text.strip()) == 0)
    flags["very_low_content_page"] = int(0 < len(body_text.strip()) < 120)
    flags["parked_or_placeholder_page"] = int(
        _contains_any(body_text_short, {
            "coming soon",
            "under construction",
            "buy this domain",
            "parked",
            "default web page",
            "placeholder",
        })
    )

    # redirect signals
    flags["redirected_to_other_domain"] = int(final_domain != original_domain and final_domain != "")
    flags["redirected_to_random_path"] = int(
        final_domain == original_domain and
        len(urlparse(final_url).path or "") > 20 and
        any(ch.isdigit() for ch in (urlparse(final_url).path or ""))
    )

    # brand detection in content/title
    title_brand_hits = sorted([b for b in KNOWN_BRANDS if b in title])
    body_brand_hits = sorted([b for b in KNOWN_BRANDS if b in body_text_short])

    features["title_brand_hits"] = title_brand_hits
    features["body_brand_hits"] = body_brand_hits

    flags["brand_title_mismatch"] = int(
        len(title_brand_hits) >= 1 and all(b not in original_domain for b in title_brand_hits)
    )

    flags["domain_title_mismatch"] = int(
        len(title_brand_hits) >= 1 and final_domain != "" and all(b not in final_domain for b in title_brand_hits)
    )

    flags["content_topic_mismatch"] = int(
        len(body_brand_hits) >= 1 and all(b not in original_domain for b in body_brand_hits)
    )

    # external form action
    external_form_action = 0
    empty_form_action = 0

    for form in forms:
        action = _safe_text(form.get("action", ""))

        if not action:
            empty_form_action = 1
            continue

        absolute_action = urljoin(final_url, action)
        action_domain = _get_registered_domain(absolute_action)

        if action_domain and action_domain != final_domain:
            external_form_action = 1

    flags["external_form_action"] = external_form_action
    flags["empty_form_action"] = empty_form_action

    # anchor analysis
    external_anchors = 0
    for a in anchors[:200]:
        href = _safe_text(a.get("href", ""))
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        abs_href = urljoin(final_url, href)
        href_domain = _get_registered_domain(abs_href)
        if href_domain and href_domain != final_domain:
            external_anchors += 1

    features["external_anchor_count"] = external_anchors

    # -----------------------------
    # Scoring 0..1
    # -----------------------------
    score = 0.0

    if flags["has_password_input"]:
        score += 0.18
    if flags["has_login_form"]:
        score += 0.14
    if flags["many_sensitive_inputs"]:
        score += 0.06
    if flags["suspicious_submit_wording"]:
        score += 0.06

    if flags["login_like_title"]:
        score += 0.06
    if flags["brand_title_mismatch"]:
        score += 0.16
    if flags["domain_title_mismatch"]:
        score += 0.12
    if flags["content_topic_mismatch"]:
        score += 0.10

    if flags["external_form_action"]:
        score += 0.18
    if flags["empty_form_action"]:
        score += 0.05

    if flags["redirected_to_other_domain"]:
        score += 0.12
    if flags["redirected_to_random_path"]:
        score += 0.07

    if flags["verification_page"]:
        score += 0.06
    if flags["generic_verification_page"]:
        score += 0.08
    if flags["suspicious_challenge_page"]:
        score += 0.10

    if flags["empty_page"]:
        score += 0.05
    if flags["very_low_content_page"]:
        score += 0.04
    if flags["parked_or_placeholder_page"]:
        score += 0.08

    if external_anchors >= 10:
        score += 0.04

    score = max(0.0, min(1.0, score))

    return {
        "H_link": round(score, 6),
        "flags": flags,
        "features": features,
    }
