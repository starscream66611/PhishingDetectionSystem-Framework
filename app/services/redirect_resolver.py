from __future__ import annotations

from urllib.parse import urlparse

import requests

from app.core.url_utils import normalize_url
from app.services.heuristics import SHORTENER_DOMAINS


REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0 Safari/537.36"
    )
}

KNOWN_REDIRECT_DOMAINS = set(SHORTENER_DOMAINS) | {
    "qrco.de",
    "q-r.to",
    "l.ead.me",
    "linkin.bio",
    "onelink.me",
    "app.link",
    "campsite.bio",
    "linktr.ee",
}


def should_resolve_redirect(host: str, registered_domain: str) -> bool:
    host = (host or "").lower().strip()
    registered_domain = (registered_domain or "").lower().strip()
    return host in KNOWN_REDIRECT_DOMAINS or registered_domain in KNOWN_REDIRECT_DOMAINS


def resolve_final_url(url: str, timeout: int = 6) -> dict:
    normalized_url = normalize_url(url)

    try:
        response = requests.head(
            normalized_url,
            headers=REQUEST_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
        final_url = response.url or normalized_url
    except Exception:
        try:
            response = requests.get(
                normalized_url,
                headers=REQUEST_HEADERS,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            final_url = response.url or normalized_url
            response.close()
        except Exception as exc:
            return {
                "resolved": False,
                "original_url": normalized_url,
                "final_url": normalized_url,
                "final_host": (urlparse(normalized_url).hostname or "").lower().strip(),
                "error": str(exc),
            }

    try:
        final_url = normalize_url(final_url)
    except Exception:
        final_url = normalized_url

    return {
        "resolved": final_url != normalized_url,
        "original_url": normalized_url,
        "final_url": final_url,
        "final_host": (urlparse(final_url).hostname or "").lower().strip(),
        "error": None,
    }
