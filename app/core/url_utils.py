from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.core.tld_utils import extract_tld_parts

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_url(raw: str) -> str:
    """Normalize raw input into a parseable URL."""
    s = (raw or "").strip()
    if not s:
        raise ValueError("Empty URL")

    if not _SCHEME_RE.match(s):
        s = "https://" + s

    return s


def clean_host(host: str) -> str:
    """Lowercase, strip spaces, remove trailing dot, brackets, and www."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""

    # IPv6 bracket style: [::1]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]

    if h.startswith("www."):
        h = h[4:]

    return h


def is_punycode(value: str) -> bool:
    """Detect whether any label in the hostname uses punycode."""
    s = clean_host(value)
    if not s:
        return False
    return any(label.startswith("xn--") for label in s.split("."))


def is_ipv4(host: str) -> bool:
    """Return True if host is a valid IPv4 address."""
    h = clean_host(host)
    if not h:
        return False

    if not _IPV4_RE.match(h):
        return False

    try:
        ipaddress.IPv4Address(h)
        return True
    except ipaddress.AddressValueError:
        return False


def extract_registered_domain(host: str) -> str:
    """Extract registered domain using tldextract when available.

    Examples:
    - login.paypal.com -> paypal.com
    - google.com.verify-login.ru -> verify-login.ru
    - a.b.example.co.uk -> example.co.uk
    """
    h = clean_host(host)
    if not h:
        return ""

    # If host is an IP, return it as-is
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass

    extracted = extract_tld_parts(h)

    if extracted is not None:
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain:
            return extracted.domain

    # Fallback if tldextract is not installed
    parts = h.split(".")
    if len(parts) <= 2:
        return h

    # NOTE:
    # fallback ini tidak seakurat tldextract untuk co.uk / com.au / dll
    return ".".join(parts[-2:])


def parse_url(url: str):
    """Parse normalized URL and return:
    parsed, host, path, registered_domain, punycode
    """
    parsed = urlparse(url)
    host = clean_host(parsed.hostname or "")
    path = parsed.path or ""
    registered_domain = extract_registered_domain(host)
    punycode = is_punycode(host)
    return parsed, host, path, registered_domain, punycode
