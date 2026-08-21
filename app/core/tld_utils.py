from __future__ import annotations

try:
    import tldextract
except ImportError:
    tldextract = None


if tldextract is not None:
    _EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)
else:
    _EXTRACTOR = None


def extract_tld_parts(host: str):
    if _EXTRACTOR is None:
        return None
    return _EXTRACTOR(host or "")
