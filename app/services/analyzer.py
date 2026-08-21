from __future__ import annotations

from app.core.detection_config import DEFAULT_CONFIG, DetectionConfig
from app.core.url_utils import parse_url
from app.services.explanations import build_explanations
from app.services.heuristics import heuristic_analysis
from app.services.hyperlink import analyze_hyperlinks
from app.services.lexical import analyze_lexical
from app.services.redirect_resolver import resolve_final_url, should_resolve_redirect
from app.services.risk import risk_score
from app.services.similarity import domain_similarity


def _analyze_core(
    normalized_url: str,
    blacklist_service,
    reference_domains: list[str],
    config: DetectionConfig | None = None,
) -> dict:
    config = config or DEFAULT_CONFIG

    parsed, host, path, registered_domain, punycode = parse_url(normalized_url)

    if not host:
        raise ValueError("Hostname tidak valid")

    blacklist_result = blacklist_service.check(normalized_url, registered_domain)
    B = float(blacklist_result.get("B", 0.0) or 0.0)

    try:
        link = analyze_hyperlinks(normalized_url, registered_domain)
    except Exception:
        link = {
            "H_link": 0.0,
            "flags": {"page_fetch_failed": 1},
            "features": {},
        }

    try:
        lex = analyze_lexical(normalized_url, registered_domain)
    except Exception:
        lex = {
            "L": 0.0,
            "flags": {"lexical_fetch_failed": 1},
            "features": {},
        }

    heur = heuristic_analysis(
        url=normalized_url,
        host=host,
        path=path,
        scheme=(parsed.scheme or ""),
    )

    sim = domain_similarity(host, reference_domains)

    h_url = float(heur.get("H", 0.0) or 0.0)
    h_link = float(link.get("H_link", 0.0) or 0.0)
    h_lex = float(lex.get("L", 0.0) or 0.0)

    # URL heuristic tetap utama, content & lexical sebagai penguat
    h_total = (0.75 * h_url) + (0.15 * h_link) + (0.10 * h_lex)

    merged_flags = dict(heur.get("flags", {}))
    merged_flags.update(link.get("flags", {}))
    merged_flags.update(lex.get("flags", {}))

    combined = risk_score(
        H=h_total,
        B=B,
        S=float(sim.get("S", 0.0) or 0.0),
        blacklist=blacklist_result,
        flags=merged_flags,
        similarity=sim,
        is_safe_brand_domain=heur.get("meta", {}).get("is_safe_brand_domain", False),
        config=config,
    )

    explanations = build_explanations(
        hostname=host,
        registered_domain=registered_domain,
        heuristics={
            **heur,
            "H_url": h_url,
            "H_link": h_link,
            "H_lex": h_lex,
            "H_total": h_total,
            "hyperlink": link,
            "lexical": lex,
            "flags": merged_flags,
        },
        similarity=sim,
    )

    return {
        "normalized_url": normalized_url,
        "hostname": host,
        "registered_domain": registered_domain,
        "is_punycode": punycode,
        "path": path,
        "blacklist": blacklist_result,
        "heuristics": {
            **heur,
            "H_url": h_url,
            "H_link": h_link,
            "H_lex": h_lex,
            "H_total": h_total,
            "hyperlink": link,
            "lexical": lex,
            "flags": merged_flags,
        },
        "similarity": sim,
        "explanations": explanations,
        **combined,
    }


def analyze_url(
    normalized_url: str,
    blacklist_service,
    reference_domains: list[str],
    config: DetectionConfig | None = None,
) -> dict:
    config = config or DEFAULT_CONFIG

    base_result = _analyze_core(
        normalized_url=normalized_url,
        blacklist_service=blacklist_service,
        reference_domains=reference_domains,
        config=config,
    )

    redirect_info = {
        "checked": False,
        "resolved": False,
        "original_url": normalized_url,
        "final_url": normalized_url,
        "analysis_target": "original_url",
        "error": None,
    }

    if should_resolve_redirect(base_result["hostname"], base_result["registered_domain"]):
        redirect_info["checked"] = True
        resolved = resolve_final_url(normalized_url)
        redirect_info.update(resolved)

        final_url = resolved.get("final_url", normalized_url)
        if resolved.get("resolved") and final_url != normalized_url:
            resolved_result = _analyze_core(
                normalized_url=final_url,
                blacklist_service=blacklist_service,
                reference_domains=reference_domains,
                config=config,
            )

            if resolved_result["risk_score"] >= base_result["risk_score"]:
                resolved_result["input_normalized_url"] = normalized_url
                resolved_result["redirect_resolution"] = {
                    **redirect_info,
                    "analysis_target": "resolved_url",
                }
                return resolved_result

    base_result["input_normalized_url"] = normalized_url
    base_result["redirect_resolution"] = redirect_info
    return base_result
