from __future__ import annotations

from app.core.detection_config import DEFAULT_CONFIG, DetectionConfig


def risk_score(
    H: float,
    B: float,
    S: float,
    blacklist: dict | None = None,
    flags: dict | None = None,
    similarity: dict | None = None,
    is_safe_brand_domain: bool = False,
    config: DetectionConfig | None = None,
) -> dict:
    flags = flags or {}
    blacklist = blacklist or {}
    similarity = similarity or {}
    config = config or DEFAULT_CONFIG

    wH = config.wH
    wB = config.wB
    wS = config.wS

    score = (wH * H) + (wB * B) + (wS * S)
    bonus = 0.0
    penalty = 0.0

    sim_ratio = float(similarity.get("ratio", 0.0) or 0.0)
    sim_reason = similarity.get("reason", "")
    blacklist_match_type = blacklist.get("match_type", "none")

    # =========================================================
    # HARD OVERRIDE: exact URL / host+path blacklist
    # =========================================================
    if blacklist_match_type in {"exact_url", "host_path"}:
        return {
            "risk_score": 1.0,
            "risk_percent": 100,

            # final output
            "prediction": "phishing",
            "risk_level": "PHISHING",

            # internal classification
            "raw_prediction": "phishing",
            "raw_risk_level": "HIGH",

            "thresholds": {
                "suspicious_threshold": config.suspicious_threshold,
                "phishing_threshold": config.phishing_threshold,
            },
            "weights": {
                "wH": wH,
                "wB": wB,
                "wS": wS,
            },
            "debug": {
                "base_score": round(score, 6),
                "bonus": 0.0,
                "penalty": 0.0,
                "similarity_ratio": round(sim_ratio, 6),
                "similarity_reason": sim_reason,
                "page_signal_count": 0,
                "override_reason": f"blacklist_{blacklist_match_type}",
            },
        }

    if (
        flags.get("has_ip_address", 0)
        and flags.get("has_password_input", 0)
        and flags.get("external_form_action", 0)
    ):
        return {
            "risk_score": 1.0,
            "risk_percent": 100,
            "prediction": "phishing",
            "risk_level": "PHISHING",
            "raw_prediction": "phishing",
            "raw_risk_level": "HIGH",
            "thresholds": {
                "suspicious_threshold": config.suspicious_threshold,
                "phishing_threshold": config.phishing_threshold,
            },
            "weights": {
                "wH": wH,
                "wB": wB,
                "wS": wS,
            },
            "debug": {
                "base_score": round(score, 6),
                "bonus": 0.0,
                "penalty": 0.0,
                "similarity_ratio": round(sim_ratio, 6),
                "similarity_reason": sim_reason,
                "page_signal_count": 0,
                "override_reason": "ip_password_external_form",
            },
        }

    # =========================================================
    # Soft blacklist bonus (kalau ada score blacklist parsial)
    # =========================================================
    if blacklist_match_type == "host_only":
        bonus += 0.02

    # =========================================================
    # URL danger combos
    # =========================================================
    if flags.get("brand_plus_suspicious_tld", 0):
        bonus += 0.08

    if flags.get("brand_plus_suspicious_word", 0):
        bonus += 0.07

    if flags.get("multiple_suspicious_words", 0):
        bonus += 0.05

    if flags.get("path_has_login_like", 0) and flags.get("suspicious_tld", 0):
        bonus += 0.07

    if flags.get("suspicious_structure", 0):
        bonus += 0.04

    if flags.get("punycode_domain", 0):
        bonus += 0.08

    if flags.get("has_ip_address", 0):
        bonus += 0.12

    if flags.get("shortener_domain", 0):
        bonus += 0.04

    if flags.get("shortener_domain", 0) and flags.get("digit_substitution_in_domain", 0):
        bonus += 0.06

    if flags.get("public_hosting_domain", 0) and flags.get("brand_in_domain", 0):
        bonus += 0.05

    if (
        flags.get("public_hosting_domain", 0)
        and flags.get("brand_in_domain", 0)
        and flags.get("path_has_login_like", 0)
    ):
        bonus += 0.15

    if flags.get("many_subdomains", 0) and flags.get("path_has_login_like", 0):
        bonus += 0.04

    if flags.get("many_hyphens", 0) and flags.get("brand_in_domain", 0):
        bonus += 0.04

    if flags.get("has_at_symbol", 0):
        bonus += 0.06

    if flags.get("many_encoded_chars", 0):
        bonus += 0.03

    if flags.get("generic_domain_with_phishing_path", 0):
        bonus += 0.08

    if flags.get("generic_suspicious_path", 0):
        bonus += 0.04

    if flags.get("redirect_like_parameter", 0):
        bonus += 0.04

    if flags.get("suspicious_file_path", 0):
        bonus += 0.05

    if flags.get("double_slash_path", 0):
        bonus += 0.03

    if flags.get("brand_in_path_only", 0):
        bonus += 0.04

    if flags.get("published_google_doc_path", 0):
        bonus += 0.18

    # =========================================================
    # Brand obfuscation / typo brand
    # =========================================================
    if flags.get("brand_obfuscation", 0):
        bonus += 0.10

    if flags.get("brand_obfuscation_plus_login", 0):
        bonus += 0.07

    if flags.get("brand_obfuscation_plus_suspicious_tld", 0):
        bonus += 0.07

    if flags.get("digit_substitution_in_domain", 0):
        bonus += 0.03

    # tokenized obfuscation
    if flags.get("brand_token_obfuscation", 0):
        bonus += 0.08

    if flags.get("brand_token_obfuscation_plus_login", 0):
        bonus += 0.06

    if flags.get("brand_token_obfuscation_plus_suspicious_word", 0):
        bonus += 0.06

    # =========================================================
    # Hyperlink / content signals
    # =========================================================
    page_signal_flags = [
        "has_password_input",
        "has_login_form",
        "login_like_title",
        "brand_title_mismatch",
        "external_form_action",
        "empty_form_action",
        "many_sensitive_inputs",
        "suspicious_submit_wording",
        "domain_title_mismatch",
        "content_topic_mismatch",
        "parked_or_placeholder_page",
        "redirected_to_other_domain",
        "redirected_to_random_path",
        "verification_page",
        "generic_verification_page",
        "empty_page",
        "very_low_content_page",
        "suspicious_challenge_page",
    ]

    page_signal_count = sum(1 for k in page_signal_flags if flags.get(k, 0))

    if page_signal_count >= 4:
        bonus += 0.12
    elif page_signal_count == 3:
        bonus += 0.09
    elif page_signal_count == 2:
        bonus += 0.05
    elif page_signal_count == 1:
        bonus += 0.02

    if flags.get("has_password_input", 0) and flags.get("brand_title_mismatch", 0):
        bonus += 0.10

    if flags.get("has_login_form", 0) and (
        flags.get("brand_title_mismatch", 0)
        or flags.get("domain_title_mismatch", 0)
    ):
        bonus += 0.08

    if flags.get("external_form_action", 0) and flags.get("has_password_input", 0):
        bonus += 0.10

    # =========================================================
    # Lexical signals
    # =========================================================
    if flags.get("lexical_suspicious_terms", 0):
        bonus += 0.02

    if flags.get("lexical_multiple_suspicious_terms", 0):
        bonus += 0.03

    if flags.get("lexical_brand_domain_mismatch", 0):
        bonus += 0.08

    if flags.get("lexical_brand_final_domain_mismatch", 0):
        bonus += 0.06

    if flags.get("lexical_brand_domain_mismatch", 0) and flags.get("lexical_suspicious_terms", 0):
        bonus += 0.05

    # =========================================================
    # Similarity
    # =========================================================
    if sim_reason not in {"exact_legitimate_domain", "legitimate_subdomain"}:
        if sim_ratio >= config.sim_high:
            bonus += 0.10
        elif sim_ratio >= config.sim_mid:
            bonus += 0.08
        elif sim_ratio >= config.sim_low:
            bonus += 0.05
        elif sim_ratio >= 0.75:
            bonus += 0.03

        if sim_ratio >= config.sim_low and flags.get("brand_in_domain", 0):
            bonus += 0.04

        if sim_ratio >= config.sim_low and flags.get("path_has_login_like", 0):
            bonus += 0.04

    # =========================================================
    # Strong impersonation combo
    # =========================================================
    if (
        sim_ratio >= config.sim_low
        and (
            flags.get("brand_obfuscation", 0)
            or flags.get("brand_token_obfuscation", 0)
            or flags.get("lexical_brand_domain_mismatch", 0)
        )
    ):
        bonus += 0.08

    if (
        sim_ratio >= config.sim_low
        and flags.get("redirected_to_other_domain", 0)
        and (
            flags.get("brand_title_mismatch", 0)
            or flags.get("content_topic_mismatch", 0)
            or flags.get("lexical_brand_domain_mismatch", 0)
        )
    ):
        bonus += 0.08

    # =========================================================
    # Generic phishing combo
    # =========================================================
    if (
        flags.get("generic_domain_with_phishing_path", 0)
        and flags.get("multiple_suspicious_words", 0)
        and flags.get("suspicious_tld", 0)
    ):
        bonus += 0.08

    if (
        flags.get("brand_in_path_only", 0)
        and flags.get("path_has_login_like", 0)
        and (
            flags.get("public_hosting_domain", 0)
            or flags.get("redirect_like_parameter", 0)
            or flags.get("suspicious_tld", 0)
        )
    ):
        bonus += 0.08

    if flags.get("published_google_doc_path", 0) and (
        flags.get("long_url", 0)
        or flags.get("very_long_url", 0)
        or flags.get("suspicious_structure", 0)
        or flags.get("shortener_domain", 0)
    ):
        bonus += 0.08

    # =========================================================
    # Fetch fail but URL highly suspicious
    # =========================================================
    if (
        flags.get("page_fetch_failed", 0)
        and (
            flags.get("brand_obfuscation", 0)
            or flags.get("brand_token_obfuscation", 0)
            or (
                flags.get("path_has_login_like", 0)
                and flags.get("multiple_suspicious_words", 0)
                and flags.get("suspicious_tld", 0)
            )
        )
    ):
        bonus += 0.05

    # =========================================================
    # Safe relief
    # =========================================================
    if sim_reason == "exact_legitimate_domain":
        penalty += 0.20

    if is_safe_brand_domain:
        penalty += 0.08
        if (
            not flags.get("suspicious_tld", 0)
            and not flags.get("multiple_suspicious_words", 0)
            and not flags.get("path_has_login_like", 0)
            and page_signal_count == 0
        ):
            penalty += 0.06

    if not flags.get("no_https", 0) and not flags.get("suspicious_structure", 0):
        penalty += 0.02

    # =========================================================
    # Final score
    # =========================================================
    bonus = min(bonus, config.bonus_cap)
    penalty = min(penalty, config.penalty_cap)

    final_score = score + bonus - penalty
    final_score = max(0.0, min(1.0, final_score))

    risk_percent = int(round(final_score * 100))

    # =========================================================
    # INTERNAL CLASSIFICATION
    # =========================================================
    if final_score >= config.phishing_threshold:
        raw_prediction = "phishing"
        raw_risk_level = "HIGH"
    elif final_score >= config.suspicious_threshold:
        raw_prediction = "suspicious"
        raw_risk_level = "MEDIUM"
    else:
        raw_prediction = "legitimate"
        raw_risk_level = "LOW"

    # =========================================================
    # FINAL OUTPUT MAPPING
    # legitimate -> non-phishing
    # suspicious -> phishing
    # phishing   -> phishing
    # =========================================================
    if raw_prediction == "legitimate":
        prediction = "non-phishing"
        risk_level = "NON-PHISHING"
    else:
        prediction = "phishing"
        risk_level = "PHISHING"

    return {
        "risk_score": round(final_score, 6),
        "risk_percent": risk_percent,

        # final output
        "prediction": prediction,
        "risk_level": risk_level,

        # internal classification
        "raw_prediction": raw_prediction,
        "raw_risk_level": raw_risk_level,

        "thresholds": {
            "suspicious_threshold": config.suspicious_threshold,
            "phishing_threshold": config.phishing_threshold,
        },
        "weights": {
            "wH": wH,
            "wB": wB,
            "wS": wS,
        },
        "debug": {
            "base_score": round(score, 6),
            "bonus": round(bonus, 6),
            "penalty": round(penalty, 6),
            "similarity_ratio": round(sim_ratio, 6),
            "similarity_reason": sim_reason,
            "page_signal_count": page_signal_count,
        },
    }
