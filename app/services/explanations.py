from __future__ import annotations


def build_explanations(
    hostname: str,
    registered_domain: str,
    heuristics: dict,
    similarity: dict,
) -> list[str]:
    flags = heuristics.get("flags", {}) or {}
    features = heuristics.get("features", {}) or {}
    sim_reason = similarity.get("reason", "")
    matched_domain = similarity.get("matched_domain")
    matched_brand = similarity.get("matched_brand")
    sim_ratio = similarity.get("ratio", 0.0)

    explanations: list[str] = []

    # -----------------------------
    # Exact safe case
    # -----------------------------
    if sim_reason == "exact_legitimate_domain":
        explanations.append(
            "Domain yang diuji cocok langsung dengan domain legitimate pada reference list."
        )
        return explanations

    # -----------------------------
    # Brand impersonation / obfuscation
    # -----------------------------
    if flags.get("brand_obfuscation", 0):
        brand_name = features.get("brand_obfuscation_brand")
        if brand_name:
            explanations.append(
                f"Nama domain menunjukkan pola penyamaran brand '{brand_name}' melalui perubahan karakter atau typo."
            )
        else:
            explanations.append(
                "Nama domain menunjukkan pola penyamaran brand melalui perubahan karakter atau typo."
            )

    if flags.get("brand_token_obfuscation", 0):
        brand_name = features.get("brand_token_obfuscation_brand")
        if brand_name:
            explanations.append(
                f"Salah satu token pada hostname tampak meniru brand '{brand_name}' meskipun tidak menggunakan penulisan asli."
            )
        else:
            explanations.append(
                "Salah satu token pada hostname tampak meniru brand terkenal meskipun tidak menggunakan penulisan asli."
            )

    if flags.get("digit_substitution_in_domain", 0):
        explanations.append(
            "Domain memakai substitusi angka atau karakter khusus yang sering digunakan untuk menyamarkan nama brand."
        )

    # -----------------------------
    # Similarity
    # -----------------------------
    if matched_domain and sim_reason in {"similar_to_priority_brand_domain", "similar_to_reference_domain"}:
        if sim_reason == "similar_to_priority_brand_domain":
            explanations.append(
                f"Domain sangat mirip dengan domain resmi prioritas '{matched_domain}', yang mengindikasikan impersonasi brand."
            )
        elif sim_ratio and sim_ratio >= 0.75:
            explanations.append(
                f"Domain memiliki kemiripan tinggi dengan domain legitimate '{matched_domain}'."
            )

    # -----------------------------
    # URL structure
    # -----------------------------
    if flags.get("suspicious_tld", 0):
        explanations.append(
            "Registered domain menggunakan TLD yang sering muncul pada URL phishing."
        )

    if flags.get("brand_plus_suspicious_tld", 0):
        explanations.append(
            "Brand terkenal muncul bersama TLD yang tidak umum untuk domain resmi."
        )

    if flags.get("brand_plus_suspicious_word", 0):
        explanations.append(
            "Nama brand muncul bersama kata-kata sensitif seperti login, verify, secure, atau sejenisnya."
        )

    if flags.get("suspicious_words", 0):
        explanations.append(
            "URL mengandung kata-kata yang umum dipakai dalam skenario phishing."
        )

    if flags.get("multiple_suspicious_words", 0):
        explanations.append(
            "Terdapat beberapa kata sensitif dalam hostname atau path yang memperkuat indikasi phishing."
        )

    if flags.get("path_has_login_like", 0):
        explanations.append(
            "Path URL mengandung kata yang berkaitan dengan login atau verifikasi akun."
        )

    if flags.get("generic_domain_with_phishing_path", 0):
        explanations.append(
            "Domain terlihat generik, tetapi path mengarah ke pola login atau verifikasi yang mencurigakan."
        )

    if flags.get("generic_suspicious_path", 0):
        explanations.append(
            "Path URL terlihat generik namun mengandung parameter atau pola yang tidak wajar."
        )

    if flags.get("suspicious_structure", 0):
        explanations.append(
            "Struktur URL terlihat tidak wajar, misalnya terlalu kompleks atau memakai pola yang sering muncul pada phishing."
        )

    if flags.get("many_hyphens", 0):
        explanations.append(
            "Hostname memakai banyak tanda hubung, pola yang cukup sering muncul pada domain phishing."
        )

    if flags.get("many_subdomains", 0):
        explanations.append(
            "Hostname memiliki banyak subdomain, yang dapat digunakan untuk menyamarkan domain utama."
        )

    if flags.get("has_ip_address", 0):
        explanations.append(
            "URL menggunakan alamat IP langsung, bukan nama domain yang normal."
        )

    if flags.get("shortener_domain", 0):
        explanations.append(
            "URL menggunakan layanan pemendek tautan sehingga tujuan akhirnya tidak terlihat jelas."
        )

    if flags.get("public_hosting_domain", 0):
        explanations.append(
            "Domain memakai layanan public hosting yang cukup sering disalahgunakan untuk phishing."
        )

    if flags.get("punycode_domain", 0):
        explanations.append(
            "Domain mengandung pola punycode yang dapat dipakai untuk homograph attack."
        )

    if flags.get("has_at_symbol", 0):
        explanations.append(
            "URL mengandung karakter '@' yang sering dipakai untuk menyamarkan tujuan tautan."
        )

    if flags.get("many_encoded_chars", 0):
        explanations.append(
            "URL mengandung banyak karakter ter-encode yang dapat digunakan untuk menyamarkan isi tautan."
        )

    # -----------------------------
    # Hyperlink / content signals
    # -----------------------------
    if flags.get("has_login_form", 0):
        explanations.append(
            "Halaman memiliki form login yang meminta kredensial pengguna."
        )

    if flags.get("has_password_input", 0):
        explanations.append(
            "Halaman memiliki input password, yang meningkatkan risiko pencurian kredensial."
        )

    if flags.get("many_sensitive_inputs", 0):
        explanations.append(
            "Halaman meminta beberapa input sensitif sekaligus."
        )

    if flags.get("suspicious_submit_wording", 0):
        explanations.append(
            "Tombol atau form pada halaman menggunakan wording yang umum dipakai untuk memancing aksi pengguna."
        )

    if flags.get("login_like_title", 0):
        explanations.append(
            "Judul halaman menunjukkan konteks login, verifikasi, atau pemulihan akun."
        )

    if flags.get("brand_title_mismatch", 0):
        explanations.append(
            "Judul halaman menampilkan brand tertentu, tetapi domain yang diuji tidak sesuai dengan brand tersebut."
        )

    if flags.get("domain_title_mismatch", 0):
        explanations.append(
            "Judul halaman dan domain akhir tidak menunjukkan kecocokan identitas yang wajar."
        )

    if flags.get("content_topic_mismatch", 0):
        explanations.append(
            "Konten halaman membahas brand atau layanan tertentu, tetapi domainnya tidak sesuai."
        )

    if flags.get("external_form_action", 0):
        explanations.append(
            "Form pada halaman mengirim data ke domain lain, yang merupakan indikator phishing yang kuat."
        )

    if flags.get("empty_form_action", 0):
        explanations.append(
            "Form pada halaman memiliki action yang kosong atau tidak jelas."
        )

    if flags.get("redirected_to_other_domain", 0):
        explanations.append(
            "URL melakukan redirect ke domain lain, yang dapat mengindikasikan pengalihan mencurigakan."
        )

    if flags.get("redirected_to_random_path", 0):
        explanations.append(
            "URL mengarah ke path acak atau tidak lazim setelah redirect."
        )

    if flags.get("verification_page", 0):
        explanations.append(
            "Halaman menampilkan pola verifikasi yang sering dipakai pada phishing."
        )

    if flags.get("generic_verification_page", 0):
        explanations.append(
            "Halaman menunjukkan verifikasi generik yang sering digunakan untuk menipu pengguna."
        )

    if flags.get("suspicious_challenge_page", 0):
        explanations.append(
            "Halaman menampilkan challenge atau captcha yang tampak tidak wajar untuk konteks domain tersebut."
        )

    if flags.get("empty_page", 0):
        explanations.append(
            "Halaman hampir kosong, yang dapat menjadi indikasi landing page phishing yang belum lengkap."
        )

    if flags.get("very_low_content_page", 0):
        explanations.append(
            "Konten halaman sangat minim dan tidak memberikan konteks yang meyakinkan."
        )

    if flags.get("parked_or_placeholder_page", 0):
        explanations.append(
            "Halaman tampak seperti placeholder atau parked page, bukan layanan resmi yang aktif."
        )

    # -----------------------------
    # Fetch failure fallback
    # -----------------------------
    if flags.get("page_fetch_failed", 0):
        explanations.append(
            "Halaman tidak dapat diakses saat analisis dilakukan, sehingga penilaian terutama didasarkan pada pola URL."
        )

    if flags.get("lexical_fetch_failed", 0):
        explanations.append(
            "Analisis lexical halaman tidak dapat dilakukan karena konten tidak berhasil diambil."
        )

    # deduplicate sambil menjaga urutan
    cleaned: list[str] = []
    seen = set()
    for item in explanations:
        if item not in seen:
            cleaned.append(item)
            seen.add(item)

    if not cleaned:
        cleaned.append(
            "Tidak ditemukan indikator yang cukup kuat untuk memberikan penjelasan spesifik."
        )

    return cleaned