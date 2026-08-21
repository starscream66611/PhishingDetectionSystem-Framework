from __future__ import annotations

import argparse
import csv
import math
import time
from pathlib import Path

import pandas as pd

from app.core.detection_config import DEFAULT_CONFIG
from app.core.url_utils import normalize_url, parse_url
from app.services.analyzer import analyze_url
from app.services.blacklist import BlacklistService
from app.services.heuristics import heuristic_analysis
from app.services.redirect_resolver import resolve_final_url, should_resolve_redirect
from app.services.risk import risk_score
from app.services.similarity import domain_similarity
from app.services.similarity import PRIORITY_BRANDS, _load_reference_domains


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EVAL_DIR = DATA_DIR / "detector_evaluation"

DEFAULT_DATASET = EVAL_DIR / "eval_dataset_balanced_750_750_direct.csv"
DEFAULT_DETAIL_OUTPUT = EVAL_DIR / "eval_results_balanced_750_750_direct_url_only.csv"
DEFAULT_SUMMARY_OUTPUT = EVAL_DIR / "eval_summary_balanced_750_750_direct_url_only.txt"


def _load_dataset(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset tidak ditemukan: {csv_path}")

    df = pd.read_csv(csv_path)
    columns = [str(col).strip() for col in df.columns]
    df.columns = columns

    if "URL" in df.columns and "label" in df.columns:
        clean = df[["URL", "label"]].copy()
        clean["URL"] = clean["URL"].astype(str).str.strip()
        clean["label"] = pd.to_numeric(clean["label"], errors="coerce")
        clean = clean.dropna(subset=["URL", "label"])
        return clean

    # Handle files like eval_legitimate.csv / eval_phishing.csv where the first row became the header.
    if len(df.columns) >= 2:
        first_url_col = df.columns[0]
        first_label_col = df.columns[1]

        rebuilt_rows: list[dict[str, object]] = []
        rebuilt_rows.append({"URL": first_url_col, "label": first_label_col})

        for _, row in df.iterrows():
            rebuilt_rows.append({"URL": row.iloc[0], "label": row.iloc[1]})

        clean = pd.DataFrame(rebuilt_rows)
        clean["URL"] = clean["URL"].astype(str).str.strip()
        clean["label"] = pd.to_numeric(clean["label"], errors="coerce")
        clean = clean.dropna(subset=["URL", "label"])
        return clean[["URL", "label"]]

    raise ValueError("Format dataset tidak dikenali. Butuh kolom URL dan label.")


def _binary_label(raw_label: object) -> str:
    try:
        value = int(float(raw_label))
    except Exception:
        text = str(raw_label).strip().lower()
        if text in {"1", "phishing", "malicious"}:
            return "phishing"
        return "legitimate"
    return "phishing" if value == 1 else "legitimate"


def _binary_prediction(prediction: str) -> str:
    return "phishing" if prediction == "phishing" else "legitimate"


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def _mcc(tp: int, tn: int, fp: int, fn: int) -> float:
    numerator = (tp * tn) - (fp * fn)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return numerator / denominator if denominator else 0.0


def _dataset_profile(dataset_path: Path) -> str:
    name = dataset_path.name.lower()
    if "direct" in name:
        return "direct_url"
    if "redirect" in name:
        return "redirect_heavy"
    return "mixed"


def _score_recommendation(metrics: dict[str, float], dataset_path: Path) -> tuple[str, list[str]]:
    accuracy = metrics["accuracy"]
    precision = metrics["precision"]
    recall = metrics["recall"]
    f1 = metrics["f1"]
    specificity = metrics["specificity"]
    balanced_accuracy = metrics["balanced_accuracy"]
    profile = _dataset_profile(dataset_path)

    notes: list[str] = []

    if min(accuracy, precision, recall, f1, balanced_accuracy) >= 0.90 and specificity >= 0.85:
        verdict = "Sangat kuat untuk skripsi dan cukup menarik untuk artikel ilmiah tingkat mahasiswa."
        notes.append("Performa inti sudah tinggi dan relatif seimbang antara mendeteksi phishing dan menahan false positive.")
    elif min(accuracy, precision, recall, f1) >= 0.80 and balanced_accuracy >= 0.80:
        verdict = "Sudah layak untuk skripsi, tetapi untuk artikel ilmiah kamu perlu analisis error dan pembandingan baseline yang rapi."
        notes.append("Metrik utama sudah baik, namun masih perlu pembahasan false positive dan false negative agar argumennya kuat.")
    else:
        verdict = "Belum cukup kuat untuk diklaim matang; masih layak sebagai eksperimen, tapi perlu tuning tambahan sebelum dijadikan hasil utama skripsi."
        notes.append("Minimal salah satu metrik inti masih rendah, jadi pembaca bisa mempertanyakan stabilitas model.")

    if recall < 0.70:
        notes.append("Recall phishing masih rendah; artinya masih ada phishing yang lolos.")
    elif recall < 0.85:
        notes.append("Recall phishing sudah cukup baik, tetapi masih ada sebagian phishing yang lolos.")

    if precision < 0.85:
        notes.append("Precision masih rendah; artinya false positive masih cukup banyak.")
    if specificity < 0.80:
        notes.append("Specificity legitimate masih rendah; website aman masih terlalu sering ditandai phishing.")
    if abs(recall - specificity) > 0.10 and profile != "direct_url":
        notes.append("Keseimbangan kelas belum stabil; tampilkan balanced accuracy dan confusion matrix di laporan.")
    elif profile == "direct_url" and balanced_accuracy >= 0.90:
        notes.append("Untuk skenario direct URL, balanced accuracy sudah kuat dan cocok dijadikan hasil utama skripsi.")

    if profile == "redirect_heavy":
        notes.append("Dataset ini didominasi shortener atau redirect, sehingga hasilnya lebih cocok dibaca sebagai stress-test tambahan.")
    elif profile == "mixed":
        notes.append("Dataset campuran berguna sebagai skenario tantangan tambahan, tetapi hasil direct URL lebih representatif untuk inti sistem.")

    return verdict, notes


def _write_summary(
    summary_path: Path,
    dataset_path: Path,
    rows: int,
    runtime_seconds: float,
    counters: dict[str, int],
    metrics: dict[str, float],
) -> None:
    verdict, notes = _score_recommendation(metrics, dataset_path)

    lines = [
        "EVALUATION SUMMARY",
        "=" * 72,
        f"Dataset           : {dataset_path}",
        f"Dataset profile    : {_dataset_profile(dataset_path)}",
        f"Rows evaluated    : {rows}",
        f"Runtime (seconds) : {runtime_seconds:.2f}",
        "",
        "CONFUSION MATRIX",
        "-" * 72,
        f"TP (phishing->phishing)     : {counters['tp']}",
        f"TN (legitimate->legitimate) : {counters['tn']}",
        f"FP (legitimate->phishing)   : {counters['fp']}",
        f"FN (phishing->legitimate)   : {counters['fn']}",
        "",
        "METRICS",
        "-" * 72,
        f"Accuracy          : {metrics['accuracy']:.4f} ({metrics['accuracy'] * 100:.2f}%)",
        f"Precision         : {metrics['precision']:.4f} ({metrics['precision'] * 100:.2f}%)",
        f"Recall            : {metrics['recall']:.4f} ({metrics['recall'] * 100:.2f}%)",
        f"Specificity       : {metrics['specificity']:.4f} ({metrics['specificity'] * 100:.2f}%)",
        f"F1-Score          : {metrics['f1']:.4f}",
        f"Balanced Accuracy : {metrics['balanced_accuracy']:.4f}",
        f"MCC               : {metrics['mcc']:.4f}",
        "",
        "ACADEMIC READINESS",
        "-" * 72,
        verdict,
        "",
        "NOTES",
        "-" * 72,
    ]

    for note in notes:
        lines.append(f"- {note}")

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate_dataset(
    csv_path: Path,
    output_csv: Path,
    summary_output: Path,
    mode: str = "full",
    reference_limit: int | None = None,
    limit: int | None = None,
    progress_every: int = 25,
    verbose: bool = False,
) -> dict:
    start_time = time.time()

    dataset = _load_dataset(csv_path)
    if limit is not None:
        dataset = dataset.head(limit)

    blacklist = BlacklistService(DATA_DIR)
    reference_domains = _load_reference_domains()
    if reference_limit is not None:
        priority_domains = list(dict.fromkeys(PRIORITY_BRANDS.values()))
        trimmed = reference_domains[:reference_limit]
        reference_domains = list(dict.fromkeys(priority_domains + trimmed))
    similarity_cache: dict[str, dict] = {}
    result_cache: dict[str, dict] = {}

    counters = {
        "tp": 0,
        "tn": 0,
        "fp": 0,
        "fn": 0,
    }
    rows = 0
    failures = 0

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with output_csv.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(
            f_out,
            fieldnames=[
                "url",
                "label",
                "prediction",
                "raw_prediction",
                "risk_level",
                "risk_score",
                "risk_percent",
                "hostname",
                "registered_domain",
                "blacklist_match_type",
                "blacklist_matched_value",
                "heuristic_url_score",
                "heuristic_link_score",
                "heuristic_lexical_score",
                "heuristic_total_score",
                "similarity_score",
                "similarity_ratio",
                "similarity_reason",
                "similarity_matched_domain",
                "active_flags",
                "error",
            ],
        )
        writer.writeheader()

        for _, row in dataset.iterrows():
            url = str(row["URL"]).strip()
            y_true = _binary_label(row["label"])

            if not url:
                continue

            try:
                normalized_url = normalize_url(url)
                if normalized_url in result_cache:
                    result = result_cache[normalized_url]
                elif mode in {"url_only", "url_plus_redirect"}:
                    parsed, host, path, registered_domain, punycode = parse_url(normalized_url)
                    analysis_url = normalized_url
                    redirect_resolution = {
                        "checked": False,
                        "resolved": False,
                        "original_url": normalized_url,
                        "final_url": normalized_url,
                        "analysis_target": "original_url",
                        "error": None,
                    }

                    if mode == "url_plus_redirect" and should_resolve_redirect(host, registered_domain):
                        redirect_resolution["checked"] = True
                        resolved = resolve_final_url(normalized_url)
                        redirect_resolution.update(resolved)
                        if resolved.get("resolved") and resolved.get("final_url"):
                            analysis_url = resolved["final_url"]
                            redirect_resolution["analysis_target"] = "resolved_url"
                            parsed, host, path, registered_domain, punycode = parse_url(analysis_url)

                    blacklist_info = blacklist.check(analysis_url, registered_domain)
                    heuristics = heuristic_analysis(
                        url=analysis_url,
                        host=host,
                        path=path,
                        scheme=(parsed.scheme or ""),
                    )
                    if host in similarity_cache:
                        similarity = similarity_cache[host]
                    else:
                        similarity = domain_similarity(host, reference_domains)
                        similarity_cache[host] = similarity

                    combined = risk_score(
                        H=float(heuristics.get("H", 0.0) or 0.0),
                        B=float(blacklist_info.get("B", 0.0) or 0.0),
                        S=float(similarity.get("S", 0.0) or 0.0),
                        blacklist=blacklist_info,
                        flags=heuristics.get("flags", {}),
                        similarity=similarity,
                        is_safe_brand_domain=heuristics.get("meta", {}).get("is_safe_brand_domain", False),
                        config=DEFAULT_CONFIG,
                    )

                    result = {
                        "input_normalized_url": normalized_url,
                        "normalized_url": analysis_url,
                        "hostname": host,
                        "registered_domain": registered_domain,
                        "is_punycode": punycode,
                        "path": path,
                        "redirect_resolution": redirect_resolution,
                        "blacklist": blacklist_info,
                        "heuristics": {
                            **heuristics,
                            "H_url": heuristics.get("H", 0.0),
                            "H_link": 0.0,
                            "H_lex": 0.0,
                            "H_total": heuristics.get("H", 0.0),
                            "flags": heuristics.get("flags", {}),
                        },
                        "similarity": similarity,
                        **combined,
                    }
                    result_cache[normalized_url] = result
                else:
                    result = analyze_url(
                        normalized_url=normalized_url,
                        blacklist_service=blacklist,
                        reference_domains=reference_domains,
                        config=DEFAULT_CONFIG,
                    )
                    result_cache[normalized_url] = result
                y_pred = _binary_prediction(result["prediction"])

                if y_true == "phishing" and y_pred == "phishing":
                    counters["tp"] += 1
                elif y_true == "legitimate" and y_pred == "legitimate":
                    counters["tn"] += 1
                elif y_true == "legitimate" and y_pred == "phishing":
                    counters["fp"] += 1
                elif y_true == "phishing" and y_pred == "legitimate":
                    counters["fn"] += 1

                heuristics = result.get("heuristics", {})
                similarity = result.get("similarity", {})
                blacklist_info = result.get("blacklist", {})
                active_flags = sorted(
                    key for key, value in heuristics.get("flags", {}).items() if value
                )

                writer.writerow(
                    {
                        "url": url,
                        "label": y_true,
                        "prediction": result["prediction"],
                        "raw_prediction": result.get("raw_prediction", ""),
                        "risk_level": result["risk_level"],
                        "risk_score": result["risk_score"],
                        "risk_percent": result["risk_percent"],
                        "hostname": result["hostname"],
                        "registered_domain": result["registered_domain"],
                        "blacklist_match_type": blacklist_info.get("match_type", ""),
                        "blacklist_matched_value": blacklist_info.get("matched_value", ""),
                        "heuristic_url_score": heuristics.get("H_url", ""),
                        "heuristic_link_score": heuristics.get("H_link", ""),
                        "heuristic_lexical_score": heuristics.get("H_lex", ""),
                        "heuristic_total_score": heuristics.get("H_total", ""),
                        "similarity_score": similarity.get("S", ""),
                        "similarity_ratio": similarity.get("ratio", ""),
                        "similarity_reason": similarity.get("reason", ""),
                        "similarity_matched_domain": similarity.get("matched_domain", ""),
                        "active_flags": ",".join(active_flags),
                        "error": "",
                    }
                )
                rows += 1

                if verbose:
                    print(
                        f"[{rows}] true={y_true:<10} pred={result['prediction']:<9} "
                        f"score={result['risk_score']:.4f} url={url}"
                    )
                elif rows % progress_every == 0:
                    elapsed = time.time() - start_time
                    print(f"Processed {rows} rows | elapsed={elapsed:.1f}s")

            except Exception as exc:
                failures += 1
                writer.writerow(
                    {
                        "url": url,
                        "label": y_true,
                        "prediction": "",
                        "raw_prediction": "",
                        "risk_level": "",
                        "risk_score": "",
                        "risk_percent": "",
                        "hostname": "",
                        "registered_domain": "",
                        "blacklist_match_type": "",
                        "blacklist_matched_value": "",
                        "heuristic_url_score": "",
                        "heuristic_link_score": "",
                        "heuristic_lexical_score": "",
                        "heuristic_total_score": "",
                        "similarity_score": "",
                        "similarity_ratio": "",
                        "similarity_reason": "",
                        "similarity_matched_domain": "",
                        "active_flags": "",
                        "error": str(exc),
                    }
                )
                print(f"[ERROR] {url} -> {exc}")

    total = max(rows, 1)
    metrics = {
        "accuracy": _safe_div(counters["tp"] + counters["tn"], total),
        "precision": _safe_div(counters["tp"], counters["tp"] + counters["fp"]),
        "recall": _safe_div(counters["tp"], counters["tp"] + counters["fn"]),
        "specificity": _safe_div(counters["tn"], counters["tn"] + counters["fp"]),
    }
    metrics["f1"] = _safe_div(
        2 * metrics["precision"] * metrics["recall"],
        metrics["precision"] + metrics["recall"],
    )
    metrics["balanced_accuracy"] = (metrics["recall"] + metrics["specificity"]) / 2
    metrics["mcc"] = _mcc(
        counters["tp"],
        counters["tn"],
        counters["fp"],
        counters["fn"],
    )

    runtime_seconds = time.time() - start_time
    _write_summary(
        summary_path=summary_output,
        dataset_path=csv_path,
        rows=rows,
        runtime_seconds=runtime_seconds,
        counters=counters,
        metrics=metrics,
    )

    print("\n" + "=" * 72)
    print("HASIL EVALUASI")
    print("=" * 72)
    print(f"Dataset           : {csv_path}")
    print(f"Mode              : {mode}")
    print(f"Reference domains : {len(reference_domains)}")
    print(f"Rows evaluated    : {rows}")
    print(f"Failures          : {failures}")
    print(f"TP                : {counters['tp']}")
    print(f"TN                : {counters['tn']}")
    print(f"FP                : {counters['fp']}")
    print(f"FN                : {counters['fn']}")
    print(f"Accuracy          : {metrics['accuracy']:.4f} ({metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision         : {metrics['precision']:.4f} ({metrics['precision'] * 100:.2f}%)")
    print(f"Recall            : {metrics['recall']:.4f} ({metrics['recall'] * 100:.2f}%)")
    print(f"Specificity       : {metrics['specificity']:.4f} ({metrics['specificity'] * 100:.2f}%)")
    print(f"F1-Score          : {metrics['f1']:.4f}")
    print(f"Balanced Accuracy : {metrics['balanced_accuracy']:.4f}")
    print(f"MCC               : {metrics['mcc']:.4f}")
    print(f"Detail CSV        : {output_csv}")
    print(f"Summary TXT       : {summary_output}")
    print(f"Runtime           : {runtime_seconds:.2f} seconds")

    verdict, notes = _score_recommendation(metrics, csv_path)
    print("\nInterpretasi:")
    print(verdict)
    for note in notes:
        print(f"- {note}")

    return {
        "rows": rows,
        "failures": failures,
        "mode": mode,
        "reference_domains": len(reference_domains),
        "counters": counters,
        "metrics": metrics,
        "detail_csv": str(output_csv),
        "summary_txt": str(summary_output),
        "runtime_seconds": runtime_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluasi performa sistem deteksi phishing dengan metrik skripsi."
    )
    parser.add_argument(
        "--csv",
        default=str(DEFAULT_DATASET),
        help="Path dataset CSV evaluasi.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_DETAIL_OUTPUT),
        help="Path output CSV detail hasil evaluasi.",
    )
    parser.add_argument(
        "--summary",
        default=str(DEFAULT_SUMMARY_OUTPUT),
        help="Path output TXT ringkasan metrik dan interpretasi.",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "url_only", "url_plus_redirect"],
        default="url_only",
        help="full = pakai semua layer termasuk fetch konten, url_only = hanya blacklist+heuristic+similarity URL, url_plus_redirect = url_only + resolve shortener/redirect.",
    )
    parser.add_argument(
        "--reference-limit",
        type=int,
        default=1000,
        help="Batasi jumlah reference domain untuk evaluasi lebih cepat tanpa mengubah sistem produksi.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Batasi jumlah baris untuk quick test.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=50,
        help="Cetak progress setiap N baris.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Tampilkan prediksi per baris.",
    )
    args = parser.parse_args()

    evaluate_dataset(
        csv_path=Path(args.csv),
        output_csv=Path(args.output),
        summary_output=Path(args.summary),
        mode=args.mode,
        reference_limit=args.reference_limit,
        limit=args.limit,
        progress_every=args.progress_every,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
