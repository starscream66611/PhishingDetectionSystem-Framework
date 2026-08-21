from __future__ import annotations

import csv
import time
from pathlib import Path

from app.core.detection_config import DEFAULT_CONFIG
from app.main import blacklist_service, REFERENCE_DOMAINS
from app.services.analyzer import analyze_url


DATA_DIR = Path("data")
PHISH_CSV = DATA_DIR / "eval_phishing.csv"
LEGIT_CSV = DATA_DIR / "eval_legitimate.csv"
OUT_CSV = DATA_DIR / "eval_results.csv"


def load_urls(path: Path, label: int) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            url = row[0].strip()
            if not url:
                continue
            if url.lower() == "url":
                continue
            rows.append((url, label))
    return rows


def compute_metrics(tp: int, tn: int, fp: int, fn: int) -> dict:
    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    tpr = recall
    tnr = tn / (tn + fp) if (tn + fp) else 0.0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "tpr": tpr,
        "tnr": tnr,
    }


def main() -> None:
    phishing = load_urls(PHISH_CSV, 1)
    legitimate = load_urls(LEGIT_CSV, 0)
    dataset = phishing + legitimate

    tp = tn = fp = fn = 0
    total_time_ms = 0.0

    with open(OUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "url",
            "actual_label",
            "predicted_label",
            "prediction_name",
            "risk_score",
            "risk_percent",
            "risk_level",
            "response_ms",
        ])

        for url, actual in dataset:
            start = time.perf_counter()

            result = analyze_url(
                normalized_url=url,
                blacklist_service=blacklist_service,
                reference_domains=REFERENCE_DOMAINS,
                config=DEFAULT_CONFIG,
            )

            elapsed_ms = (time.perf_counter() - start) * 1000.0
            total_time_ms += elapsed_ms

            predicted = 1 if result["prediction"] in {"phishing", "suspicious"} else 0

            if actual == 1 and predicted == 1:
                tp += 1
            elif actual == 0 and predicted == 0:
                tn += 1
            elif actual == 0 and predicted == 1:
                fp += 1
            elif actual == 1 and predicted == 0:
                fn += 1

            writer.writerow([
                url,
                actual,
                predicted,
                result["prediction"],
                result["risk_score"],
                result["risk_percent"],
                result["risk_level"],
                round(elapsed_ms, 3),
            ])

    metrics = compute_metrics(tp, tn, fp, fn)
    avg_response_ms = total_time_ms / len(dataset) if dataset else 0.0

    print("=== FINAL EVALUATION ===")
    print(f"TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall   : {metrics['recall']:.4f}")
    print(f"F1 Score : {metrics['f1']:.4f}")
    print(f"TPR      : {metrics['tpr']:.4f}")
    print(f"TNR      : {metrics['tnr']:.4f}")
    print(f"FPR      : {metrics['fpr']:.4f}")
    print(f"FNR      : {metrics['fnr']:.4f}")
    print(f"Avg Resp : {avg_response_ms:.3f} ms")


if __name__ == "__main__":
    main()