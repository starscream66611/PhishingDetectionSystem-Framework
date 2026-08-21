from __future__ import annotations

import csv
from itertools import product
from pathlib import Path

from app.core.detection_config import DetectionConfig
from app.main import blacklist_service, REFERENCE_DOMAINS
from app.services.analyzer import analyze_url


DATA_DIR = Path("data")
PHISH_CSV = DATA_DIR / "validation_phishing.csv"
LEGIT_CSV = DATA_DIR / "validation_legitimate.csv"
OUT_CSV = DATA_DIR / "tuning_results.csv"


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

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def evaluate_config(dataset: list[tuple[str, int]], cfg: DetectionConfig) -> dict:
    tp = tn = fp = fn = 0

    for url, actual in dataset:
        result = analyze_url(
            normalized_url=url,
            blacklist_service=blacklist_service,
            reference_domains=REFERENCE_DOMAINS,
            config=cfg,
        )

        predicted = 1 if result["prediction"] in {"phishing", "suspicious"} else 0

        if actual == 1 and predicted == 1:
            tp += 1
        elif actual == 0 and predicted == 0:
            tn += 1
        elif actual == 0 and predicted == 1:
            fp += 1
        else:
            fn += 1

    metrics = compute_metrics(tp, tn, fp, fn)
    metrics["tp"] = tp
    metrics["tn"] = tn
    metrics["fp"] = fp
    metrics["fn"] = fn
    return metrics


def main() -> None:
    phishing = load_urls(PHISH_CSV, 1)
    legitimate = load_urls(LEGIT_CSV, 0)
    dataset = phishing + legitimate

    weight_candidates = [
        (0.50, 0.25, 0.25),
        (0.45, 0.30, 0.25),
        (0.45, 0.25, 0.30),
        (0.40, 0.30, 0.30),
        (0.55, 0.20, 0.25),
        (0.35, 0.30, 0.35),
        (0.40, 0.25, 0.35),
    ]

    phishing_thresholds = [0.50, 0.55, 0.60, 0.65]
    suspicious_thresholds = [0.28, 0.30, 0.34, 0.38]

    sim_highs = [0.93, 0.95, 0.97]
    sim_mids = [0.88, 0.90, 0.92]
    sim_lows = [0.80, 0.84, 0.86]

    bonus_caps = [0.28, 0.30, 0.32]
    penalty_caps = [0.25, 0.28, 0.30]

    rows: list[dict] = []

    for (wH, wB, wS), pth, sth, sh, sm, sl, bcap, pcap in product(
        weight_candidates,
        phishing_thresholds,
        suspicious_thresholds,
        sim_highs,
        sim_mids,
        sim_lows,
        bonus_caps,
        penalty_caps,
    ):
        if round(wH + wB + wS, 10) != 1.0:
            continue
        if not (sl <= sm <= sh):
            continue
        if not (sth < pth):
            continue

        cfg = DetectionConfig(
            wH=wH,
            wB=wB,
            wS=wS,
            phishing_threshold=pth,
            suspicious_threshold=sth,
            sim_high=sh,
            sim_mid=sm,
            sim_low=sl,
            bonus_cap=bcap,
            penalty_cap=pcap,
        )

        metrics = evaluate_config(dataset, cfg)

        # objective: accuracy utama, lalu f1, recall, dan fpr rendah
        objective_score = (
            (metrics["accuracy"] * 0.50)
            + (metrics["f1"] * 0.25)
            + (metrics["recall"] * 0.20)
            + ((1.0 - metrics["fpr"]) * 0.05)
        )

        rows.append({
            "wH": wH,
            "wB": wB,
            "wS": wS,
            "phishing_threshold": pth,
            "suspicious_threshold": sth,
            "sim_high": sh,
            "sim_mid": sm,
            "sim_low": sl,
            "bonus_cap": bcap,
            "penalty_cap": pcap,
            "accuracy": round(metrics["accuracy"], 6),
            "precision": round(metrics["precision"], 6),
            "recall": round(metrics["recall"], 6),
            "f1": round(metrics["f1"], 6),
            "fpr": round(metrics["fpr"], 6),
            "tp": metrics["tp"],
            "tn": metrics["tn"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "objective_score": round(objective_score, 6),
        })

    rows.sort(key=lambda x: x["objective_score"], reverse=True)

    with open(OUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print("=== TOP 10 CONFIGS ===")
    for row in rows[:10]:
        print(row)


if __name__ == "__main__":
    main()