from __future__ import annotations

import argparse
import csv
import os
import statistics
import threading
import time
from pathlib import Path

import pandas as pd
import psutil

from app.core.url_utils import normalize_url
from app.services.analyzer import analyze_url
from app.services.blacklist import BlacklistService
from app.services.similarity import PRIORITY_BRANDS, _load_reference_domains

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DATASET = DATA_DIR / "detector_evaluation" / "eval_dataset_balanced_500_500_direct.csv"
RESULT_DIR = DATA_DIR / "benchmark_results"


def load_urls(path: Path, limit: int | None = None) -> list[str]:
    df = pd.read_csv(path)
    url_col = next((c for c in df.columns if c.strip().lower() == "url"), None)
    if url_col is None:
        raise ValueError(f"Kolom URL tidak ditemukan. Kolom tersedia: {list(df.columns)}")
    urls = [str(v).strip() for v in df[url_col].dropna().tolist() if str(v).strip()]
    return urls[:limit] if limit else urls


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark CPU, RAM, and latency phishing detector")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--limit", type=int, default=None, help="Batasi jumlah URL, mis. 100 atau 500")
    parser.add_argument("--sample-interval", type=float, default=0.10, help="Interval sampling resource dalam detik")
    parser.add_argument("--reference-limit", type=int, default=None, help="Opsional: batasi domain referensi")
    args = parser.parse_args()

    urls = load_urls(args.dataset, args.limit)
    if not urls:
        raise SystemExit("Dataset kosong")

    blacklist = BlacklistService(DATA_DIR)
    reference_domains = _load_reference_domains()
    if args.reference_limit:
        priority = list(dict.fromkeys(PRIORITY_BRANDS.values()))
        reference_domains = list(dict.fromkeys(priority + reference_domains[:args.reference_limit]))

    process = psutil.Process(os.getpid())
    logical_cpus = psutil.cpu_count(logical=True) or 1

    cpu_raw_samples: list[float] = []
    rss_mb_samples: list[float] = []
    stop_event = threading.Event()

    # Prime psutil's CPU counter.
    process.cpu_percent(interval=None)

    def sampler() -> None:
        while not stop_event.is_set():
            cpu_raw_samples.append(process.cpu_percent(interval=None))
            rss_mb_samples.append(process.memory_info().rss / (1024 * 1024))
            stop_event.wait(args.sample_interval)

    latencies_ms: list[float] = []
    successes = 0
    failures = 0

    monitor = threading.Thread(target=sampler, daemon=True)
    monitor.start()
    start_wall = time.perf_counter()

    for i, url in enumerate(urls, start=1):
        t0 = time.perf_counter()
        try:
            normalized = normalize_url(url)
            analyze_url(
                normalized_url=normalized,
                blacklist_service=blacklist,
                reference_domains=reference_domains,
            )
            successes += 1
        except Exception:
            failures += 1
        finally:
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        if i % 50 == 0 or i == len(urls):
            print(f"Progress: {i}/{len(urls)}")

    total_seconds = time.perf_counter() - start_wall
    stop_event.set()
    monitor.join(timeout=max(1.0, args.sample_interval * 2))

    # One final sample so short runs still have data.
    cpu_raw_samples.append(process.cpu_percent(interval=None))
    rss_mb_samples.append(process.memory_info().rss / (1024 * 1024))

    cpu_normalized = [x / logical_cpus for x in cpu_raw_samples]
    throughput = len(urls) / total_seconds if total_seconds else 0.0

    metrics = {
        "dataset": str(args.dataset),
        "urls": len(urls),
        "successes": successes,
        "failures": failures,
        "logical_cpus": logical_cpus,
        "runtime_seconds": total_seconds,
        "throughput_urls_per_second": throughput,
        "latency_avg_ms": statistics.mean(latencies_ms) if latencies_ms else 0.0,
        "latency_median_ms": statistics.median(latencies_ms) if latencies_ms else 0.0,
        "latency_p95_ms": percentile(latencies_ms, 0.95),
        "latency_max_ms": max(latencies_ms) if latencies_ms else 0.0,
        "process_cpu_avg_percent_raw": statistics.mean(cpu_raw_samples) if cpu_raw_samples else 0.0,
        "process_cpu_peak_percent_raw": max(cpu_raw_samples) if cpu_raw_samples else 0.0,
        "process_cpu_avg_percent_normalized": statistics.mean(cpu_normalized) if cpu_normalized else 0.0,
        "process_cpu_peak_percent_normalized": max(cpu_normalized) if cpu_normalized else 0.0,
        "memory_avg_mb": statistics.mean(rss_mb_samples) if rss_mb_samples else 0.0,
        "memory_peak_mb": max(rss_mb_samples) if rss_mb_samples else 0.0,
    }

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    summary_path = RESULT_DIR / f"benchmark_summary_{stamp}.txt"
    samples_path = RESULT_DIR / f"benchmark_resource_samples_{stamp}.csv"

    with samples_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sample_no", "process_cpu_percent_raw", "process_cpu_percent_normalized", "memory_rss_mb"])
        for idx, (raw, norm, mem) in enumerate(zip(cpu_raw_samples, cpu_normalized, rss_mb_samples), start=1):
            writer.writerow([idx, round(raw, 3), round(norm, 3), round(mem, 3)])

    lines = [
        "SYSTEM RESOURCE BENCHMARK",
        "=" * 64,
        f"Dataset                       : {metrics['dataset']}",
        f"URLs tested                   : {metrics['urls']}",
        f"Successful                    : {metrics['successes']}",
        f"Failed                        : {metrics['failures']}",
        f"Logical CPU cores             : {metrics['logical_cpus']}",
        f"Total runtime                 : {metrics['runtime_seconds']:.3f} s",
        f"Throughput                    : {metrics['throughput_urls_per_second']:.3f} URL/s",
        "",
        "LATENCY",
        "-" * 64,
        f"Average                       : {metrics['latency_avg_ms']:.3f} ms",
        f"Median                        : {metrics['latency_median_ms']:.3f} ms",
        f"P95                           : {metrics['latency_p95_ms']:.3f} ms",
        f"Maximum                       : {metrics['latency_max_ms']:.3f} ms",
        "",
        "PROCESS CPU",
        "-" * 64,
        f"Average (raw psutil)          : {metrics['process_cpu_avg_percent_raw']:.2f}%",
        f"Peak (raw psutil)             : {metrics['process_cpu_peak_percent_raw']:.2f}%",
        f"Average (0-100 normalized)    : {metrics['process_cpu_avg_percent_normalized']:.2f}%",
        f"Peak (0-100 normalized)       : {metrics['process_cpu_peak_percent_normalized']:.2f}%",
        "",
        "MEMORY (RSS)",
        "-" * 64,
        f"Average                       : {metrics['memory_avg_mb']:.2f} MB",
        f"Peak                          : {metrics['memory_peak_mb']:.2f} MB",
        "",
        "Notes:",
        "- Raw process CPU can exceed 100% when the process uses multiple logical CPU cores.",
        "- Normalized CPU divides raw process CPU by the number of logical CPU cores.",
        f"- Resource sampling interval: {args.sample_interval:.2f} seconds.",
    ]
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n" + "\n".join(lines))
    print(f"\nSummary saved : {summary_path}")
    print(f"Samples saved : {samples_path}")


if __name__ == "__main__":
    main()
