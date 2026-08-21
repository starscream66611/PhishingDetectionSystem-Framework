import time
import statistics
import requests
import psutil

API_URL = "http://127.0.0.1:8000/scan/url"

TEST_URLS = [
    "https://google.com",
    "https://facebook.com",
    "https://youtube.com",
    "https://github.com",
    "https://binus.ac.id",
    "http://paypal-login-security-check.com",
    "http://192.168.1.1/login",
    "http://secure-account-verification-update.com",
    "https://www.microsoft.com",
    "https://www.instagram.com",
] * 10


def find_fastapi_process():
    candidates = []

    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (p.info["name"] or "").lower()
            cmdline_list = p.info["cmdline"] or []
            cmdline = " ".join(cmdline_list).lower()

            if "python" in name and (
                "uvicorn" in cmdline
                or "app.main:app" in cmdline
                or "app.main" in cmdline
            ):
                candidates.append(p)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not candidates:
        return None

    print("\nDetected Python/Uvicorn processes:")
    for i, p in enumerate(candidates):
        try:
            print(f"{i+1}. PID={p.pid} | CMD={' '.join(p.cmdline())}")
        except Exception:
            print(f"{i+1}. PID={p.pid}")

    if len(candidates) == 1:
        return candidates[0]

    choice = input("\nPilih nomor proses FastAPI yang benar: ")
    try:
        return candidates[int(choice) - 1]
    except Exception:
        print("Pilihan tidak valid, memakai proses pertama.")
        return candidates[0]


def main():
    print("=== QUICK BACKEND BENCHMARK ===")
    print("Pastikan backend sudah jalan di terminal lain:")
    print("uvicorn app.main:app --reload")

    process = find_fastapi_process()

    if process:
        print(f"\nUsing FastAPI PID: {process.pid}")
        process.cpu_percent(interval=None)
    else:
        print("\nFastAPI PID tidak terdeteksi. CPU/RAM tidak akan dihitung.")

    latencies = []
    status_codes = []
    cpu_values = []
    memory_values = []

    print("\nRunning benchmark...")

    start_total = time.perf_counter()

    for test_url in TEST_URLS:
        start = time.perf_counter()

        try:
            response = requests.post(API_URL, json={"url": test_url}, timeout=15)
            status_codes.append(response.status_code)
        except Exception as e:
            print("\nERROR request gagal.")
            print("Pastikan endpoint benar:", API_URL)
            print("Detail:", e)
            return

        end = time.perf_counter()
        latencies.append((end - start) * 1000)

        if process:
            try:
                cpu_values.append(process.cpu_percent(interval=0.1))
                memory_values.append(process.memory_info().rss / (1024 * 1024))
            except Exception:
                pass

    end_total = time.perf_counter()
    total_time = end_total - start_total

    avg_latency = statistics.mean(latencies)
    throughput = len(TEST_URLS) / total_time

    print("\n=== RESULT ===")
    print(f"Total requests          : {len(TEST_URLS)}")
    print(f"Successful responses    : {sum(1 for s in status_codes if 200 <= s < 300)}")
    print(f"Total time              : {total_time:.2f} seconds")
    print(f"Throughput              : {throughput:.2f} requests/second")
    print(f"Average response time   : {avg_latency:.2f} ms")
    print(f"Minimum response time   : {min(latencies):.2f} ms")
    print(f"Maximum response time   : {max(latencies):.2f} ms")

    if cpu_values:
        print(f"Average CPU usage       : {statistics.mean(cpu_values):.2f}%")
        print(f"Maximum CPU usage       : {max(cpu_values):.2f}%")
    else:
        print("Average CPU usage       : not detected")

    if memory_values:
        print(f"Average memory usage    : {statistics.mean(memory_values):.2f} MB")
        print(f"Maximum memory usage    : {max(memory_values):.2f} MB")
    else:
        print("Average memory usage    : not detected")

    print("\nKalimat untuk paper:")
    print(
        f"The runtime benchmark was conducted using {len(TEST_URLS)} URL requests. "
        f"The system achieved an average response time of {avg_latency:.2f} ms, "
        f"throughput of {throughput:.2f} requests per second, "
        f"average CPU usage of {statistics.mean(cpu_values):.2f}% and "
        f"average memory usage of {statistics.mean(memory_values):.2f} MB."
        if cpu_values and memory_values
        else
        f"The runtime benchmark was conducted using {len(TEST_URLS)} URL requests. "
        f"The system achieved an average response time of {avg_latency:.2f} ms "
        f"and throughput of {throughput:.2f} requests per second."
    )


if __name__ == "__main__":
    main()