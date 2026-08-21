from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode
import csv
import html
import re

LOGGER = logging.getLogger(__name__)


class BlacklistService:
    def __init__(self, data_dir: str | Path | None = None) -> None:
        if data_dir is None:
            self.data_dir = Path(__file__).resolve().parents[2] / "data"
        else:
            self.data_dir = Path(data_dir)

        self.blacklist_dir = self.data_dir / "blacklist"
        self.blacklist_files = [
            self.blacklist_dir / "phishtank.csv",
            self.blacklist_dir / "openphish.txt",
        ]

        # kompatibel dengan main.py
        self.items: set[str] = set()
        self.domain_index: dict[str, set[str]] = {}

        # index utama
        self.exact_urls: set[str] = set()
        self.host_paths: set[tuple[str, str]] = set()

        self._load()

    def _normalize_input_url(self, url: str) -> str:
        url = html.unescape((url or "").strip())

        if not url:
            return ""

        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url

        parsed = urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "https"
        host = parsed.netloc.lower().strip()
        path = parsed.path or "/"

        if "@" in host:
            host = host.split("@")[-1]

        if ":" in host:
            host = host.split(":")[0]

        host = re.sub(r"^www\d*\.", "", host)
        host = host.strip(".")

        path = re.sub(r"/{2,}", "/", path).strip()
        if not path.startswith("/"):
            path = "/" + path
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query_pairs = sorted(query_pairs)
        query = urlencode(query_pairs, doseq=True)

        normalized = f"{scheme}://{host}{path}"
        if query:
            normalized += f"?{query}"

        return normalized

    def _normalize_host(self, host: str) -> str:
        host = html.unescape((host or "").strip().lower())

        if "@" in host:
            host = host.split("@")[-1]

        if ":" in host:
            host = host.split(":")[0]

        host = re.sub(r"^www\d*\.", "", host)
        host = host.strip(".")

        return host

    def _host_path_from_url(self, url: str) -> tuple[str, str]:
        parsed = urlparse(url)
        host = self._normalize_host(parsed.netloc)
        path = parsed.path or "/"
        path = re.sub(r"/{2,}", "/", path).strip()

        if not path.startswith("/"):
            path = "/" + path
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        return host, path

    def _extract_url_field_from_csv_row(self, row: dict) -> str | None:
        # prioritas nama kolom umum
        candidate_keys = [
            "url",
            "phish_url",
            "phishurl",
            "URI",
            "uri",
        ]

        for key in candidate_keys:
            if key in row and row[key]:
                value = str(row[key]).strip()
                if value.startswith("http://") or value.startswith("https://"):
                    return value

        # fallback: ambil field pertama yang terlihat seperti URL
        for _, value in row.items():
            if not value:
                continue
            value = str(value).strip()
            if value.startswith("http://") or value.startswith("https://"):
                return value

        return None

    def _register_url(
        self,
        normalized_url: str,
        items: set[str],
        exact_urls: set[str],
        host_paths: set[tuple[str, str]],
        domain_index: dict[str, set[str]],
    ) -> None:
        items.add(normalized_url)
        exact_urls.add(normalized_url)

        host, path = self._host_path_from_url(normalized_url)
        if path == "/":
            return

        if host and path:
            host_paths.add((host, path))
            domain_index.setdefault(host, set()).add(normalized_url)

    def _load(self) -> None:
        exact_urls: set[str] = set()
        host_paths: set[tuple[str, str]] = set()
        items: set[str] = set()
        domain_index: dict[str, set[str]] = {}

        LOGGER.info("Loading blacklist sources: %s", [str(p) for p in self.blacklist_files])

        for file_path in self.blacklist_files:
            if not file_path.exists():
                LOGGER.warning("Blacklist file not found: %s", file_path)
                continue

            suffix = file_path.suffix.lower()

            try:
                if suffix == ".csv":
                    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
                        reader = csv.DictReader(f)
                        row_count = 0
                        loaded_count = 0

                        for row in reader:
                            row_count += 1
                            raw_url = self._extract_url_field_from_csv_row(row)
                            if not raw_url:
                                continue

                            norm_url = self._normalize_input_url(raw_url)
                            if not norm_url:
                                continue

                            loaded_count += 1
                            self._register_url(norm_url, items, exact_urls, host_paths, domain_index)

                        LOGGER.info("Loaded CSV blacklist %s: rows=%s, urls=%s", file_path.name, row_count, loaded_count)

                else:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        row_count = 0
                        loaded_count = 0

                        for line in f:
                            row_count += 1
                            raw_url = line.strip()
                            if not raw_url or raw_url.startswith("#"):
                                continue

                            norm_url = self._normalize_input_url(raw_url)
                            if not norm_url:
                                continue

                            loaded_count += 1
                            self._register_url(norm_url, items, exact_urls, host_paths, domain_index)

                        LOGGER.info("Loaded TXT blacklist %s: rows=%s, urls=%s", file_path.name, row_count, loaded_count)

            except Exception:
                LOGGER.exception("Failed loading blacklist file %s", file_path)

        self.items = items
        self.domain_index = domain_index
        self.exact_urls = exact_urls
        self.host_paths = host_paths

        LOGGER.info(
            "Blacklist ready: exact_urls=%s, host_paths=%s, hosts=%s",
            len(self.items),
            len(self.host_paths),
            len(self.domain_index),
        )

    def reload(self) -> None:
        self._load()

    def check(self, url: str, host: str | None = None) -> dict:
        """
        Rule:
        1. exact full URL match -> B = 1
        2. exact host + path match -> B = 1
        3. host/domain saja -> TIDAK dipakai
        """
        normalized_url = self._normalize_input_url(url)

        if not normalized_url:
            return {
                "B": 0,
                "match_type": "none",
                "matched_value": None,
            }

        # 1) exact full URL
        if normalized_url in self.exact_urls:
            return {
                "B": 1,
                "match_type": "exact_url",
                "matched_value": normalized_url,
            }

        # 2) exact host + path
        normalized_host, path = self._host_path_from_url(normalized_url)
        if (normalized_host, path) in self.host_paths:
            return {
                "B": 1,
                "match_type": "host_path",
                "matched_value": f"{normalized_host}{path}",
            }

        # 3) host saja tetap dicatat sebagai sinyal informasi, tapi tidak override keputusan
        if normalized_host in self.domain_index:
            return {
                "B": 0,
                "match_type": "host_only",
                "matched_value": normalized_host,
            }

        # 4) jangan match domain induk/registered domain saja
        return {
            "B": 0,
            "match_type": "none",
            "matched_value": None,
        }
