from __future__ import annotations

import io
import logging
from pathlib import Path

from tranco import Tranco

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from PIL import Image
from pyzbar.pyzbar import decode

from app.core.url_utils import normalize_url
from app.models.schemas import URLRequest, QRContentRequest
from app.services.analyzer import analyze_url
from app.services.blacklist import BlacklistService


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
LOGGER = logging.getLogger(__name__)

REFERENCE_SOURCE = "local"
BLACKLIST_SOURCE = "local"


app = FastAPI(
    title="Phishing Detector API (Training-free)",
    description="Layered detection: blacklist + hyperlink + heuristics + domain similarity -> risk percentage",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "API running. Go to /docs",
        "final_output_classes": [
            "non-phishing",
            "phishing",
        ],
        "internal_risk_mapping": {
            "LOW": {
                "raw_prediction": "legitimate",
                "final_prediction": "non-phishing",
            },
            "MEDIUM": {
                "raw_prediction": "suspicious",
                "final_prediction": "phishing",
            },
            "HIGH": {
                "raw_prediction": "phishing",
                "final_prediction": "phishing",
            },
        },
        "scan_endpoints": [
            "/scan/url",
            "/scan/qr",
            "/scan/qr-image",
        ],
    }


def _build_scan_response(result: dict, *, input_value: str, qr_text: str | None = None) -> dict:
    response = {
        "input_normalized_url": result.get("input_normalized_url", result["normalized_url"]),
        "normalized_url": result["normalized_url"],
        "final": {
            "prediction": result["prediction"],
            "risk_level": result["risk_level"],
            "risk_percent": result["risk_percent"],
            "risk_score": result["risk_score"],
        },
        "internal": {
            "prediction": result["raw_prediction"],
            "risk_level": result["raw_risk_level"],
            "mapping_note": "legitimate -> non-phishing, suspicious -> phishing, phishing -> phishing",
        },
        "details": {
            "redirect_resolution": result.get("redirect_resolution", {}),
            "blacklist": result["blacklist"],
            "heuristics": result["heuristics"],
            "similarity": result["similarity"],
            "explanations": result["explanations"],
            "weights": result["weights"],
            "debug": result["debug"],
        },
    }

    if qr_text is not None:
        response["input_qr_text"] = qr_text
    else:
        response["input"] = input_value
        response["hostname"] = result["hostname"]
        response["registered_domain"] = result["registered_domain"]
        response["is_punycode"] = result["is_punycode"]
        response["path"] = result["path"]

    return response


def load_reference_domains(top_n: int = 10000) -> list[str]:
    global REFERENCE_SOURCE

    local_path = DATA_DIR / "reference_domains.txt"

    try:
        LOGGER.info("Loading latest Tranco reference domains.")
        t = Tranco(cache=True, cache_dir=str(DATA_DIR / ".tranco_cache"))
        latest_list = t.list()
        domains = latest_list.top(top_n)
        domains = [d.strip().lower() for d in domains if d and d.strip()]

        if len(domains) < 100:
            raise RuntimeError("Tranco returned too few domains (sanity check failed).")

        REFERENCE_SOURCE = "online"
        LOGGER.info("Loaded %s reference domains from Tranco.", len(domains))
        return domains

    except Exception as exc:
        LOGGER.warning("Failed to load Tranco online; falling back to local references: %s", exc)

    if local_path.exists():
        domains: list[str] = []
        with open(local_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.append(line)

        REFERENCE_SOURCE = "local"
        LOGGER.info("Loaded %s reference domains from the local cache.", len(domains))
        return domains

    REFERENCE_SOURCE = "builtin"
    return [
        "google.com",
        "facebook.com",
        "instagram.com",
        "microsoft.com",
        "apple.com",
        "paypal.com",
        "binus.ac.id",
    ]


blacklist = BlacklistService()
BLACKLIST_SOURCE = "folder:blacklist"

REFERENCE_DOMAINS = load_reference_domains(top_n=10000)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "message": "API running",
        "reference_source": REFERENCE_SOURCE,
        "blacklist_source": BLACKLIST_SOURCE,
        "reference_count": len(REFERENCE_DOMAINS),
        "blacklist_count": len(blacklist.items),
        "blacklist_domain_count": len(blacklist.domain_index),
    }


@app.post("/scan/url")
def scan_url(request: URLRequest):
    try:
        normalized = normalize_url(request.url)
        result = analyze_url(
            normalized_url=normalized,
            blacklist_service=blacklist,
            reference_domains=REFERENCE_DOMAINS,
        )
        return _build_scan_response(result, input_value=request.url)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        LOGGER.exception("Unexpected error while scanning URL.")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@app.post("/scan/qr")
def scan_qr_content(request: QRContentRequest):
    content = (request.qr_content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="QR content kosong")

    try:
        normalized = normalize_url(content)
        result = analyze_url(
            normalized_url=normalized,
            blacklist_service=blacklist,
            reference_domains=REFERENCE_DOMAINS,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="QR tidak berisi URL yang valid")
    except Exception as e:
        LOGGER.exception("Unexpected error while scanning QR content.")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

    return _build_scan_response(result, input_value=content)


@app.post("/scan/qr-image")
async def scan_qr_image(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="File kosong")

    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        raise HTTPException(status_code=400, detail="File bukan gambar valid")

    decoded = decode(img)
    if not decoded:
        raise HTTPException(status_code=400, detail="QR tidak terbaca / tidak ada data")

    qr_text = decoded[0].data.decode("utf-8", errors="ignore").strip()

    try:
        normalized = normalize_url(qr_text)
        result = analyze_url(
            normalized_url=normalized,
            blacklist_service=blacklist,
            reference_domains=REFERENCE_DOMAINS,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="QR tidak berisi URL valid")
    except Exception as e:
        LOGGER.exception("Unexpected error while scanning QR image.")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

    return _build_scan_response(result, input_value=qr_text, qr_text=qr_text)
