# Backend (FastAPI) — Training-free Phishing Detector

This backend implements the layered detection model from your approved proposal:
- **Blacklist verification (B)**
- **Heuristic URL analysis (H)**
- **Domain similarity check (S)**

Final risk score follows:
`RiskScore = w1*H + w2*B + w3*S` and is normalized to **0–100%**.

## Quick start

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open docs:
- http://127.0.0.1:8000/docs

## Endpoints
- `GET /health`
- `POST /scan/url`  `{ "url": "https://..." }`
- `POST /scan/qr`   `{ "qr_content": "https://..." }` (frontend decodes QR, backend analyzes)

## Where to put blacklist
Put offline blacklist entries in `data/blacklist.txt` (domain or full URL, one per line).

## Notes for February timeline
Focus on making the **core detection engine** stable first. UI can be minimal.
