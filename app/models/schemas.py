from pydantic import BaseModel, Field


class URLRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com/login"])


class QRContentRequest(BaseModel):
    # For February scope: frontend can decode QR and send extracted content.
    # If the content is a URL, the backend analyzes it with the same pipeline.
    qr_content: str = Field(..., examples=["https://example.com"])


class ScanResponse(BaseModel):
    input: str
    normalized_url: str
    prediction: str
    risk_score: float
    risk_percent: int
    risk_level: str
    details: dict
