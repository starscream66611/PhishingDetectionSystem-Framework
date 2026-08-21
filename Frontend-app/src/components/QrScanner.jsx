import React, { useEffect, useRef, useState } from "react";
import { Html5Qrcode } from "html5-qrcode";

const API_BASE = "http://127.0.0.1:8000";

export default function QrScanner() {
  const scannerRef = useRef(null);
  const [isScanning, setIsScanning] = useState(false);
  const [decodedText, setDecodedText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    return () => {
      stopScan();
    };
  }, []);

  const startScan = async () => {
    setError("");
    setResult(null);
    setDecodedText("");

    const scanner = new Html5Qrcode("qr-reader");
    scannerRef.current = scanner;

    try {
      setIsScanning(true);

      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        async (text) => {
          setDecodedText(text);
          await stopScan();
          analyze(text);
        }
      );
    } catch (err) {
      setError("Gagal membuka kamera. Pastikan izin kamera diizinkan.");
      setIsScanning(false);
    }
  };

  const stopScan = async () => {
    if (!scannerRef.current) return;

    try {
      await scannerRef.current.stop();
      await scannerRef.current.clear();
    } catch (e) {}

    scannerRef.current = null;
    setIsScanning(false);
  };

  const analyze = async (text) => {
    try {
      const res = await fetch(`${API_BASE}/scan/qr`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ qr_content: text }),
      });

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError("Tidak bisa konek ke backend.");
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Scan QR Phishing Detector</h2>

      <button onClick={startScan} disabled={isScanning}>
        {isScanning ? "Scanning..." : "Mulai Scan"}
      </button>

      <div
        id="qr-reader"
        style={{ width: "300px", marginTop: "20px" }}
      ></div>

      {decodedText && (
        <div style={{ marginTop: 20 }}>
          <b>QR Result:</b>
          <div>{decodedText}</div>
        </div>
      )}

      {result && (
        <div style={{ marginTop: 20 }}>
          <h3>Analysis Result</h3>
          <p><b>Prediction:</b> {result.final.prediction}</p>
          <p><b>Risk Level:</b> {result.final.risk_level}</p>
          <p><b>Risk Percent:</b> {result.final.risk_percent}%</p>
        </div>
      )}

      {error && (
        <div style={{ color: "red", marginTop: 20 }}>
          {error}
        </div>
      )}
    </div>
  );
}