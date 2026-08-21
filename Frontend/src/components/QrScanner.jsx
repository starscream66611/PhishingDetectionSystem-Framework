import React, { useEffect, useRef, useState } from "react";
import { Html5Qrcode } from "html5-qrcode";

// Ganti kalau backend kamu beda host/port
const API_BASE = "http://127.0.0.1:8000";

export default function QrScanner() {
  const scannerRef = useRef(null);
  const [isScanning, setIsScanning] = useState(false);
  const [decodedText, setDecodedText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  // Pastikan scanner stop saat komponen unmount
  useEffect(() => {
    return () => {
      stopScan();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startScan = async () => {
    setError("");
    setResult(null);
    setDecodedText("");

    try {
      // id element untuk tempat render kamera
      const scanner = new Html5Qrcode("qr-reader");
      scannerRef.current = scanner;

      setIsScanning(true);

      await scanner.start(
        { facingMode: "environment" }, // kamera belakang
        {
          fps: 10,
          qrbox: { width: 250, height: 250 },
        },
        async (text) => {
          // callback sukses saat QR ke-scan
          setDecodedText(text);
          await stopScan(); // stop setelah dapat 1 hasil
          await analyzeQrText(text); // kirim ke backend
        },
        (scanError) => {
          // callback error scanning (abaikan, biasanya noisy)
          // console.log(scanError);
        },
      );
    } catch (e) {
      setIsScanning(false);
      setError(
        "Gagal membuka kamera. Pastikan izin kamera diizinkan dan gunakan HTTPS jika di HP.",
      );
    }
  };

  const stopScan = async () => {
    const scanner = scannerRef.current;
    if (!scanner) return;

    try {
      const isRunning = scanner.getState && scanner.getState() === 2; // 2 = SCANNING
      if (isRunning) {
        await scanner.stop();
      }
    } catch (e) {
      // ignore
    }

    try {
      await scanner.clear();
    } catch (e) {
      // ignore
    }

    scannerRef.current = null;
    setIsScanning(false);
  };

  const analyzeQrText = async (text) => {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/scan/qr`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ qr_content: text }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data?.detail || "Gagal analisis QR.");
        return;
      }

      setResult(data);
    } catch (e) {
      setError(
        "Tidak bisa konek ke backend. Pastikan backend jalan di 127.0.0.1:8000",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 520, margin: "0 auto", padding: 16 }}>
      <h2>Scan QR → Analisis Phishing</h2>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {!isScanning ? (
          <button onClick={startScan} style={{ padding: "8px 12px" }}>
            Mulai Scan
          </button>
        ) : (
          <button onClick={stopScan} style={{ padding: "8px 12px" }}>
            Stop
          </button>
        )}

        {decodedText && (
          <button
            onClick={() => analyzeQrText(decodedText)}
            style={{ padding: "8px 12px" }}
            disabled={loading}
          >
            Analisis lagi
          </button>
        )}
      </div>

      {/* Tempat kamera render */}
      <div
        id="qr-reader"
        style={{
          width: "100%",
          border: "1px solid #ddd",
          borderRadius: 8,
          padding: 8,
          marginBottom: 12,
        }}
      />

      {decodedText && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontWeight: 600 }}>Hasil QR (decoded):</div>
          <div style={{ wordBreak: "break-all" }}>{decodedText}</div>
        </div>
      )}

      {loading && <div>⏳ Menganalisis...</div>}

      {error && (
        <div style={{ color: "crimson", marginTop: 8 }}>❌ {error}</div>
      )}

      {result && (
        <div
          style={{
            marginTop: 12,
            padding: 12,
            border: "1px solid #ddd",
            borderRadius: 8,
          }}
        >
          <div style={{ fontWeight: 700, marginBottom: 8 }}>Hasil Analisis</div>

          <div>
            <b>Prediction:</b> {result?.final?.prediction}
          </div>
          <div>
            <b>Risk level:</b> {result?.final?.risk_level}
          </div>
          <div>
            <b>Risk percent:</b> {result?.final?.risk_percent}%
          </div>

          <details style={{ marginTop: 10 }}>
            <summary>Detail</summary>
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {JSON.stringify(result?.details, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}
