from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DetectionConfig:
    wH: float = 0.35
    wB: float = 0.20
    wS: float = 0.45

    suspicious_threshold: float = 0.34
    phishing_threshold: float = 0.60

    sim_high: float = 0.95
    sim_mid: float = 0.90
    sim_low: float = 0.84

    bonus_cap: float = 0.32
    penalty_cap: float = 0.30


DEFAULT_CONFIG = DetectionConfig()