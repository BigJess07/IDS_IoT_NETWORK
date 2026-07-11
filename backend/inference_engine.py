"""
Runtime inference wrapper.

Loads the trained artifacts once and exposes `classify()` which takes a
feature dict (from FlowState.to_features) and returns a Verdict with the
predicted label, top-1 confidence, and measured wall-clock latency.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import joblib
import numpy as np

from .config import (
    BENIGN_LABEL,
    FEATURE_LIST_PATH,
    LABEL_MAP_PATH,
    MODEL_PATH,
    SCALER_PATH,
)


@dataclass
class Verdict:
    label: str
    confidence: float
    latency_ms: float
    is_threat: bool


class InferenceEngine:
    def __init__(self) -> None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model artifact not found at {MODEL_PATH}. "
                "Run `python -m backend.train_model` first."
            )
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.features: List[str] = json.loads(FEATURE_LIST_PATH.read_text())
        self.labels: List[str] = json.loads(LABEL_MAP_PATH.read_text())

    def classify(self, features: Dict[str, float]) -> Verdict:
        vec = np.array([[features[f] for f in self.features]], dtype=np.float32)
        vec = self.scaler.transform(vec)
        t0 = time.perf_counter()
        proba = self.model.predict_proba(vec)[0]
        latency_ms = (time.perf_counter() - t0) * 1000.0
        idx = int(np.argmax(proba))
        label = self.labels[idx]
        return Verdict(
            label=label,
            confidence=float(proba[idx]),
            latency_ms=latency_ms,
            is_threat=label != BENIGN_LABEL,
        )


_engine: Optional[InferenceEngine] = None


def get_engine() -> InferenceEngine:
    global _engine
    if _engine is None:
        _engine = InferenceEngine()
    return _engine