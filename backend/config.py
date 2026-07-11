"""
SentinelIoT — central configuration.

All tunables live here so the training pipeline, feature extractor, sniffer,
and API server stay in sync. Values are conservative defaults chosen for a
constrained edge gateway (Raspberry Pi 4 class).
"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
LOG_DIR = BASE_DIR / "logs"
for _d in (DATA_DIR, MODEL_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "rf_ids.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
FEATURE_LIST_PATH = MODEL_DIR / "features.json"
LABEL_MAP_PATH = MODEL_DIR / "labels.json"

# ---------------------------------------------------------------------------
# Flow extraction
# ---------------------------------------------------------------------------
FLOW_WINDOW_SECONDS = 5.0        # rolling window used to aggregate a flow
FLOW_IDLE_TIMEOUT = 15.0         # evict inactive flows after this many seconds
MAX_ACTIVE_FLOWS = 4096          # safety cap on the in-memory flow table

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
# Kept intentionally small so the artifact stays under ~2 MB on disk and
# inference stays sub-5ms on a Pi 4.
RF_PARAMS = {
    "n_estimators": 60,
    "max_depth": 14,
    "min_samples_leaf": 4,
    "n_jobs": -1,
    "class_weight": "balanced",
    "random_state": 42,
}

THREAT_CLASSES = (
    "DDoS-UDP-Flood",
    "DDoS-TCP-SYN",
    "DoS-HTTP-Slowloris",
    "Botnet-Mirai-Scan",
    "Botnet-C2-Beacon",
    "Reconnaissance-PortScan",
)
BENIGN_LABEL = "Benign"

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
API_HOST = "0.0.0.0"
API_PORT = 8000
ALLOWED_ORIGINS = ["*"]  # dashboard is co-hosted; tighten in production