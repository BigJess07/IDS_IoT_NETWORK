"""
Dataset loading & preprocessing.

Tries, in order:
  1. A user-provided CSV under backend/data/<name>.csv whose columns already
     match FEATURE_NAMES + "label" (e.g. exported from CIC-IDS2017).
  2. A synthetic dataset generated on the fly (for pipeline smoke tests).

Real-world datasets to plug in:
  * CIC-IDS2017 / CIC-IoT2023 (https://www.unb.ca/cic/datasets/)
  * IoT-23 (https://www.stratosphereips.org/datasets-iot23)
"""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .config import DATA_DIR
from .feature_extractor import FEATURE_NAMES
from .synthetic_dataset import build_dataset


def _find_user_csv() -> Path | None:
    for p in sorted(DATA_DIR.glob("*.csv")):
        if p.name.startswith("synthetic_"):
            continue
        try:
            head = pd.read_csv(p, nrows=1)
        except Exception:
            continue
        if {"label", *FEATURE_NAMES}.issubset(head.columns):
            return p
    return None


def load_dataset() -> pd.DataFrame:
    user_csv = _find_user_csv()
    if user_csv is not None:
        print(f"[data] using user-provided dataset: {user_csv}")
        return pd.read_csv(user_csv)
    print("[data] no user CSV found; generating synthetic dataset")
    return build_dataset()


def split_and_scale(
    df: pd.DataFrame, test_size: float = 0.2, seed: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, StandardScaler]:
    X = df[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )
    scaler = StandardScaler().fit(X_tr)
    return scaler.transform(X_tr), scaler.transform(X_te), y_tr, y_te, scaler