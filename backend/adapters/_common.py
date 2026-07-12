"""Shared helpers for dataset adapters.

All public IoT IDS datasets ship per-flow CSVs with slightly different
column names. These helpers pick the first column that matches a list of
candidates (case-insensitive) so a single adapter tolerates the small
schema drift across Bot-IoT / TON-IoT releases.
"""
from __future__ import annotations

from typing import Iterable, Optional

import numpy as np
import pandas as pd

from ..feature_extractor import FEATURE_NAMES


def pick(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[pd.Series]:
    """Return the first column in `candidates` present in `df` (case-insensitive)."""
    lowered = {c.lower(): c for c in df.columns}
    for name in candidates:
        real = lowered.get(name.lower())
        if real is not None:
            return df[real]
    return None


def numeric(series: Optional[pd.Series], default: float = 0.0) -> pd.Series:
    if series is None:
        return pd.Series(dtype="float32")
    return pd.to_numeric(series, errors="coerce").fillna(default).astype("float32")


def finalize(feature_df: pd.DataFrame, labels: pd.Series) -> pd.DataFrame:
    """Ensure every FEATURE_NAMES column exists, order them, attach labels."""
    for col in FEATURE_NAMES:
        if col not in feature_df.columns:
            feature_df[col] = 0.0
    out = feature_df[FEATURE_NAMES].copy()
    out.replace([np.inf, -np.inf], 0.0, inplace=True)
    out.fillna(0.0, inplace=True)
    out["label"] = labels.astype(str).values
    return out


def proto_one_hot(proto_series: Optional[pd.Series]) -> pd.DataFrame:
    """Map a free-text protocol column to the (tcp, udp, icmp) one-hot triple."""
    if proto_series is None:
        return pd.DataFrame(
            {"proto_tcp": 0.0, "proto_udp": 0.0, "proto_icmp": 0.0}, index=[0]
        )
    p = proto_series.astype(str).str.lower().str.strip()
    return pd.DataFrame(
        {
            "proto_tcp": p.eq("tcp").astype("float32"),
            "proto_udp": p.eq("udp").astype("float32"),
            "proto_icmp": p.isin(["icmp", "ipv6-icmp"]).astype("float32"),
        }
    )