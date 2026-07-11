"""
Synthetic flow-feature dataset generator.

Used when the student cannot download CIC-IDS2017 / IoT-23 in time, or wants
a fast smoke-test of the training pipeline. Distributions are hand-tuned to
resemble the qualitative shape of each attack family (heavy pps for floods,
long slow flows for Slowloris, high unique_dst_ports for port scans, etc.).

Do NOT ship the trained-on-synthetic model as a real IDS — use it only for
plumbing tests. Swap in real data via `data_preprocessing.py`.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import BENIGN_LABEL, THREAT_CLASSES
from .feature_extractor import FEATURE_NAMES


def _sample(n: int, label: str, rng: np.random.Generator) -> pd.DataFrame:
    """Draw n samples for a given class."""
    if label == BENIGN_LABEL:
        pkt = rng.integers(4, 60, size=n)
        bts = pkt * rng.integers(60, 900, size=n)
        dur = rng.uniform(0.3, 4.9, size=n)
        syn = rng.uniform(0.0, 0.12, size=n)
        rst = rng.uniform(0.0, 0.05, size=n)
        udp = rng.integers(0, 2, size=n)
        uports = rng.integers(1, 4, size=n)
    elif label == "DDoS-UDP-Flood":
        pkt = rng.integers(200, 900, size=n)
        bts = pkt * rng.integers(400, 1500, size=n)
        dur = rng.uniform(1.0, 5.0, size=n)
        syn = rng.uniform(0.0, 0.05, size=n)
        rst = rng.uniform(0.0, 0.05, size=n)
        udp = np.ones(n, dtype=int)
        uports = rng.integers(1, 3, size=n)
    elif label == "DDoS-TCP-SYN":
        pkt = rng.integers(150, 700, size=n)
        bts = pkt * rng.integers(60, 120, size=n)
        dur = rng.uniform(0.5, 5.0, size=n)
        syn = rng.uniform(0.75, 0.99, size=n)
        rst = rng.uniform(0.1, 0.4, size=n)
        udp = np.zeros(n, dtype=int)
        uports = rng.integers(1, 5, size=n)
    elif label == "DoS-HTTP-Slowloris":
        pkt = rng.integers(6, 40, size=n)
        bts = pkt * rng.integers(120, 400, size=n)
        dur = rng.uniform(4.5, 5.0, size=n)
        syn = rng.uniform(0.05, 0.2, size=n)
        rst = rng.uniform(0.0, 0.05, size=n)
        udp = np.zeros(n, dtype=int)
        uports = np.ones(n, dtype=int)
    elif label == "Botnet-Mirai-Scan":
        pkt = rng.integers(20, 120, size=n)
        bts = pkt * rng.integers(60, 90, size=n)
        dur = rng.uniform(0.4, 3.0, size=n)
        syn = rng.uniform(0.85, 0.99, size=n)
        rst = rng.uniform(0.4, 0.9, size=n)
        udp = np.zeros(n, dtype=int)
        uports = rng.integers(15, 80, size=n)
    elif label == "Botnet-C2-Beacon":
        pkt = rng.integers(6, 25, size=n)
        bts = pkt * rng.integers(200, 500, size=n)
        dur = rng.uniform(2.0, 5.0, size=n)
        syn = rng.uniform(0.03, 0.1, size=n)
        rst = rng.uniform(0.0, 0.03, size=n)
        udp = np.zeros(n, dtype=int)
        uports = np.ones(n, dtype=int)
    elif label == "Reconnaissance-PortScan":
        pkt = rng.integers(30, 200, size=n)
        bts = pkt * rng.integers(40, 80, size=n)
        dur = rng.uniform(0.6, 4.5, size=n)
        syn = rng.uniform(0.9, 1.0, size=n)
        rst = rng.uniform(0.6, 0.98, size=n)
        udp = np.zeros(n, dtype=int)
        uports = rng.integers(40, 300, size=n)
    else:
        raise ValueError(label)

    pkt_mean = bts / pkt
    pkt_std = pkt_mean * rng.uniform(0.05, 0.3, size=n)
    iat_mean = dur / np.maximum(pkt, 1)
    df = pd.DataFrame(
        {
            "duration": dur,
            "packet_count": pkt.astype(float),
            "byte_count": bts.astype(float),
            "bytes_per_second": bts / dur,
            "packets_per_second": pkt / dur,
            "mean_pkt_size": pkt_mean,
            "std_pkt_size": pkt_std,
            "min_pkt_size": np.maximum(40.0, pkt_mean - 2 * pkt_std),
            "max_pkt_size": pkt_mean + 3 * pkt_std,
            "mean_iat": iat_mean,
            "std_iat": iat_mean * rng.uniform(0.1, 0.6, size=n),
            "syn_ratio": syn,
            "ack_ratio": rng.uniform(0.1, 0.9, size=n),
            "fin_ratio": rng.uniform(0.0, 0.2, size=n),
            "rst_ratio": rst,
            "unique_dst_ports": uports.astype(float),
            "proto_tcp": (1 - udp).astype(float),
            "proto_udp": udp.astype(float),
            "proto_icmp": np.zeros(n),
        }
    )
    df["label"] = label
    return df[FEATURE_NAMES + ["label"]]


def build_dataset(per_class: int = 4000, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    frames = [_sample(per_class * 3, BENIGN_LABEL, rng)]  # benign oversampled
    frames.extend(_sample(per_class, c, rng) for c in THREAT_CLASSES)
    df = pd.concat(frames, ignore_index=True)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


if __name__ == "__main__":  # pragma: no cover
    df = build_dataset()
    out = "backend/data/synthetic_flows.csv"
    df.to_csv(out, index=False)
    print(f"[synthetic] wrote {len(df):,} rows -> {out}")