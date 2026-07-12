"""Bot-IoT (UNSW, 2018) adapter.

Source:
    https://research.unsw.edu.au/projects/bot-iot-dataset

Expected columns (varies slightly across the released splits — the adapter
auto-detects via case-insensitive candidate lists):
    proto, saddr, sport, daddr, dport, dur, pkts, bytes,
    spkts, dpkts, sbytes, dbytes, rate, srate, drate,
    stime, ltime, mean, stddev, min, max,
    category, subcategory, attack

The `attack` column is 0 for benign, 1 for attack. `category` /
`subcategory` name the family (DDoS, DoS, Reconnaissance, Theft, ...).

Usage:
    from backend.adapters import load_bot_iot
    df = load_bot_iot("backend/data/bot_iot/UNSW_2018_IoT_Botnet_Full5pc_1.csv")
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Union

import numpy as np
import pandas as pd

from ..config import BENIGN_LABEL
from ._common import finalize, numeric, pick, proto_one_hot

# Bot-IoT (category, subcategory) -> SentinelIoT label
_LABEL_MAP = {
    ("ddos", "udp"): "DDoS-UDP-Flood",
    ("ddos", "tcp"): "DDoS-TCP-SYN",
    ("ddos", "http"): "DoS-HTTP-Slowloris",
    ("dos", "udp"): "DDoS-UDP-Flood",
    ("dos", "tcp"): "DDoS-TCP-SYN",
    ("dos", "http"): "DoS-HTTP-Slowloris",
    ("reconnaissance", "os_fingerprint"): "Reconnaissance-PortScan",
    ("reconnaissance", "service_scan"): "Reconnaissance-PortScan",
    ("reconnaissance", "port_scanning"): "Reconnaissance-PortScan",
    ("theft", "data_exfiltration"): "Botnet-C2-Beacon",
    ("theft", "keylogging"): "Botnet-C2-Beacon",
}


def _map_label(cat: str, sub: str, attack_flag: int) -> str:
    if not attack_flag:
        return BENIGN_LABEL
    c = (cat or "").strip().lower()
    s = (sub or "").strip().lower()
    if (c, s) in _LABEL_MAP:
        return _LABEL_MAP[(c, s)]
    # category-only fallbacks
    if c == "ddos":
        return "DDoS-UDP-Flood"
    if c == "dos":
        return "DDoS-TCP-SYN"
    if c == "reconnaissance":
        return "Reconnaissance-PortScan"
    if c == "theft":
        return "Botnet-C2-Beacon"
    return "Botnet-Mirai-Scan"


def _read_many(paths: Iterable[Path]) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    for p in paths:
        frames.append(pd.read_csv(p, low_memory=False))
    if not frames:
        raise FileNotFoundError("no Bot-IoT CSVs found")
    return pd.concat(frames, ignore_index=True)


def load_bot_iot(path: Union[str, Path]) -> pd.DataFrame:
    """Load one Bot-IoT CSV (or a directory of them) into SentinelIoT schema."""
    p = Path(path)
    if p.is_dir():
        raw = _read_many(sorted(p.glob("*.csv")))
    else:
        raw = pd.read_csv(p, low_memory=False)

    duration = numeric(pick(raw, ["dur", "duration"]), default=1e-3).clip(lower=1e-3)
    pkts = numeric(pick(raw, ["pkts", "packet_count", "total_pkts"]), default=1.0).clip(lower=1.0)
    byts = numeric(pick(raw, ["bytes", "byte_count", "total_bytes"]), default=0.0)
    mean_pkt = numeric(pick(raw, ["mean", "mean_pkt_size"]), default=0.0)
    std_pkt = numeric(pick(raw, ["stddev", "std_pkt_size"]), default=0.0)
    min_pkt = numeric(pick(raw, ["min", "min_pkt_size"]), default=0.0)
    max_pkt = numeric(pick(raw, ["max", "max_pkt_size"]), default=0.0)
    dport = numeric(pick(raw, ["dport", "dst_port", "daddr_port"]), default=0.0)

    # Bot-IoT doesn't expose per-flag counts on every split; derive from state/flgs if present.
    state = pick(raw, ["state", "flgs", "flags"])
    if state is not None:
        s = state.astype(str).str.upper()
        syn_ratio = s.str.contains("S", regex=False).astype("float32")
        ack_ratio = s.str.contains("A", regex=False).astype("float32")
        fin_ratio = s.str.contains("F", regex=False).astype("float32")
        rst_ratio = s.str.contains("R", regex=False).astype("float32")
    else:
        z = pd.Series(np.zeros(len(raw), dtype="float32"))
        syn_ratio = ack_ratio = fin_ratio = rst_ratio = z

    features = pd.DataFrame(
        {
            "duration": duration,
            "packet_count": pkts,
            "byte_count": byts,
            "bytes_per_second": (byts / duration).astype("float32"),
            "packets_per_second": (pkts / duration).astype("float32"),
            "mean_pkt_size": mean_pkt.where(mean_pkt > 0, byts / pkts),
            "std_pkt_size": std_pkt,
            "min_pkt_size": min_pkt,
            "max_pkt_size": max_pkt,
            "mean_iat": (duration / pkts).astype("float32"),
            "std_iat": (duration / pkts * 0.25).astype("float32"),
            "syn_ratio": syn_ratio,
            "ack_ratio": ack_ratio,
            "fin_ratio": fin_ratio,
            "rst_ratio": rst_ratio,
            # Bot-IoT is per-flow, so unique_dst_ports collapses to 1 unless a
            # coarser aggregation is applied upstream.
            "unique_dst_ports": pd.Series(np.ones(len(raw), dtype="float32")),
        }
    )
    features = pd.concat([features, proto_one_hot(pick(raw, ["proto", "protocol"]))], axis=1)

    cat = pick(raw, ["category"])
    sub = pick(raw, ["subcategory"])
    attack = pick(raw, ["attack", "label"])
    cat_v = cat.astype(str) if cat is not None else pd.Series([""] * len(raw))
    sub_v = sub.astype(str) if sub is not None else pd.Series([""] * len(raw))
    atk_v = numeric(attack, default=0.0).astype(int) if attack is not None else pd.Series(
        np.ones(len(raw), dtype=int)
    )
    labels = pd.Series(
        [_map_label(c, s, a) for c, s, a in zip(cat_v, sub_v, atk_v)],
        index=raw.index,
    )
    return finalize(features, labels)