"""TON-IoT (UNSW, 2020) network-flow adapter.

Source:
    https://research.unsw.edu.au/projects/toniot-datasets

Targets the `Network_dataset_*.csv` files (Zeek-derived flow records).
Typical columns: ts, src_ip, src_port, dst_ip, dst_port, proto, service,
duration, src_bytes, dst_bytes, conn_state, missed_bytes, src_pkts,
src_ip_bytes, dst_pkts, dst_ip_bytes, ..., label, type.

`label` is 0/1 (benign/attack); `type` names the attack family
(scanning, dos, ddos, injection, mitm, password, backdoor, ransomware, xss).

Usage:
    from backend.adapters import load_ton_iot
    df = load_ton_iot("backend/data/ton_iot/Network_dataset_1.csv")
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Union

import numpy as np
import pandas as pd

from ..config import BENIGN_LABEL
from ._common import finalize, numeric, pick, proto_one_hot

_TYPE_MAP = {
    "normal": BENIGN_LABEL,
    "benign": BENIGN_LABEL,
    "scanning": "Reconnaissance-PortScan",
    "dos": "DDoS-TCP-SYN",
    "ddos": "DDoS-UDP-Flood",
    "backdoor": "Botnet-C2-Beacon",
    "ransomware": "Botnet-C2-Beacon",
    "injection": "DoS-HTTP-Slowloris",
    "xss": "DoS-HTTP-Slowloris",
    "password": "Botnet-Mirai-Scan",
    "mitm": "Botnet-Mirai-Scan",
}


def _map_label(t: str, flag: int) -> str:
    if not flag:
        return BENIGN_LABEL
    return _TYPE_MAP.get((t or "").strip().lower(), "Botnet-Mirai-Scan")


def _read_many(paths: Iterable[Path]) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    for p in paths:
        frames.append(pd.read_csv(p, low_memory=False))
    if not frames:
        raise FileNotFoundError("no TON-IoT CSVs found")
    return pd.concat(frames, ignore_index=True)


def load_ton_iot(path: Union[str, Path]) -> pd.DataFrame:
    p = Path(path)
    if p.is_dir():
        raw = _read_many(sorted(p.glob("*.csv")))
    else:
        raw = pd.read_csv(p, low_memory=False)

    duration = numeric(pick(raw, ["duration", "dur"]), default=1e-3).clip(lower=1e-3)
    src_pkts = numeric(pick(raw, ["src_pkts", "spkts"]), default=0.0)
    dst_pkts = numeric(pick(raw, ["dst_pkts", "dpkts"]), default=0.0)
    pkts = (src_pkts + dst_pkts).clip(lower=1.0)
    src_bytes = numeric(pick(raw, ["src_bytes", "sbytes", "src_ip_bytes"]), default=0.0)
    dst_bytes = numeric(pick(raw, ["dst_bytes", "dbytes", "dst_ip_bytes"]), default=0.0)
    byts = src_bytes + dst_bytes
    mean_pkt = (byts / pkts).astype("float32")

    # TON-IoT conn_state carries Zeek connection-state codes (S0, S1, SF, REJ, RSTO...).
    conn_state = pick(raw, ["conn_state", "state", "flags"])
    if conn_state is not None:
        cs = conn_state.astype(str).str.upper()
        syn_ratio = cs.str.startswith("S").astype("float32")
        ack_ratio = cs.eq("SF").astype("float32")
        fin_ratio = cs.str.contains("F", regex=False).astype("float32")
        rst_ratio = cs.str.contains("R", regex=False).astype("float32")
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
            "mean_pkt_size": mean_pkt,
            "std_pkt_size": (mean_pkt * 0.2).astype("float32"),
            "min_pkt_size": (mean_pkt * 0.5).astype("float32"),
            "max_pkt_size": (mean_pkt * 1.5).astype("float32"),
            "mean_iat": (duration / pkts).astype("float32"),
            "std_iat": (duration / pkts * 0.25).astype("float32"),
            "syn_ratio": syn_ratio,
            "ack_ratio": ack_ratio,
            "fin_ratio": fin_ratio,
            "rst_ratio": rst_ratio,
            "unique_dst_ports": pd.Series(np.ones(len(raw), dtype="float32")),
        }
    )
    features = pd.concat([features, proto_one_hot(pick(raw, ["proto", "protocol"]))], axis=1)

    type_col = pick(raw, ["type", "attack_cat", "category"])
    flag_col = pick(raw, ["label", "attack"])
    type_v = type_col.astype(str) if type_col is not None else pd.Series(["normal"] * len(raw))
    flag_v = (
        numeric(flag_col, default=0.0).astype(int)
        if flag_col is not None
        else pd.Series(np.ones(len(raw), dtype=int))
    )
    labels = pd.Series([_map_label(t, f) for t, f in zip(type_v, flag_v)], index=raw.index)
    return finalize(features, labels)