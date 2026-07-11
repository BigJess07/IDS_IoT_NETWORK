"""
Flow-level feature extraction.

A "flow" is the classic 5-tuple: (src_ip, dst_ip, src_port, dst_port, proto).
We aggregate packets into flows over FLOW_WINDOW_SECONDS and emit a fixed
numeric feature vector suitable for the Random Forest classifier.

Deliberately packet-header only (no DPI / no payload inspection) so the
system is protocol-agnostic and privacy-preserving.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from .config import FLOW_IDLE_TIMEOUT, FLOW_WINDOW_SECONDS, MAX_ACTIVE_FLOWS

FlowKey = Tuple[str, str, int, int, str]

FEATURE_NAMES: List[str] = [
    "duration",
    "packet_count",
    "byte_count",
    "bytes_per_second",
    "packets_per_second",
    "mean_pkt_size",
    "std_pkt_size",
    "min_pkt_size",
    "max_pkt_size",
    "mean_iat",          # inter-arrival time
    "std_iat",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "unique_dst_ports",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
]


@dataclass
class FlowState:
    key: FlowKey
    start_ts: float
    last_ts: float
    packet_sizes: List[int] = field(default_factory=list)
    inter_arrivals: List[float] = field(default_factory=list)
    flags: Dict[str, int] = field(
        default_factory=lambda: {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0}
    )
    dst_ports_seen: set = field(default_factory=set)

    def add_packet(self, ts: float, size: int, flags: str, dst_port: int) -> None:
        if self.packet_sizes:
            self.inter_arrivals.append(max(0.0, ts - self.last_ts))
        self.packet_sizes.append(size)
        self.last_ts = ts
        self.dst_ports_seen.add(dst_port)
        for f in ("SYN", "ACK", "FIN", "RST"):
            if f in flags:
                self.flags[f] += 1

    def to_features(self) -> Dict[str, float]:
        import statistics as st

        n = max(1, len(self.packet_sizes))
        duration = max(1e-3, self.last_ts - self.start_ts)
        total_bytes = sum(self.packet_sizes)
        proto = self.key[4]
        return {
            "duration": duration,
            "packet_count": float(n),
            "byte_count": float(total_bytes),
            "bytes_per_second": total_bytes / duration,
            "packets_per_second": n / duration,
            "mean_pkt_size": st.fmean(self.packet_sizes),
            "std_pkt_size": st.pstdev(self.packet_sizes) if n > 1 else 0.0,
            "min_pkt_size": float(min(self.packet_sizes)),
            "max_pkt_size": float(max(self.packet_sizes)),
            "mean_iat": st.fmean(self.inter_arrivals) if self.inter_arrivals else 0.0,
            "std_iat": st.pstdev(self.inter_arrivals) if len(self.inter_arrivals) > 1 else 0.0,
            "syn_ratio": self.flags["SYN"] / n,
            "ack_ratio": self.flags["ACK"] / n,
            "fin_ratio": self.flags["FIN"] / n,
            "rst_ratio": self.flags["RST"] / n,
            "unique_dst_ports": float(len(self.dst_ports_seen)),
            "proto_tcp": 1.0 if proto == "TCP" else 0.0,
            "proto_udp": 1.0 if proto == "UDP" else 0.0,
            "proto_icmp": 1.0 if proto == "ICMP" else 0.0,
        }


class FlowTable:
    """
    Rolling flow aggregator. Call `update()` with each packet observed;
    call `pop_completed()` to drain flows whose window has closed.
    """

    def __init__(
        self,
        window: float = FLOW_WINDOW_SECONDS,
        idle: float = FLOW_IDLE_TIMEOUT,
        max_flows: int = MAX_ACTIVE_FLOWS,
    ) -> None:
        self.window = window
        self.idle = idle
        self.max_flows = max_flows
        self._flows: Dict[FlowKey, FlowState] = {}
        self._completed: Deque[FlowState] = deque()

    def update(
        self,
        ts: float,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        proto: str,
        size: int,
        flags: str = "",
    ) -> None:
        key: FlowKey = (src, dst, int(sport), int(dport), proto)
        state = self._flows.get(key)
        if state is None:
            if len(self._flows) >= self.max_flows:
                self._evict_oldest()
            state = FlowState(key=key, start_ts=ts, last_ts=ts)
            self._flows[key] = state
        state.add_packet(ts, size, flags, int(dport))
        # Close the flow if its window elapsed
        if state.last_ts - state.start_ts >= self.window:
            self._completed.append(state)
            self._flows.pop(key, None)

    def sweep_idle(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        expired = [k for k, s in self._flows.items() if now - s.last_ts > self.idle]
        for k in expired:
            self._completed.append(self._flows.pop(k))

    def pop_completed(self) -> List[FlowState]:
        out, self._completed = list(self._completed), deque()
        return out

    def _evict_oldest(self) -> None:
        oldest_key = min(self._flows, key=lambda k: self._flows[k].start_ts)
        self._completed.append(self._flows.pop(oldest_key))