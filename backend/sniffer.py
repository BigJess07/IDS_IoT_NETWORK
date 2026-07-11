"""
Packet source abstraction.

Three interchangeable sources — pick automatically at runtime:
  * LiveSniffer      — scapy.AsyncSniffer on a real NIC (requires CAP_NET_RAW)
  * PcapReplayer     — replays a .pcap file at (optionally) accelerated speed
  * SyntheticSource  — fabricates packet events when neither is available,
                       so the demo never goes silent.

Every source yields dicts:
    {ts, src, dst, sport, dport, proto, size, flags}
"""
from __future__ import annotations

import logging
import queue
import random
import time
from typing import Iterator, Optional

log = logging.getLogger("sentinel.sniffer")


class LiveSniffer:
    def __init__(self, iface: Optional[str] = None, bpf: str = "ip") -> None:
        self.iface = iface
        self.bpf = bpf
        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=10_000)
        self._sniffer = None

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP  # noqa: WPS433
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("scapy unavailable or capture privileges missing") from exc

        def _on_pkt(pkt):
            try:
                if IP not in pkt:
                    return
                ip = pkt[IP]
                proto, sport, dport, flags = "OTHER", 0, 0, ""
                if TCP in pkt:
                    proto = "TCP"
                    sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
                    flags = str(pkt[TCP].flags)
                elif UDP in pkt:
                    proto = "UDP"
                    sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
                elif ICMP in pkt:
                    proto = "ICMP"
                self._q.put_nowait(
                    {
                        "ts": time.time(),
                        "src": ip.src, "dst": ip.dst,
                        "sport": sport, "dport": dport,
                        "proto": proto, "size": len(pkt), "flags": flags,
                    }
                )
            except queue.Full:
                pass
            except Exception as e:  # pragma: no cover
                log.debug("packet parse failed: %s", e)

        try:
            self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=_on_pkt, store=False)
            self._sniffer.start()
            log.info("live sniffer started on iface=%s", self.iface or "<default>")
        except PermissionError as exc:
            raise RuntimeError(
                "insufficient privileges for live capture "
                "(hint: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python)`)"
            ) from exc

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()

    def stream(self) -> Iterator[dict]:
        while True:
            yield self._q.get()


class PcapReplayer:
    def __init__(self, path: str, speed: float = 1.0) -> None:
        self.path = path
        self.speed = max(0.01, speed)

    def stream(self) -> Iterator[dict]:
        from scapy.all import IP, PcapReader, TCP, UDP, ICMP  # noqa: WPS433

        base_wall = time.time()
        base_pcap: Optional[float] = None
        with PcapReader(self.path) as reader:
            for pkt in reader:
                if IP not in pkt:
                    continue
                if base_pcap is None:
                    base_pcap = float(pkt.time)
                target = base_wall + (float(pkt.time) - base_pcap) / self.speed
                delay = target - time.time()
                if delay > 0:
                    time.sleep(delay)
                ip = pkt[IP]
                proto, sport, dport, flags = "OTHER", 0, 0, ""
                if TCP in pkt:
                    proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
                    flags = str(pkt[TCP].flags)
                elif UDP in pkt:
                    proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
                elif ICMP in pkt:
                    proto = "ICMP"
                yield {
                    "ts": time.time(),
                    "src": ip.src, "dst": ip.dst,
                    "sport": sport, "dport": dport,
                    "proto": proto, "size": len(pkt), "flags": flags,
                }


class SyntheticSource:
    """Fabricates packet events matching the dashboard's traffic mix (~14% hostile)."""

    BENIGN_SRC = ["192.168.4.17", "192.168.4.32", "10.0.0.45", "10.0.0.88"]
    HOSTILE_SRC = ["203.0.113.42", "198.51.100.7", "172.16.9.101"]
    DST = ["192.168.4.1", "10.0.0.1", "10.0.0.10"]
    PROTOS = ("TCP", "UDP", "ICMP")

    def __init__(self, packets_per_second: float = 120.0) -> None:
        self.pps = packets_per_second

    def stream(self) -> Iterator[dict]:
        interval = 1.0 / self.pps
        while True:
            hostile = random.random() < 0.14
            src = random.choice(self.HOSTILE_SRC if hostile else self.BENIGN_SRC)
            proto = random.choice(self.PROTOS)
            size = random.randint(60, 300) if hostile else random.randint(60, 1500)
            flags = ""
            if proto == "TCP":
                flags = random.choice(["S", "S", "S", "R"] if hostile
                                       else ["S", "SA", "A", "PA", "R", "FA"])
            yield {
                "ts": time.time(),
                "src": src,
                "dst": random.choice(self.DST),
                "sport": random.randint(1024, 65535),
                "dport": random.choice([22, 23, 53, 80, 443, 1883, 8883, 8080]),
                "proto": proto, "size": size, "flags": flags,
            }
            time.sleep(max(0.0, interval + random.uniform(-interval * 0.3, interval * 0.3)))


def auto_source(iface: Optional[str] = None, pcap: Optional[str] = None):
    """Pick the best available packet source."""
    if pcap:
        log.info("using PCAP replayer: %s", pcap)
        return PcapReplayer(pcap)
    try:
        sniff = LiveSniffer(iface=iface)
        sniff.start()
        return sniff
    except Exception as exc:
        log.warning("live capture unavailable (%s); falling back to synthetic", exc)
        return SyntheticSource()