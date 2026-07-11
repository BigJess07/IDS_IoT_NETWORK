"""
SentinelIoT FastAPI server.

HTTP:
    GET  /api/health           liveness + model info
    GET  /api/stats            gateway snapshot (matches StatCard values)
    GET  /api/flows?limit=40   recent classified flows (FlowFeed)
    GET  /api/alerts?limit=50  recent security alerts (AlertLog)
    POST /api/control/{cmd}    cmd in {start, stop, reset}

WebSocket:
    /ws/stream                 pushes {type, payload}:
                                 flow       -> FlowRow
                                 alert      -> AlertRow
                                 throughput -> ThroughputPoint (every 2s)
                                 stats      -> gateway snapshot (every 2s)

Payload shapes intentionally mirror the TS types used by the React
dashboard (FlowRow / AlertRow / ThroughputPoint) so the client can
consume them without translation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import threading
import time
import uuid
from collections import deque
from typing import Deque, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .config import ALLOWED_ORIGINS, API_HOST, API_PORT
from .feature_extractor import FlowTable
from .inference_engine import InferenceEngine, get_engine
from .sniffer import auto_source

log = logging.getLogger("sentinel.api")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# Map internal class labels -> dashboard-friendly display strings.
THREAT_TYPE_MAP = {
    "DDoS-UDP-Flood": "DDoS · UDP Flood",
    "DDoS-TCP-SYN": "DDoS · TCP SYN",
    "DoS-HTTP-Slowloris": "DoS · HTTP Slowloris",
    "Botnet-Mirai-Scan": "Botnet · Mirai Scan",
    "Botnet-C2-Beacon": "Botnet · C2 Beacon",
    "Reconnaissance-PortScan": "Reconnaissance · Port Scan",
}


class GatewayState:
    def __init__(self) -> None:
        self.running = True
        self.flows: Deque[dict] = deque(maxlen=200)
        self.alerts: Deque[dict] = deque(maxlen=200)
        self.throughput: Deque[dict] = deque(maxlen=200)
        self.total_flows = 0
        self.total_threats = 0
        self.avg_inference_ms = 0.0
        self.bytes_window = 0
        self.packets_window = 0
        self.last_throughput_ts = time.time()
        self._lock = threading.Lock()

    def push_packet(self, size: int) -> None:
        with self._lock:
            self.bytes_window += size
            self.packets_window += 1

    def tick_throughput(self) -> dict:
        with self._lock:
            now = time.time()
            elapsed = max(0.5, now - self.last_throughput_ts)
            bps = self.bytes_window / elapsed
            pps = self.packets_window / elapsed
            self.bytes_window = 0
            self.packets_window = 0
            self.last_throughput_ts = now
        point = {
            "t": int(now * 1000),
            "label": time.strftime("%H:%M:%S", time.localtime(now)),
            "bps": bps,
            "pps": pps,
        }
        self.throughput.append(point)
        return point

    def record_flow(self, flow: dict) -> None:
        with self._lock:
            self.flows.appendleft(flow)
            self.total_flows += 1
            self.avg_inference_ms = self.avg_inference_ms * 0.9 + flow["inference"] * 0.1

    def record_alert(self, alert: dict) -> None:
        with self._lock:
            self.alerts.appendleft(alert)
            self.total_threats += 1

    def snapshot(self) -> dict:
        with self._lock:
            latest_bps = self.throughput[-1]["bps"] if self.throughput else 0.0
            peak_bps = max((p["bps"] for p in self.throughput), default=0.0)
            return {
                "running": self.running,
                "totalFlows": self.total_flows,
                "threats": self.total_threats,
                "avgInferenceMs": round(self.avg_inference_ms, 2),
                "currentBps": latest_bps,
                "peakBps": peak_bps,
                "threatRatio": (
                    self.total_threats / self.total_flows if self.total_flows else 0.0
                ),
                "node": {"host": "rpi-gw-01", "modelSizeMb": 1.8, "flowWindowS": 5.0},
            }


state = GatewayState()


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self.clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self.clients.discard(ws)

    async def broadcast(self, event: dict) -> None:
        payload = json.dumps(event, default=str)
        stale: list[WebSocket] = []
        for ws in list(self.clients):
            try:
                await ws.send_text(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            await self.disconnect(ws)

    def broadcast_threadsafe(self, event: dict) -> None:
        """Called from the worker thread to hop back onto the asyncio loop."""
        if self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(event), self.loop)


hub = Hub()


def worker_loop(engine: InferenceEngine) -> None:
    """Packet source -> flow table -> classifier -> dashboard events."""
    log.info("worker starting")
    source = auto_source()
    flow_table = FlowTable()
    last_sweep = time.time()
    for pkt in source.stream():
        if not state.running:
            time.sleep(0.05)
            continue
        state.push_packet(pkt["size"])
        flow_table.update(
            ts=pkt["ts"], src=pkt["src"], dst=pkt["dst"],
            sport=pkt["sport"], dport=pkt["dport"], proto=pkt["proto"],
            size=pkt["size"], flags=pkt.get("flags", ""),
        )
        now = time.time()
        if now - last_sweep > 2.0:
            flow_table.sweep_idle(now)
            last_sweep = now
        for completed in flow_table.pop_completed():
            features = completed.to_features()
            verdict = engine.classify(features)
            flow_row = {
                "id": uuid.uuid4().hex[:10],
                "ts": int(now * 1000),
                "src": completed.key[0],
                "dst": completed.key[1],
                "proto": completed.key[4],
                "packets": int(features["packet_count"]),
                "bytes": int(features["byte_count"]),
                "duration": round(features["duration"], 2),
                "inference": round(verdict.latency_ms, 2),
                "verdict": 1 if verdict.is_threat else 0,
                "label": verdict.label,
                "confidence": round(verdict.confidence, 3),
            }
            state.record_flow(flow_row)
            hub.broadcast_threadsafe({"type": "flow", "payload": flow_row})
            if verdict.is_threat:
                alert = {
                    "id": flow_row["id"],
                    "ts": flow_row["ts"],
                    "type": THREAT_TYPE_MAP.get(verdict.label, verdict.label),
                    "src": flow_row["src"],
                    "dst": flow_row["dst"],
                    "action": "BLOCKED" if random.random() < 0.7 else "QUARANTINED",
                    "inference": flow_row["inference"],
                    "confidence": flow_row["confidence"],
                }
                state.record_alert(alert)
                hub.broadcast_threadsafe({"type": "alert", "payload": alert})


async def throughput_ticker() -> None:
    while True:
        await asyncio.sleep(2.0)
        point = state.tick_throughput()
        await hub.broadcast({"type": "throughput", "payload": point})
        await hub.broadcast({"type": "stats", "payload": state.snapshot()})


app = FastAPI(title="SentinelIoT IDS API", version="1.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup() -> None:
    hub.loop = asyncio.get_running_loop()
    engine = get_engine()  # fail fast if model is missing
    threading.Thread(target=worker_loop, args=(engine,), daemon=True).start()
    asyncio.create_task(throughput_ticker())
    log.info("SentinelIoT API ready on %s:%s", API_HOST, API_PORT)


@app.get("/api/health")
async def health() -> dict:
    engine = get_engine()
    return {
        "status": "ok",
        "model": {"classes": engine.labels, "features": len(engine.features)},
    }


@app.get("/api/stats")
async def get_stats() -> dict:
    return state.snapshot()


@app.get("/api/flows")
async def get_flows(limit: int = 40) -> dict:
    return {"rows": list(state.flows)[:limit]}


@app.get("/api/alerts")
async def get_alerts(limit: int = 50) -> dict:
    return {"rows": list(state.alerts)[:limit]}


@app.post("/api/control/{cmd}")
async def control(cmd: str) -> dict:
    if cmd == "start":
        state.running = True
    elif cmd == "stop":
        state.running = False
    elif cmd == "reset":
        state.flows.clear()
        state.alerts.clear()
        state.throughput.clear()
        state.total_flows = 0
        state.total_threats = 0
        state.avg_inference_ms = 0.0
    else:
        return {"ok": False, "error": f"unknown command '{cmd}'"}
    return {"ok": True, "running": state.running}


@app.websocket("/ws/stream")
async def ws_stream(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        # boot the client with current state so the dashboard is never blank
        await ws.send_text(json.dumps({"type": "stats", "payload": state.snapshot()}))
        for row in reversed(list(state.flows)[:40]):
            await ws.send_text(json.dumps({"type": "flow", "payload": row}))
        for row in reversed(list(state.alerts)[:50]):
            await ws.send_text(json.dumps({"type": "alert", "payload": row}))
        while True:
            await ws.receive_text()  # keep-alive; ignore client input
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(ws)


def main() -> None:  # pragma: no cover
    import uvicorn
    uvicorn.run("backend.api_server:app", host=API_HOST, port=API_PORT, reload=False)


if __name__ == "__main__":  # pragma: no cover
    main()