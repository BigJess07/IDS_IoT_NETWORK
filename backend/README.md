# SentinelIoT — Python Backend

Lightweight ML intrusion-detection system that sits passively on an IoT
edge gateway (Raspberry Pi 4-class hardware) and feeds the React IDS
console.

```
 NIC / PCAP ──► sniffer ──► FlowTable ──► feature vector ──► RandomForest
                                                                 │
                                                                 ▼
                                                 FastAPI  (REST + WebSocket)
                                                                 │
                                                                 ▼
                                                    React dashboard (this app)
```

Header-only (5-tuple + timing/size stats). No DPI, no payload inspection.

---

## 1. Directory layout

```
backend/
├── config.py                # central knobs (window, model params, paths)
├── feature_extractor.py     # FlowTable + 19 flow features
├── synthetic_dataset.py     # fallback training data
├── data_preprocessing.py    # loads user CSV or synthetic dataset
├── train_model.py           # trains + persists RandomForest artifacts
├── inference_engine.py      # runtime classifier wrapper
├── sniffer.py               # LiveSniffer | PcapReplayer | SyntheticSource
├── api_server.py            # FastAPI + WebSocket
├── data/                    # drop CIC-IDS / IoT-23 CSVs here
├── models/                  # rf_ids.joblib, scaler.joblib, ...
└── logs/
```

---

## 2. Install

```bash
cd backend
python -m venv .venv
source .venv/bin/activate               # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

For live capture on Linux, grant scapy raw-socket capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))
```

No sudo? The sniffer falls back to a synthetic packet source
automatically so demos and training still work.

---

## 3. Train the model

Optionally drop a real dataset (CIC-IDS2017, CIC-IoT2023, IoT-23) into
`backend/data/*.csv`. Columns must include those in
`feature_extractor.FEATURE_NAMES` plus a `label` column. Otherwise a
synthetic dataset is generated for a smoke test.

```bash
python -m backend.train_model
```

Outputs:

```
backend/models/rf_ids.joblib      (~1-2 MB)
backend/models/scaler.joblib
backend/models/features.json
backend/models/labels.json
```

A scikit-learn `classification_report` and confusion matrix print for the
held-out split.

---

## 4. Run the API

```bash
python -m backend.api_server
```

Starts on `http://0.0.0.0:8000`:

| Method | Path                    | Purpose                                |
| ------ | ----------------------- | -------------------------------------- |
| GET    | `/api/health`           | liveness + model metadata              |
| GET    | `/api/stats`            | gateway snapshot (matches StatCards)   |
| GET    | `/api/flows?limit=40`   | latest classified flows                |
| GET    | `/api/alerts?limit=50`  | latest security alerts                 |
| POST   | `/api/control/{cmd}`    | `start` / `stop` / `reset`             |
| WS     | `/ws/stream`            | live push of flows / alerts / stats    |

The WebSocket emits `{type, payload}` frames whose payload shapes match
the TypeScript types the dashboard already uses (`FlowRow`, `AlertRow`,
`ThroughputPoint`).

---

## 5. End-to-end demo — chronological

```bash
# terminal 1 — train (once)
python -m backend.train_model

# terminal 2 — API + inference engine
python -m backend.api_server

# terminal 3 — dashboard
bun install
bun run dev
```

Open the dashboard; the WebSocket at `/ws/stream` will feed it.

---

## 6. Wire the dashboard to real events (optional)

The React dashboard currently runs a client-side simulator
(`src/components/dashboard/Dashboard.tsx`). To consume the backend:

```ts
useEffect(() => {
  const ws = new WebSocket("ws://localhost:8000/ws/stream");
  ws.onmessage = (m) => {
    const { type, payload } = JSON.parse(m.data);
    if (type === "flow")       setFlows((p) => [payload, ...p].slice(0, 40));
    if (type === "alert")      setAlerts((p) => [payload, ...p].slice(0, 50));
    if (type === "throughput") setSeries((p) => [...p, payload].slice(-40));
    if (type === "stats") {
      setTotalFlows(payload.totalFlows);
      setThreats(payload.threats);
      setAvgInference(payload.avgInferenceMs);
    }
  };
  return () => ws.close();
}, []);
```

---

## 7. Error handling

* Missing model artifacts → `InferenceEngine` raises with the exact
  training command to run.
* Live-capture privilege denied → automatic fallback to `SyntheticSource`
  with a warning in the logs.
* Missing PCAP → scapy raises `FileNotFoundError`; caller decides.
* Flow table capped at `MAX_ACTIVE_FLOWS`; oldest flow evicted first to
  survive slow-loris–style resource exhaustion.