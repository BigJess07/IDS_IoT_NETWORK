"""Dataset adapters that map public IoT IDS datasets to SentinelIoT's
internal FEATURE_NAMES + `label` schema.

Currently supported:
    * Bot-IoT   (UNSW, 2018)   -> `bot_iot.load_bot_iot`
    * TON-IoT   (UNSW, 2020)   -> `ton_iot.load_ton_iot`

Each adapter returns a pandas.DataFrame whose columns are exactly
`FEATURE_NAMES + ['label']`, with labels drawn from
`config.THREAT_CLASSES` U {config.BENIGN_LABEL}.
"""
from .bot_iot import load_bot_iot
from .ton_iot import load_ton_iot

__all__ = ["load_bot_iot", "load_ton_iot"]