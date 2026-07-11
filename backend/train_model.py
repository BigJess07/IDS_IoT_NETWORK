"""
Train the Random Forest IDS model.

Usage:
    python -m backend.train_model

Outputs saved to backend/models/:
    rf_ids.joblib      trained sklearn RandomForestClassifier
    scaler.joblib      fitted StandardScaler
    features.json      ordered feature-name list (contract with inference)
    labels.json        classes_ list (index -> label)
"""
from __future__ import annotations

import json
import time

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from .config import (
    FEATURE_LIST_PATH,
    LABEL_MAP_PATH,
    MODEL_PATH,
    RF_PARAMS,
    SCALER_PATH,
)
from .data_preprocessing import load_dataset, split_and_scale
from .feature_extractor import FEATURE_NAMES


def main() -> None:
    print("[train] loading dataset …")
    df = load_dataset()
    print(f"[train] {len(df):,} rows, {df['label'].nunique()} classes")

    X_tr, X_te, y_tr, y_te, scaler = split_and_scale(df)
    print(f"[train] train={X_tr.shape}  test={X_te.shape}")

    clf = RandomForestClassifier(**RF_PARAMS)
    t0 = time.perf_counter()
    clf.fit(X_tr, y_tr)
    print(f"[train] fit complete in {(time.perf_counter() - t0) * 1000:,.0f} ms")

    y_pred = clf.predict(X_te)
    print("\n=== classification report ===")
    print(classification_report(y_te, y_pred, digits=3))
    print("=== confusion matrix (rows=true) ===")
    print(confusion_matrix(y_te, y_pred, labels=clf.classes_))

    joblib.dump(clf, MODEL_PATH, compress=3)
    joblib.dump(scaler, SCALER_PATH, compress=3)
    FEATURE_LIST_PATH.write_text(json.dumps(FEATURE_NAMES, indent=2))
    LABEL_MAP_PATH.write_text(json.dumps(list(clf.classes_), indent=2))

    size_kb = MODEL_PATH.stat().st_size / 1024
    print(f"\n[train] saved model -> {MODEL_PATH}  ({size_kb:,.1f} KB)")


if __name__ == "__main__":
    main()