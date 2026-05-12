"""
ANCHOR — Isolation Forest Training Script
Run this once before starting the API:

    cd ~/anchor
    python ml/train.py

For production: add this to a nightly cron job to retrain
on real session data from Supabase.
"""

import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from datetime import datetime

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# ─────────────────────────────────────────
# SYNTHETIC NORMAL SESSION DATA
#
# Represents what legitimate university/institution
# user behaviour looks like:
# - Business hours (07:00–18:00 SAST = 05:00–16:00 UTC)
# - Weekdays mostly
# - Low data volumes per event (1–20 records)
# - Low velocity (1–5 events per minute)
# - Low sensitivity actions mostly
# - Low cumulative risk
# ─────────────────────────────────────────

def generate_normal_sessions(n: int = 5000) -> np.ndarray:
    """
    Synthetic baseline — normal institutional user behaviour.
    Feature order:
        [hour_of_day, day_of_week, data_volume, events_last_minute,
         is_sensitive_action, is_sensitive_endpoint, cumulative_risk]
    """
    rng = np.random.default_rng(42)

    # Business hours: 5–16 UTC (07:00–18:00 SAST)
    hours        = rng.integers(5, 17, n)
    days         = rng.integers(0, 5, n)         # Mon–Fri
    data_volumes = rng.integers(0, 20, n)        # small reads
    velocities   = rng.integers(1, 6, n)         # 1–5 events/min
    sensitive_a  = rng.choice([0, 1], n, p=[0.85, 0.15])  # 15% sensitive
    sensitive_e  = rng.choice([0, 1], n, p=[0.90, 0.10])  # 10% sensitive endpoint
    risk         = rng.integers(0, 20, n)        # low cumulative risk

    return np.column_stack([
        hours, days, data_volumes, velocities,
        sensitive_a, sensitive_e, risk
    ]).astype(float)


def generate_attack_samples(n: int = 500) -> np.ndarray:
    """
    Known attack patterns — for validation only.
    NOT fed into training (Isolation Forest is unsupervised).
    Used to verify the model catches real threats.
    """
    rng = np.random.default_rng(99)
    samples = []

    # Data exfiltration: high volume, off-hours, sensitive action
    for _ in range(n // 5):
        samples.append([
            rng.integers(0, 5),      # off-hours (midnight–5am UTC)
            rng.integers(0, 7),
            rng.integers(500, 5000), # massive volume
            rng.integers(15, 60),    # high velocity
            1,                       # sensitive action
            1,                       # sensitive endpoint
            rng.integers(40, 80)     # elevated risk
        ])

    # Bulk download: any hour, high volume, sequential
    for _ in range(n // 5):
        samples.append([
            rng.integers(5, 20),
            rng.integers(0, 7),
            rng.integers(200, 2000),
            rng.integers(10, 30),
            1,
            rng.choice([0, 1]),
            rng.integers(20, 60)
        ])

    # Off-hours admin: night access to admin endpoints
    for _ in range(n // 5):
        samples.append([
            rng.choice([0, 1, 2, 3, 22, 23]),
            rng.integers(0, 7),
            rng.integers(0, 50),
            rng.integers(1, 10),
            1,
            1,
            rng.integers(30, 70)
        ])

    # Rapid fire: bot-speed event velocity
    for _ in range(n // 5):
        samples.append([
            rng.integers(5, 17),
            rng.integers(0, 5),
            rng.integers(1, 10),
            rng.integers(40, 100),   # bot speed
            rng.choice([0, 1]),
            rng.choice([0, 1]),
            rng.integers(0, 50)
        ])

    # Weekend admin: sensitive action on weekend
    for _ in range(n // 5):
        samples.append([
            rng.integers(0, 24),
            rng.choice([5, 6]),      # Sat/Sun
            rng.integers(50, 500),
            rng.integers(5, 20),
            1,
            1,
            rng.integers(20, 60)
        ])

    return np.array(samples, dtype=float)


def train():
    print("=" * 50)
    print("Anchor — Isolation Forest Training")
    print("=" * 50)

    # Generate training data
    print("\n[1/4] Generating synthetic session data...")
    X_train = generate_normal_sessions(n=5000)
    print(f"      Training samples: {len(X_train)}")

    # Train
    print("\n[2/4] Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=200,       # more trees = better accuracy
        contamination=0.05,     # assume 5% of events are anomalous
        max_samples="auto",
        random_state=42,
        n_jobs=-1               # use all CPU cores
    )
    model.fit(X_train)
    print("      Training complete")

    # Validate on attack samples
    print("\n[3/4] Validating on known attack patterns...")
    X_attacks = generate_attack_samples(n=500)
    predictions = model.predict(X_attacks)
    detected    = (predictions == -1).sum()
    recall      = detected / len(X_attacks) * 100
    print(f"      Attack recall: {detected}/{len(X_attacks)} ({recall:.1f}%)")

    # Validate false positive rate on normal data
    X_normal_test = generate_normal_sessions(n=1000)
    normal_preds  = model.predict(X_normal_test)
    false_pos     = (normal_preds == -1).sum()
    fp_rate       = false_pos / len(X_normal_test) * 100
    print(f"      False positive rate: {false_pos}/{len(X_normal_test)} ({fp_rate:.1f}%)")

    # Save
    print("\n[4/4] Saving model...")
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"      Saved to: {MODEL_PATH}")

    print("\n" + "=" * 50)
    print(f"Done. Model ready for Anchor.")
    print(f"Recall: {recall:.1f}% | False positive rate: {fp_rate:.1f}%")
    print("=" * 50)


if __name__ == "__main__":
    train()
