import os
import pickle
import numpy as np
from datetime import datetime, timezone

# ─────────────────────────────────────────
# ANCHOR ANOMALY DETECTOR
#
# Isolation Forest — scikit-learn
# Replaces Gemini for detection so API credits
# are only spent on explanation, not scoring.
#
# Feature vector (7 features per event):
#   0. hour_of_day          (0–23)
#   1. day_of_week          (0–6, Mon=0)
#   2. data_volume          (records accessed)
#   3. events_last_minute   (velocity)
#   4. is_sensitive_action  (0 or 1)
#   5. is_sensitive_endpoint(0 or 1)
#   6. cumulative_risk      (0–100)
# ─────────────────────────────────────────

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

SENSITIVE_ACTIONS = {
    "export_records", "bulk_download", "delete_records",
    "admin_access", "schema_access", "user_management",
    "permission_change", "config_change", "database_query",
    "mass_update", "backup_access"
}

SENSITIVE_ENDPOINTS = [
    "/admin", "/config", "/users", "/export",
    "/delete", "/schema", "/backup", "/logs", "/permissions"
]


class AnchorAnomalyDetector:
    """
    Wraps sklearn IsolationForest.
    Trained once on synthetic baseline data.
    In production: retrained nightly on real session history.
    """

    def __init__(self):
        self.model = None
        self._load()

    def _load(self):
        """Load model from disk if it exists."""
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                print("[Anchor/ML] Isolation Forest model loaded")
            except Exception as e:
                print(f"[Anchor/ML] Failed to load model: {e}")
                self.model = None
        else:
            print("[Anchor/ML] No model found — run ml/train.py to train")

    def save(self, model):
        """Save trained model to disk."""
        self.model = model
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        print(f"[Anchor/ML] Model saved to {MODEL_PATH}")

    def is_ready(self) -> bool:
        return self.model is not None

    def build_features(
        self,
        action: str,
        endpoint: str,
        data_volume: int,
        events_last_minute: int,
        cumulative_risk: int,
        timestamp: datetime = None
    ) -> np.ndarray:
        """
        Convert raw event data into the 7-feature vector.
        Same feature extraction used at training and at inference.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        hour_of_day           = timestamp.hour
        day_of_week           = timestamp.weekday()
        is_sensitive_action   = 1 if action in SENSITIVE_ACTIONS else 0
        is_sensitive_endpoint = 1 if (
            endpoint and any(endpoint.startswith(s) for s in SENSITIVE_ENDPOINTS)
        ) else 0

        return np.array([[
            hour_of_day,
            day_of_week,
            min(data_volume, 10000),   # cap extreme values
            min(events_last_minute, 100),
            is_sensitive_action,
            is_sensitive_endpoint,
            cumulative_risk
        ]], dtype=float)

    def score(
        self,
        action: str,
        endpoint: str,
        data_volume: int,
        events_last_minute: int,
        cumulative_risk: int,
        timestamp: datetime = None
    ) -> dict:
        """
        Score a single event.

        Returns:
            anomaly_score:  float 0.0–1.0  (higher = more anomalous)
            is_anomaly:     bool
            confidence:     low / medium / high
            risk_added:     int 0–40 (added to cumulative risk)
        """
        if not self.is_ready():
            return _no_model_fallback(action, data_volume, cumulative_risk)

        features = self.build_features(
            action, endpoint, data_volume,
            events_last_minute, cumulative_risk, timestamp
        )

        # decision_function: negative = anomalous, positive = normal
        raw_score = self.model.decision_function(features)[0]

        # Normalise to 0–1 where 1 = most anomalous
        # Typical range is roughly -0.5 to 0.5
        anomaly_score = max(0.0, min(1.0, (0.3 - raw_score) / 0.6))
        is_anomaly    = self.model.predict(features)[0] == -1

        # Map anomaly score to risk contribution
        if anomaly_score >= 0.8:
            risk_added  = 40
            confidence  = "high"
        elif anomaly_score >= 0.6:
            risk_added  = 25
            confidence  = "medium"
        elif anomaly_score >= 0.4:
            risk_added  = 10
            confidence  = "medium"
        else:
            risk_added  = 0
            confidence  = "high"

        return {
            "anomaly_score": round(anomaly_score, 3),
            "is_anomaly":    is_anomaly,
            "confidence":    confidence,
            "risk_added":    risk_added
        }


def _no_model_fallback(action: str, data_volume: int, cumulative_risk: int) -> dict:
    """
    Used when model hasn't been trained yet.
    Simple rules — keeps Anchor functional.
    """
    score = 0
    if action in SENSITIVE_ACTIONS:
        score += 20
    if data_volume > 100:
        score += 15

    return {
        "anomaly_score": round(score / 100, 3),
        "is_anomaly":    score >= 20,
        "confidence":    "low",
        "risk_added":    score
    }


# Singleton — loaded once at startup, reused across requests
_detector = None

def get_detector() -> AnchorAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnchorAnomalyDetector()
    return _detector
