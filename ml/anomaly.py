import os
import json
import httpx
from datetime import datetime, timezone
from database import get_db
from ml.anomaly_detector import get_detector

# ─────────────────────────────────────────
# ANCHOR ANOMALY AGENT v2
#
# Detection:   Isolation Forest (scikit-learn) — free, local, no API
# Explanation: Gemini API — only fires on genuinely anomalous events
#
# Risk escalation:
#   0–39   → none    (monitor quietly)
#   40–59  → warn    (log, alert admin)
#   60–79  → reauth  (force re-authentication)
#   80–100 → kill    (terminate session immediately)
# ─────────────────────────────────────────

GEMINI_MODEL   = "gemini-2.5-flash"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

GEMINI_THRESHOLD = 0.3


def run_anomaly_agent(
    session_uuid: str,
    user_id:      str,
    action:       str,
    endpoint:     str,
    data_volume:  int,
    ip_address:   str,
    client_id:    str = None,
    user_agent:   str = None
) -> dict:
    db = get_db()

    # ── Pull context ─────────────────────────────────────────
    recent_events      = _get_recent_events(db, session_uuid)
    cumulative_risk    = _get_cumulative_risk(db, session_uuid)   # FIX: reads risk_score correctly
    events_last_minute = _count_recent_events(recent_events, seconds=60)
    user_baseline      = _get_user_baseline(db, user_id)
    institution        = _get_institution(db, client_id)

    # ── IP/UA hijack detection ───────────────────────────────
    # Compare current request against session's registered values
    hijack_bonus = _check_hijack(db, session_uuid, ip_address, user_agent)
    if hijack_bonus > 0:
        new_cumulative = min(cumulative_risk + hijack_bonus, 100)
        verdict = {
            "cumulative_risk":    new_cumulative,
            "risk_contribution":  hijack_bonus,
            "action_required":    _escalate(new_cumulative),
            "explanation":        f"Session hijack detected — IP or device changed mid-session. Original session fingerprint does not match current request.",
            "attack_pattern":     "session hijacking",
            "recommended_action": "Kill session immediately and notify the account holder.",
            "popia_concern":      True,
            "confidence":         "high",
            "ml_score":           1.0
        }
        _store_verdict(db, session_uuid, user_id, new_cumulative, verdict, client_id)
        _log_threat_internal(session_uuid, "session_hijack_detected", ip_address, client_id)
        return verdict

    # ── Isolation Forest scoring ─────────────────────────────
    detector  = get_detector()
    ml_result = detector.score(
        action             = action,
        endpoint           = endpoint,
        data_volume        = data_volume,
        events_last_minute = events_last_minute,
        cumulative_risk    = cumulative_risk
    )

    anomaly_score  = ml_result["anomaly_score"]
    risk_added     = ml_result["risk_added"]
    new_cumulative = min(cumulative_risk + risk_added, 100)

    # ── Clearly normal — return without API call ─────────────
    if anomaly_score < GEMINI_THRESHOLD:
        verdict = {
            "cumulative_risk":    new_cumulative,
            "risk_contribution":  risk_added,
            "action_required":    _escalate(new_cumulative),
            "explanation":        "",
            "attack_pattern":     "none",
            "recommended_action": "Normal activity — no action required",
            "popia_concern":      False,
            "confidence":         ml_result["confidence"],
            "ml_score":           anomaly_score
        }
        _store_verdict(db, session_uuid, user_id, new_cumulative, verdict, client_id)
        return verdict

    # ── Anomalous — call Gemini for explanation ──────────────
    gemini_verdict = _call_gemini(
        session_uuid    = session_uuid,
        user_id         = user_id,
        action          = action,
        endpoint        = endpoint,
        data_volume     = data_volume,
        ip_address      = ip_address,
        recent_events   = recent_events,
        user_baseline   = user_baseline,
        cumulative_risk = cumulative_risk,
        institution     = institution,
        ml_score        = anomaly_score,
        ml_risk_added   = risk_added
    )

    final_risk_added = max(risk_added, gemini_verdict.get("risk_contribution", risk_added))
    final_cumulative = min(cumulative_risk + final_risk_added, 100)

    verdict = {
        "cumulative_risk":    final_cumulative,
        "risk_contribution":  final_risk_added,
        "action_required":    _escalate(final_cumulative),
        "explanation":        gemini_verdict.get("explanation", ""),
        "attack_pattern":     gemini_verdict.get("attack_pattern", "none"),
        "recommended_action": gemini_verdict.get("recommended_action", "Review session"),
        "popia_concern":      gemini_verdict.get("popia_concern", False),
        "confidence":         gemini_verdict.get("confidence", "medium"),
        "ml_score":           anomaly_score
    }

    _store_verdict(db, session_uuid, user_id, final_cumulative, verdict, client_id)

    # ── Auto-trigger POPIA if breach threshold crossed ───────
    try:
        from popia import check_and_generate_popia_report
        check_and_generate_popia_report(
            session_uuid = session_uuid,
            client_id    = client_id,
            verdict      = verdict
        )
    except Exception as e:
        print(f"[Anchor/POPIA] Auto-trigger failed: {e}")

    # ── Log as threat if action is kill/reauth ────────────────
    if verdict["action_required"] in ("kill", "reauth"):
        _log_threat_internal(
            session_uuid,
            f"anomaly:{verdict.get('attack_pattern', 'unknown')}",
            ip_address,
            client_id
        )

    return verdict


# ─────────────────────────────────────────
# HIJACK DETECTION
# ─────────────────────────────────────────

def _check_hijack(db, session_uuid: str, current_ip: str, current_ua: str) -> int:
    """
    Compares current IP/UA against what was registered at session creation.
    Returns risk bonus if mismatch detected, 0 if clean.
    """
    if not current_ip and not current_ua:
        return 0
    try:
        result = db.table("anchor_sessions") \
            .select("ip_address, user_agent") \
            .eq("session_uuid", session_uuid) \
            .limit(1) \
            .execute()
        if not result.data:
            return 0
        session      = result.data[0]
        original_ip  = session.get("ip_address")
        original_ua  = session.get("user_agent")
        ip_changed   = current_ip and original_ip and current_ip != original_ip
        ua_changed   = current_ua and original_ua and current_ua != original_ua
        if ip_changed and ua_changed:
            return 80   # both changed — very high confidence hijack
        if ip_changed:
            return 50   # IP changed — suspicious
        if ua_changed:
            return 30   # UA changed — moderate suspicion
    except Exception:
        pass
    return 0


# ─────────────────────────────────────────
# GEMINI EXPLANATION LAYER
# ─────────────────────────────────────────

def _call_gemini(
    session_uuid, user_id, action, endpoint, data_volume,
    ip_address, recent_events, user_baseline, cumulative_risk,
    institution, ml_score, ml_risk_added
) -> dict:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return _rule_fallback(action, endpoint, data_volume, cumulative_risk)

    try:
        prompt = _build_prompt(
            session_uuid, user_id, action, endpoint, data_volume,
            ip_address, recent_events, user_baseline, cumulative_risk,
            institution, ml_score, ml_risk_added
        )

        payload = {
            "system_instruction": {
                "parts": [{"text": _system_prompt()}]
            },
            "contents": [
                {"role": "user", "parts": [{"text": prompt}]}
            ],
            "generationConfig": {
                "temperature":      0.1,
                "maxOutputTokens":  600,
                "responseMimeType": "application/json"
            }
        }

        response = httpx.post(
            f"{GEMINI_API_URL}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=20.0
        )

        if response.status_code != 200:
            print(f"[Anchor/Gemini] API error {response.status_code}: {response.text[:200]}")
            return _rule_fallback(action, endpoint, data_volume, cumulative_risk)

        data     = response.json()
        raw_text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )
        return _parse_verdict(raw_text)

    except Exception as e:
        print(f"[Anchor/Gemini] Exception: {e}")
        return _rule_fallback(action, endpoint, data_volume, cumulative_risk)


def _system_prompt() -> str:
    return """You are Anchor's threat explanation agent — a cybersecurity analyst for 
South African institutions. The Anchor ML model has flagged a session event as anomalous.
Your job is to explain what is happening in plain English and recommend an action.

You understand: POPIA, OWASP Top 10, insider threats, data exfiltration, 
session hijacking, credential stuffing, and behavioural baseline deviation.

Respond ONLY with valid JSON. No preamble. No markdown. Raw JSON only.

{
  "risk_contribution": <integer 0-50>,
  "explanation": "<Plain English. What is this user doing and why is it concerning. Be specific.>",
  "attack_pattern": "<data exfiltration | insider threat | session hijacking | privilege escalation | reconnaissance | credential stuffing aftermath | novel pattern | none>",
  "recommended_action": "<One sentence — what the admin should do right now>",
  "popia_concern": <true|false>,
  "confidence": "<low|medium|high>"
}"""


def _build_prompt(
    session_uuid, user_id, action, endpoint, data_volume,
    ip_address, recent_events, user_baseline, cumulative_risk,
    institution, ml_score, ml_risk_added
) -> str:
    return f"""The Anchor ML model flagged this session event as anomalous.
Anomaly score: {ml_score:.2f}/1.0 (threshold: {GEMINI_THRESHOLD})
ML estimated risk contribution: {ml_risk_added}

CURRENT EVENT:
- Action:      {action}
- Endpoint:    {endpoint or "not specified"}
- Data volume: {data_volume} records
- IP address:  {ip_address or "unknown"}
- Time (UTC):  {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")}

SESSION:
- UUID:             {session_uuid}
- User:             {user_id}
- Institution:      {institution or "South African institution"}
- Cumulative risk:  {cumulative_risk}/100 before this event

USER BASELINE:
{_format_baseline(user_baseline)}

SESSION TIMELINE (last 20 events):
{_format_timeline(recent_events)}

The ML model says this is anomalous. Explain why, name the attack pattern, 
and tell the admin what to do."""


def _format_baseline(baseline: dict) -> str:
    if not baseline or baseline.get("session_count", 0) < 3:
        return "  Less than 3 prior sessions — no reliable baseline yet."
    return (
        f"  Sessions on record:          {baseline.get('session_count', 0)}\n"
        f"  Avg events per session:      {round(baseline.get('avg_events_per_session', 0), 1)}\n"
        f"  Avg data volume per session: {round(baseline.get('avg_data_volume', 0), 1)} records\n"
        f"  Typical hours (UTC):         {baseline.get('typical_hours', 'unknown')}"
    )


def _format_timeline(events: list) -> str:
    if not events:
        return "  No prior events this session."
    lines = []
    for e in sorted(events, key=lambda x: x.get("created_at", ""))[-20:]:
        ts      = e.get("created_at", "")[:19].replace("T", " ")
        action  = e.get("action", "unknown")
        ep      = e.get("endpoint", "")
        vol     = e.get("data_volume", 0)
        flagged = " ⚠" if e.get("flagged") else ""
        line    = f"  [{ts}] {action}"
        if ep:  line += f" → {ep}"
        if vol: line += f" ({vol} records)"
        line += flagged
        lines.append(line)
    return "\n".join(lines)


# ─────────────────────────────────────────
# RULE FALLBACK
# ─────────────────────────────────────────

def _rule_fallback(action, endpoint, data_volume, cumulative_risk) -> dict:
    score   = 0
    reasons = []

    SENSITIVE_ACTIONS = {
        "export_records", "bulk_download", "delete_records",
        "admin_access", "schema_access", "user_management",
        "permission_change", "config_change", "database_query",
        "mass_update", "backup_access"
    }
    SENSITIVE_ENDPOINTS = ["/admin", "/config", "/users", "/export", "/delete"]

    if action in SENSITIVE_ACTIONS:
        score += 20
        reasons.append(f"Sensitive action: {action}")
    if data_volume > 100:
        score += min(20, int((data_volume / 100) * 8))
        reasons.append(f"High data volume: {data_volume} records")
    if endpoint and any(endpoint.startswith(s) for s in SENSITIVE_ENDPOINTS):
        score += 10
        reasons.append(f"Sensitive endpoint: {endpoint}")
    hour = datetime.now(timezone.utc).hour
    if (hour >= 22 or hour < 5) and action in SENSITIVE_ACTIONS:
        score += 15
        reasons.append(f"Off-hours sensitive access at {hour}:00 UTC")

    return {
        "risk_contribution":  score,
        "explanation":        f"[Rule fallback] {'; '.join(reasons) or 'No specific rule matched'}",
        "attack_pattern":     "none",
        "recommended_action": "Review session manually",
        "popia_concern":      score >= 20,
        "confidence":         "low"
    }


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _escalate(score: int) -> str:
    if score >= 80: return "kill"
    if score >= 60: return "reauth"
    if score >= 40: return "warn"
    return "none"


def _parse_verdict(raw_text: str) -> dict:
    try:
        clean = raw_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean.strip())
    except Exception:
        return {
            "risk_contribution":  10,
            "explanation":        raw_text[:300] if raw_text else "Parse error",
            "attack_pattern":     "unknown",
            "recommended_action": "Review session manually",
            "popia_concern":      False,
            "confidence":         "low"
        }


def _get_cumulative_risk(db, session_uuid: str) -> int:
    """
    FIX: reads the latest risk_score from anchor_session_events.
    The old version summed risk_contribution which was always 0
    because session_events.py updates risk_score, not risk_contribution.
    """
    result = db.table("anchor_session_events") \
        .select("risk_score") \
        .eq("session_uuid", session_uuid) \
        .order("created_at", desc=True) \
        .limit(1) \
        .execute()
    if not result.data:
        return 0
    return result.data[0].get("risk_score", 0) or 0


def _get_recent_events(db, session_uuid: str) -> list:
    result = db.table("anchor_session_events") \
        .select("*") \
        .eq("session_uuid", session_uuid) \
        .order("created_at", desc=True) \
        .limit(50) \
        .execute()
    return result.data or []


def _count_recent_events(events: list, seconds: int = 60) -> int:
    now   = datetime.now(timezone.utc)
    count = 0
    for e in events:
        try:
            ts = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
            if (now - ts).total_seconds() <= seconds:
                count += 1
        except Exception:
            pass
    return count


def _get_user_baseline(db, user_id: str) -> dict:
    try:
        sessions = db.table("anchor_sessions") \
            .select("session_uuid") \
            .eq("user_id", user_id) \
            .execute()

        if not sessions.data or len(sessions.data) < 3:
            return {}

        uuids  = [s["session_uuid"] for s in sessions.data]
        events = db.table("anchor_session_events") \
            .select("session_uuid, data_volume, created_at") \
            .in_("session_uuid", uuids) \
            .execute()

        if not events.data:
            return {}

        stats = {}
        hours = []
        for e in events.data:
            sid = e["session_uuid"]
            if sid not in stats:
                stats[sid] = {"count": 0, "volume": 0}
            stats[sid]["count"]  += 1
            stats[sid]["volume"] += e.get("data_volume", 0)
            try:
                ts = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
                hours.append(ts.hour)
            except Exception:
                pass

        counts  = [s["count"]  for s in stats.values()]
        volumes = [s["volume"] for s in stats.values()]
        avg_h   = int(sum(hours) / len(hours)) if hours else 10
        typical = f"{max(0, avg_h - 3):02d}:00 – {min(23, avg_h + 3):02d}:00 UTC"

        return {
            "session_count":          len(stats),
            "avg_events_per_session": sum(counts) / len(counts),
            "avg_data_volume":        sum(volumes) / len(volumes),
            "typical_hours":          typical
        }
    except Exception:
        return {}


def _get_institution(db, client_id: str) -> str:
    if not client_id:
        return None
    try:
        r = db.table("anchor_clients") \
            .select("client_name, institution_type") \
            .eq("id", client_id) \
            .limit(1) \
            .execute()
        if r.data:
            return f"{r.data[0].get('client_name')} ({r.data[0].get('institution_type')})"
    except Exception:
        pass
    return None


def _store_verdict(db, session_uuid: str, user_id: str, risk: int, verdict: dict, client_id: str = None):
    """FIX: now writes client_id so dashboard filter finds these rows."""
    try:
        def _level(s):
            if s >= 80: return "critical"
            if s >= 60: return "high"
            if s >= 40: return "medium"
            return "low"

        db.table("anchor_ai_analyses").insert({
            "session_uuid":       session_uuid,
            "user_id":            user_id,
            "client_id":          client_id,
            "cumulative_risk":    risk,
            "risk_score":         risk,
            "threat_level":       _level(risk),
            "explanation":        verdict.get("explanation", ""),
            "attack_pattern":     verdict.get("attack_pattern", ""),
            "recommended_action": verdict.get("recommended_action", ""),
            "popia_concern":      verdict.get("popia_concern", False),
            "confidence":         verdict.get("confidence", "low"),
            "ml_score":           verdict.get("ml_score", 0),
            "created_at":         datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception as e:
        print(f"[Anchor/Anomaly] Store verdict failed: {e}")


def _log_threat_internal(session_uuid: str, threat_type: str, ip_address: str, client_id: str = None):
    """Internal threat logger — calls watcher with client_id."""
    try:
        from watcher import log_threat
        log_threat(session_uuid, threat_type, ip_address, client_id)
    except Exception:
        pass