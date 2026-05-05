import os
import json
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from database import get_db

load_dotenv()

# ─────────────────────────────────────────
# ANOMALY AGENT
#
# Full AI agent using Google Gemini (free tier).
# Reasons over session history, user baseline,
# and institution context in one shot.
#
# Falls back to rule engine if Gemini is unavailable
# so Anchor keeps working no matter what.
#
# Risk escalation ladder:
#   0–39   → none    (monitor quietly)
#   40–59  → warn    (log, alert admin)
#   60–79  → reauth  (force re-authentication)
#   80–100 → kill    (terminate session immediately)
# ─────────────────────────────────────────

GEMINI_MODEL   = "gemini-2.0-flash"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# Actions that always trigger agent — never skip these
HIGH_SENSITIVITY_ACTIONS = {
    "export_records", "bulk_download", "delete_records",
    "admin_access", "schema_access", "user_management",
    "permission_change", "config_change", "database_query",
    "mass_update", "backup_access"
}

# Endpoints worth analysing regardless of action
SENSITIVE_ENDPOINTS = [
    "/admin", "/config", "/users", "/export",
    "/delete", "/schema", "/backup", "/logs", "/permissions"
]

# Benign pre-filter thresholds
BENIGN_MAX_DATA_VOLUME       = 10
BENIGN_MAX_EVENTS_PER_MINUTE = 10


def run_anomaly_agent(
    session_uuid: str,
    user_id: str,
    action: str,
    endpoint: str,
    data_volume: int,
    ip_address: str,
    client_id: str = None
) -> dict:
    """
    Main entry point — called by session_events.py after every event.

    1. Fast pre-filter — is this clearly benign? Skip Gemini call.
    2. Pull session history + user baseline from Supabase
    3. Call Gemini agent with full context
    4. Return structured verdict

    Returns:
        cumulative_risk:    int 0-100
        risk_contribution:  int — what this event added
        action_required:    none / warn / reauth / kill
        explanation:        plain English — what is happening
        attack_pattern:     named pattern or "none"
        recommended_action: what admin should do
        popia_concern:      bool
        confidence:         low / medium / high
    """
    db = get_db()

    # ── Fast pre-filter ──────────────────────────────────────
    if _is_benign(action, endpoint, data_volume, session_uuid, db):
        cumulative = _get_cumulative_risk(db, session_uuid)
        return {
            "cumulative_risk":    cumulative,
            "risk_contribution":  0,
            "action_required":    "none",
            "explanation":        "",
            "attack_pattern":     "none",
            "recommended_action": "Normal activity — no action required",
            "popia_concern":      False,
            "confidence":         "high"
        }

    # ── Pull context from Supabase ───────────────────────────
    recent_events   = _get_recent_events(db, session_uuid)
    user_baseline   = _get_user_baseline(db, user_id)
    cumulative_risk = _get_cumulative_risk(db, session_uuid)
    institution     = _get_institution(db, client_id)

    # ── Call Gemini agent ────────────────────────────────────
    verdict = _call_gemini(
        session_uuid    = session_uuid,
        user_id         = user_id,
        action          = action,
        endpoint        = endpoint,
        data_volume     = data_volume,
        ip_address      = ip_address,
        recent_events   = recent_events,
        user_baseline   = user_baseline,
        cumulative_risk = cumulative_risk,
        institution     = institution
    )

    # ── Compute final cumulative risk ────────────────────────
    new_cumulative = min(cumulative_risk + verdict.get("risk_contribution", 0), 100)
    verdict["cumulative_risk"] = new_cumulative
    verdict["action_required"] = _escalate(new_cumulative)

    # ── Store verdict to Supabase for dashboard ──────────────
    _store_verdict(db, session_uuid, user_id, new_cumulative, verdict)

    return verdict


# ─────────────────────────────────────────
# GEMINI AGENT CORE
# ─────────────────────────────────────────

def _call_gemini(
    session_uuid, user_id, action, endpoint, data_volume,
    ip_address, recent_events, user_baseline, cumulative_risk, institution
) -> dict:
    """
    Builds the prompt, calls Gemini, parses the response.
    Falls back to rule engine if API key missing or call fails.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return _rule_fallback(action, endpoint, data_volume, recent_events, cumulative_risk)

    prompt = _build_prompt(
        session_uuid, user_id, action, endpoint, data_volume,
        ip_address, recent_events, user_baseline, cumulative_risk, institution
    )

    # Gemini wants system instruction + user message separately
    payload = {
        "system_instruction": {
            "parts": [{"text": _system_prompt()}]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature":     0.1,   # low temp — we want consistent JSON
            "maxOutputTokens": 1000,
            "responseMimeType": "application/json"  # forces JSON output
        }
    }

    try:
        response = httpx.post(
            f"{GEMINI_API_URL}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=25.0
        )

        if response.status_code != 200:
            print(f"[Anchor/Gemini] API error {response.status_code}: {response.text[:200]}")
            return _rule_fallback(action, endpoint, data_volume, recent_events, cumulative_risk)

        data = response.json()

        # Extract text from Gemini response structure
        raw_text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

        return _parse_verdict(raw_text)

    except Exception as e:
        print(f"[Anchor/Gemini] Exception: {e}")
        return _rule_fallback(action, endpoint, data_volume, recent_events, cumulative_risk)


# ─────────────────────────────────────────
# PROMPT CONSTRUCTION
# ─────────────────────────────────────────

def _system_prompt() -> str:
    return """You are Anchor's anomaly detection agent — an expert cybersecurity analyst 
specialising in post-authentication behavioural threat detection for South African 
institutions: universities, banks, and government portals.

Your job is to analyse session event timelines and determine whether a user session 
represents a genuine threat. You understand:
- OWASP Top 10 (especially A01 Broken Access Control, A09 Security Logging failures)
- POPIA compliance — South Africa's data protection law
- Attack patterns: insider threats, data exfiltration, session hijacking, 
  privilege escalation probing, reconnaissance, credential stuffing aftermath
- Behavioural baseline deviation — when something is unusual for THIS specific user
  even if it looks normal in isolation

You must respond ONLY with valid JSON. No preamble. No explanation. Raw JSON only.

Response format:
{
  "risk_contribution": <integer 0-50, how much risk THIS single event adds>,
  "explanation": "<Plain English. What is this user actually doing and why is it concerning. Write for a security admin. Be specific about the pattern you see across the timeline.>",
  "attack_pattern": "<One of: 'data exfiltration' | 'insider threat' | 'session hijacking' | 'privilege escalation probing' | 'reconnaissance' | 'credential stuffing aftermath' | 'novel pattern' | 'none'>",
  "recommended_action": "<What the security admin should do right now, in one sentence>",
  "popia_concern": <true|false>,
  "confidence": "<low|medium|high>"
}"""


def _build_prompt(
    session_uuid, user_id, action, endpoint, data_volume,
    ip_address, recent_events, user_baseline, cumulative_risk, institution
) -> str:

    baseline_text   = _format_baseline(user_baseline)
    timeline_text   = _format_timeline(recent_events)
    institution_text = institution or "South African institution (type unknown)"

    return f"""Analyse this session event and return a threat assessment.

CURRENT EVENT:
- Action:       {action}
- Endpoint:     {endpoint or "not specified"}
- Data volume:  {data_volume} records
- IP address:   {ip_address or "unknown"}
- Time (UTC):   {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")}

SESSION CONTEXT:
- Session UUID:      {session_uuid}
- User ID:           {user_id}
- Institution:       {institution_text}
- Cumulative risk:   {cumulative_risk}/100 before this event

USER BASELINE (historical behaviour):
{baseline_text}

SESSION TIMELINE (chronological, up to 50 events):
{timeline_text}

Assess: Is this a threat? What pattern does the full timeline suggest?
Is POPIA-protected data at risk? What should the admin do right now?"""


def _format_baseline(baseline: dict) -> str:
    if not baseline or baseline.get("session_count", 0) < 3:
        return "  Insufficient history — less than 3 prior sessions on record."
    return (
        f"  Sessions on record:           {baseline.get('session_count', 0)}\n"
        f"  Avg events per session:       {round(baseline.get('avg_events_per_session', 0), 1)}\n"
        f"  Avg data volume per session:  {round(baseline.get('avg_data_volume', 0), 1)} records\n"
        f"  Typical active hours (UTC):   {baseline.get('typical_hours', 'unknown')}"
    )


def _format_timeline(events: list) -> str:
    if not events:
        return "  No prior events this session."

    sorted_events = sorted(events, key=lambda e: e.get("created_at", ""))
    lines = []

    for e in sorted_events[-50:]:
        ts      = e.get("created_at", "")[:19].replace("T", " ")
        action  = e.get("action", "unknown")
        ep      = e.get("endpoint", "")
        vol     = e.get("data_volume", 0)
        flagged = " ⚠️" if e.get("flagged") else ""

        line = f"  [{ts}] {action}"
        if ep:
            line += f" → {ep}"
        if vol > 0:
            line += f" ({vol} records)"
        line += flagged
        lines.append(line)

    if len(events) > 50:
        lines.insert(0, f"  [Showing last 50 of {len(events)} total events]")

    return "\n".join(lines)


# ─────────────────────────────────────────
# BENIGN PRE-FILTER
# Skip Gemini call if clearly low risk
# Any doubt → goes to the agent
# ─────────────────────────────────────────

def _is_benign(action: str, endpoint: str, data_volume: int, session_uuid: str, db) -> bool:
    if action in HIGH_SENSITIVITY_ACTIONS:
        return False
    if endpoint and any(endpoint.startswith(s) for s in SENSITIVE_ENDPOINTS):
        return False
    if data_volume > BENIGN_MAX_DATA_VOLUME:
        return False

    recent = _get_recent_events(db, session_uuid)
    events_last_minute = [
        e for e in recent
        if _seconds_ago(e.get("created_at", "")) <= 60
    ]
    if len(events_last_minute) >= BENIGN_MAX_EVENTS_PER_MINUTE:
        return False

    return True


# ─────────────────────────────────────────
# RULE FALLBACK
# Only used when Gemini is unavailable
# Keeps Anchor functional without AI
# ─────────────────────────────────────────

def _rule_fallback(action, endpoint, data_volume, recent_events, cumulative_risk) -> dict:
    score   = 0
    reasons = []

    if action in HIGH_SENSITIVITY_ACTIONS:
        score += 20
        reasons.append(f"High sensitivity action: {action}")

    if data_volume > 100:
        score += min(25, int((data_volume / 100) * 10))
        reasons.append(f"Bulk data access: {data_volume} records")

    if endpoint and any(endpoint.startswith(s) for s in SENSITIVE_ENDPOINTS):
        score += 15
        reasons.append(f"Sensitive endpoint: {endpoint}")

    hour = datetime.now(timezone.utc).hour
    if (hour >= 22 or hour < 6) and action in HIGH_SENSITIVITY_ACTIONS:
        score += 15
        reasons.append(f"Off-hours sensitive action at {hour}:00 UTC")

    explanation    = "; ".join(reasons) if reasons else "No specific rules triggered"
    new_cumulative = min(cumulative_risk + score, 100)

    return {
        "risk_contribution":  score,
        "cumulative_risk":    new_cumulative,
        "action_required":    _escalate(new_cumulative),
        "explanation":        f"[Rule fallback — Gemini unavailable] {explanation}",
        "attack_pattern":     "none",
        "recommended_action": "Review session manually — AI analysis unavailable",
        "popia_concern":      score >= 25,
        "confidence":         "low"
    }


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _escalate(cumulative_risk: int) -> str:
    if cumulative_risk >= 80: return "kill"
    if cumulative_risk >= 60: return "reauth"
    if cumulative_risk >= 40: return "warn"
    return "none"


def _get_cumulative_risk(db, session_uuid: str) -> int:
    result = db.table("anchor_session_events") \
        .select("risk_contribution") \
        .eq("session_uuid", session_uuid) \
        .execute()
    if not result.data:
        return 0
    return min(sum(e.get("risk_contribution", 0) for e in result.data), 100)


def _get_recent_events(db, session_uuid: str) -> list:
    result = db.table("anchor_session_events") \
        .select("*") \
        .eq("session_uuid", session_uuid) \
        .order("created_at", desc=True) \
        .limit(200) \
        .execute()
    return result.data or []


def _get_user_baseline(db, user_id: str) -> dict:
    try:
        sessions_result = db.table("anchor_sessions") \
            .select("session_uuid") \
            .eq("user_id", user_id) \
            .execute()

        if not sessions_result.data or len(sessions_result.data) < 3:
            return {}

        session_uuids = [s["session_uuid"] for s in sessions_result.data]

        events_result = db.table("anchor_session_events") \
            .select("session_uuid, data_volume, created_at") \
            .in_("session_uuid", session_uuids) \
            .execute()

        if not events_result.data:
            return {}

        events = events_result.data
        session_stats = {}
        hours = []

        for e in events:
            sid = e["session_uuid"]
            if sid not in session_stats:
                session_stats[sid] = {"count": 0, "volume": 0}
            session_stats[sid]["count"]  += 1
            session_stats[sid]["volume"] += e.get("data_volume", 0)
            try:
                ts = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
                hours.append(ts.hour)
            except Exception:
                pass

        counts  = [s["count"]  for s in session_stats.values()]
        volumes = [s["volume"] for s in session_stats.values()]

        if hours:
            avg_hour      = int(sum(hours) / len(hours))
            typical_hours = f"{max(0, avg_hour - 3):02d}:00 – {min(23, avg_hour + 3):02d}:00 UTC"
        else:
            typical_hours = "unknown"

        return {
            "session_count":          len(session_stats),
            "avg_events_per_session": sum(counts)  / len(counts)  if counts  else 0,
            "avg_data_volume":        sum(volumes) / len(volumes) if volumes else 0,
            "typical_hours":          typical_hours
        }

    except Exception:
        return {}


def _get_institution(db, client_id: str) -> str:
    if not client_id:
        return None
    try:
        result = db.table("anchor_clients") \
            .select("client_name, institution_type") \
            .eq("id", client_id) \
            .limit(1) \
            .execute()
        if result.data:
            r = result.data[0]
            return f"{r.get('client_name', 'Unknown')} ({r.get('institution_type', 'institution')})"
    except Exception:
        pass
    return None


def _parse_verdict(raw_text: str) -> dict:
    try:
        clean = raw_text.strip()
        # Strip markdown fences if Gemini adds them despite responseMimeType
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean.strip())
    except Exception:
        return {
            "risk_contribution":  10,
            "explanation":        raw_text[:300] if raw_text else "Analysis parse error",
            "attack_pattern":     "unknown",
            "recommended_action": "Review session manually",
            "popia_concern":      False,
            "confidence":         "low"
        }


def _store_verdict(db, session_uuid: str, user_id: str, risk: int, verdict: dict):
    try:
        db.table("anchor_ai_analyses").insert({
            "session_uuid":       session_uuid,
            "user_id":            user_id,
            "risk_score":         risk,
            "threat_level":       _risk_level(risk),
            "explanation":        verdict.get("explanation", ""),
            "attack_pattern":     verdict.get("attack_pattern", ""),
            "recommended_action": verdict.get("recommended_action", ""),
            "popia_concern":      verdict.get("popia_concern", False),
            "confidence":         verdict.get("confidence", "low"),
            "created_at":         datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception:
        pass


def _risk_level(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    return "low"


def _seconds_ago(timestamp_str: str) -> float:
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return 9999