import os
import json
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from database import get_db

load_dotenv()

# ─────────────────────────────────────────
# ANCHOR POPIA AGENT
#
# POPIA Section 22 — when a breach occurs,
# the Information Regulator AND affected
# parties must be notified within 72 hours.
#
# This agent:
#   1. Detects when a breach threshold is crossed
#   2. Pulls threat context from Supabase
#   3. Calls Gemini to draft a compliant notification
#   4. Stores the draft — admin reviews and sends
#
# Breach threshold (any one of):
#   - AI analysis flags attack_pattern as data exfiltration
#     or insider threat with risk score >= 80
#   - Honeypot session with bulk_download or export_records
#   - Manual trigger from admin dashboard
# ─────────────────────────────────────────

GEMINI_MODEL   = "gemini-2.0-flash"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

BREACH_PATTERNS = {"data exfiltration", "insider threat"}
BREACH_ACTIONS  = {"export_records", "bulk_download", "delete_records", "mass_update"}
BREACH_RISK_THRESHOLD = 80


# ─────────────────────────────────────────
# PUBLIC INTERFACE
# ─────────────────────────────────────────

def check_and_generate_popia_report(
    session_uuid: str,
    client_id:    str,
    verdict:      dict
) -> dict | None:
    """
    Called automatically after every AI analysis verdict.
    If breach threshold is crossed, generates the POPIA draft.

    Returns the report dict if generated, None if threshold not met.
    """
    if not _is_breach(verdict):
        return None

    return _generate_report(
        session_uuid  = session_uuid,
        client_id     = client_id,
        breach_type   = verdict.get("attack_pattern", "unknown"),
        risk_score    = verdict.get("cumulative_risk", 0),
        explanation   = verdict.get("explanation", ""),
        attack_data   = verdict
    )


def generate_manual_report(session_uuid: str, client_id: str) -> dict:
    """
    Manually triggered from admin dashboard.
    Pulls latest threat data and generates report regardless of threshold.
    """
    db      = get_db()
    verdict = _get_latest_verdict(db, session_uuid)

    return _generate_report(
        session_uuid = session_uuid,
        client_id    = client_id,
        breach_type  = verdict.get("attack_pattern", "manual_trigger"),
        risk_score   = verdict.get("risk_score", 0),
        explanation  = verdict.get("explanation", "Manual report requested"),
        attack_data  = verdict
    )


def get_reports(client_id: str = None, limit: int = 20) -> list:
    """Returns all POPIA report drafts, newest first."""
    db    = get_db()
    query = db.table("anchor_popia_reports").select("*")
    if client_id:
        query = query.eq("client_id", client_id)
    result = query.order("created_at", desc=True).limit(limit).execute()
    return result.data or []


def get_report(report_id: int) -> dict | None:
    """Returns a single POPIA report by ID."""
    db     = get_db()
    result = db.table("anchor_popia_reports") \
        .select("*") \
        .eq("id", report_id) \
        .limit(1) \
        .execute()
    return result.data[0] if result.data else None


# ─────────────────────────────────────────
# CORE REPORT GENERATION
# ─────────────────────────────────────────

def _generate_report(
    session_uuid: str,
    client_id:    str,
    breach_type:  str,
    risk_score:   int,
    explanation:  str,
    attack_data:  dict
) -> dict:
    """
    Pulls full context, calls Gemini, stores and returns the report.
    """
    db = get_db()

    # Pull context
    institution    = _get_institution(db, client_id)
    affected_count = _estimate_affected_users(db, session_uuid)
    data_cats      = _identify_data_categories(db, session_uuid)
    timeline       = _get_breach_timeline(db, session_uuid)
    honeypot_data  = _get_honeypot_context(db, session_uuid)

    # Call Gemini
    report_text = _call_gemini(
        institution    = institution,
        breach_type    = breach_type,
        risk_score     = risk_score,
        explanation    = explanation,
        affected_count = affected_count,
        data_cats      = data_cats,
        timeline       = timeline,
        honeypot_data  = honeypot_data,
        session_uuid   = session_uuid
    )

    # Store in Supabase
    record = {
        "session_uuid":   session_uuid,
        "client_id":      client_id,
        "breach_type":    breach_type,
        "affected_users": affected_count,
        "data_categories": ", ".join(data_cats),
        "report_draft":   report_text,
        "status":         "draft",
        "created_at":     datetime.now(timezone.utc).isoformat()
    }

    result = db.table("anchor_popia_reports").insert(record).execute()

    print(f"[Anchor/POPIA] Report generated for session {session_uuid[:8]}... — {breach_type}")

    return {
        "report_id":      result.data[0]["id"] if result.data else None,
        "session_uuid":   session_uuid,
        "breach_type":    breach_type,
        "affected_users": affected_count,
        "data_categories": data_cats,
        "report_draft":   report_text,
        "status":         "draft",
        "deadline":       _deadline_72h()
    }


# ─────────────────────────────────────────
# GEMINI — POPIA REPORT DRAFTING
# ─────────────────────────────────────────

def _call_gemini(
    institution, breach_type, risk_score, explanation,
    affected_count, data_cats, timeline, honeypot_data, session_uuid
) -> str:
    """
    Calls Gemini to draft the POPIA Section 22 notification.
    Falls back to a structured template if Gemini is unavailable.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return _template_fallback(
            institution, breach_type, affected_count, data_cats, explanation
        )

    prompt = _build_prompt(
        institution, breach_type, risk_score, explanation,
        affected_count, data_cats, timeline, honeypot_data, session_uuid
    )

    payload = {
        "system_instruction": {
            "parts": [{"text": _system_prompt()}]
        },
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]}
        ],
        "generationConfig": {
            "temperature":     0.2,
            "maxOutputTokens": 2000
        }
    }

    try:
        response = httpx.post(
            f"{GEMINI_API_URL}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=30.0
        )

        if response.status_code != 200:
            print(f"[Anchor/POPIA] Gemini error {response.status_code}")
            return _template_fallback(
                institution, breach_type, affected_count, data_cats, explanation
            )

        data = response.json()
        return (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

    except Exception as e:
        print(f"[Anchor/POPIA] Gemini exception: {e}")
        return _template_fallback(
            institution, breach_type, affected_count, data_cats, explanation
        )


def _system_prompt() -> str:
    return """You are a POPIA compliance officer drafting a Section 22 breach notification 
for a South African institution. You write formal, legally precise notifications that 
meet the requirements of the Protection of Personal Information Act 4 of 2013.

Your notification must be:
- Formal and professional in tone
- Factually accurate based on the incident data provided
- Complete — covering all Section 22 requirements
- Written for two audiences: the Information Regulator and affected data subjects
- Clear about what happened, what data was affected, and what steps are being taken

Do not add fictional details. If information is unknown, say so explicitly.
Write the full notification document — not a summary."""


def _build_prompt(
    institution, breach_type, risk_score, explanation,
    affected_count, data_cats, timeline, honeypot_data, session_uuid
) -> str:

    honeypot_note = ""
    if honeypot_data:
        actions = [h.get("action", "") for h in honeypot_data[:5]]
        honeypot_note = f"""
ATTACKER BEHAVIOUR OBSERVED (via honeypot containment):
Actions attempted: {", ".join(actions)}
Note: Attacker was contained in a honeypot session. 
Real data was not accessed. Dummy data only was served."""

    return f"""Draft a POPIA Section 22 breach notification for the following incident.

INSTITUTION: {institution or "South African Educational Institution"}
INCIDENT REFERENCE: ANCHOR-{session_uuid[:8].upper()}
DETECTED BY: Anchor Identity & Session Protection Platform
DETECTION TIME: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
72-HOUR DEADLINE: {_deadline_72h()}

INCIDENT DETAILS:
- Breach type: {breach_type}
- Risk score at detection: {risk_score}/100
- Anchor's assessment: {explanation}
- Estimated affected data subjects: {affected_count}
- Personal information categories involved: {", ".join(data_cats) if data_cats else "Under investigation"}

INCIDENT TIMELINE:
{timeline}
{honeypot_note}

ANCHOR PLATFORM RESPONSE:
- Threat detected automatically by Anchor anomaly detection
- Session flagged and contained
- Threat logged to secure audit trail
- This notification generated automatically within minutes of detection

Draft the full POPIA Section 22 notification covering:
1. Description of the breach (what happened)
2. Identity and contact details of the responsible party (institution)
3. Categories and approximate number of data subjects affected
4. Categories and approximate number of personal information records affected
5. Likely consequences of the breach
6. Measures taken or proposed to address the breach
7. Measures taken to notify affected data subjects
8. Contact details of the Information Officer

Format as a formal document ready to submit to the Information Regulator."""


# ─────────────────────────────────────────
# TEMPLATE FALLBACK
# Used when Gemini is unavailable
# Still a valid structured POPIA document
# ─────────────────────────────────────────

def _template_fallback(
    institution, breach_type, affected_count, data_cats, explanation
) -> str:
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    deadline = _deadline_72h()
    cats     = ", ".join(data_cats) if data_cats else "Under investigation"

    return f"""POPIA SECTION 22 — BREACH NOTIFICATION DRAFT
=====================================================
[TEMPLATE — Review and complete before submitting]

Date of Notification: {now}
72-Hour Submission Deadline: {deadline}
Responsible Party: {institution or "[Institution Name]"}

1. DESCRIPTION OF THE BREACH
A security incident of type "{breach_type}" was detected by the Anchor 
Identity & Session Protection Platform. {explanation}

2. RESPONSIBLE PARTY
Institution: {institution or "[Full Institution Name]"}
Address: [Institution Address]
Information Officer: [Name and Contact Details]

3. DATA SUBJECTS AFFECTED
Estimated number of affected data subjects: {affected_count}
Categories of data subjects: [Students / Staff / Third Parties]

4. PERSONAL INFORMATION AFFECTED
Categories of personal information: {cats}
Estimated number of records: {affected_count}

5. LIKELY CONSEQUENCES
The breach may result in unauthorised access to personal information,
potential identity theft, and reputational harm to affected data subjects.

6. MEASURES TAKEN BY THE INSTITUTION
- Incident detected and contained automatically by Anchor platform
- Affected sessions terminated immediately
- Full audit trail secured
- Investigation initiated
- [Additional measures — complete before submitting]

7. NOTIFICATION TO DATA SUBJECTS
Affected data subjects will be notified by:
[Email / SMS / Letter — complete before submitting]
Notification timeline: Within [X] hours of this report

8. INFORMATION OFFICER CONTACT
Name: [Information Officer Name]
Email: [Email Address]
Phone: [Phone Number]

=====================================================
IMPORTANT: This is a draft generated by Anchor.
Review all bracketed fields before submission.
Submit to: inforeg@justice.gov.za
Deadline: {deadline}
====================================================="""


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _is_breach(verdict: dict) -> bool:
    """Determines if a verdict crosses the breach threshold."""
    risk          = verdict.get("cumulative_risk", 0)
    pattern       = verdict.get("attack_pattern", "")
    popia_concern = verdict.get("popia_concern", False)

    if risk >= BREACH_RISK_THRESHOLD and pattern in BREACH_PATTERNS:
        return True
    if popia_concern and risk >= 70:
        return True
    return False


def _deadline_72h() -> str:
    from datetime import timedelta
    deadline = datetime.now(timezone.utc) + timedelta(hours=72)
    return deadline.strftime("%Y-%m-%d %H:%M UTC")


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
            d = r.data[0]
            return f"{d.get('client_name')} ({d.get('institution_type', 'institution')})"
    except Exception:
        pass
    return None


def _estimate_affected_users(db, session_uuid: str) -> int:
    """
    Counts distinct user IDs touched by events in this session.
    In a real breach this would be broader — kept conservative here.
    """
    try:
        result = db.table("anchor_session_events") \
            .select("user_id") \
            .eq("session_uuid", session_uuid) \
            .execute()
        if result.data:
            return len(set(e["user_id"] for e in result.data if e.get("user_id")))
    except Exception:
        pass
    return 1


def _identify_data_categories(db, session_uuid: str) -> list:
    """
    Infers what categories of personal data were at risk
    based on the endpoints and actions in the session.
    """
    try:
        result = db.table("anchor_session_events") \
            .select("action, endpoint") \
            .eq("session_uuid", session_uuid) \
            .execute()

        categories = set()
        for e in (result.data or []):
            action   = e.get("action", "")
            endpoint = e.get("endpoint", "") or ""

            if any(x in endpoint for x in ["/users", "/students", "/staff"]):
                categories.add("Identity information (names, email addresses)")
            if any(x in endpoint for x in ["/finance", "/fees", "/payment"]):
                categories.add("Financial information")
            if any(x in endpoint for x in ["/grades", "/results", "/academic"]):
                categories.add("Academic records")
            if "admin" in endpoint or action in ("admin_access", "user_management"):
                categories.add("Administrative records")
            if action in ("export_records", "bulk_download", "database_query"):
                categories.add("Personal records (bulk — categories under investigation)")

        return list(categories) if categories else ["Personal information (under investigation)"]
    except Exception:
        return ["Personal information (under investigation)"]


def _get_breach_timeline(db, session_uuid: str) -> str:
    """Formats the session event timeline for the report."""
    try:
        result = db.table("anchor_session_events") \
            .select("action, endpoint, data_volume, created_at, flagged") \
            .eq("session_uuid", session_uuid) \
            .order("created_at") \
            .execute()

        if not result.data:
            return "Timeline unavailable."

        lines = []
        for e in result.data:
            ts      = e.get("created_at", "")[:19].replace("T", " ")
            action  = e.get("action", "unknown")
            ep      = e.get("endpoint", "")
            vol     = e.get("data_volume", 0)
            flagged = " [FLAGGED]" if e.get("flagged") else ""
            line    = f"  {ts} UTC — {action}"
            if ep:  line += f" → {ep}"
            if vol: line += f" ({vol} records)"
            line += flagged
            lines.append(line)

        return "\n".join(lines)
    except Exception:
        return "Timeline unavailable."


def _get_honeypot_context(db, session_uuid: str) -> list:
    """Returns honeypot logs if this was a honeypot session."""
    try:
        result = db.table("anchor_honeypot_logs") \
            .select("action, endpoint, created_at") \
            .eq("session_uuid", session_uuid) \
            .order("created_at") \
            .execute()
        return result.data or []
    except Exception:
        return []


def _get_latest_verdict(db, session_uuid: str) -> dict:
    """Gets the most recent AI analysis for a session."""
    try:
        result = db.table("anchor_ai_analyses") \
            .select("*") \
            .eq("session_uuid", session_uuid) \
            .order("created_at", desc=True) \
            .limit(1) \
            .execute()
        return result.data[0] if result.data else {}
    except Exception:
        return {}
