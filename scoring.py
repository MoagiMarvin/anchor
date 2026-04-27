def calculate_risk_score(fingerprint_match, ip_changed, ua_changed, session_age_minutes):
    score = 0
    reasons = []
    if not fingerprint_match:
        score += 60
        reasons.append("Fingerprint mismatch detected")
        if ip_changed:
            score += 25
            reasons.append("IP address changed mid-session")
        if ua_changed:
            score += 15
            reasons.append("Browser/device changed mid-session")
    score = min(score, 100)
    if score == 0:
        level = "safe"
    elif score < 30:
        level = "low"
    elif score < 60:
        level = "medium"
    elif score < 80:
        level = "high"
    else:
        level = "critical"
    return {"score": score, "level": level, "reasons": reasons}
