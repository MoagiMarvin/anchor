from datetime import datetime, timezone
from collections import defaultdict

# Simple in-memory rate limiter
# Tracks requests per API key per minute
request_counts = defaultdict(list)

MAX_REQUESTS_PER_MINUTE = 60

def check_rate_limit(api_key: str):
    """
    Allows max 60 requests per minute per client.
    Directly addresses DDoS threat from the 2026 threat landscape.
    """
    now = datetime.now(timezone.utc)
    window = request_counts[api_key]

    # Remove requests older than 1 minute
    request_counts[api_key] = [t for t in window if (now - t).seconds < 60]

    if len(request_counts[api_key]) >= MAX_REQUESTS_PER_MINUTE:
        return False

    request_counts[api_key].append(now)
    return True
