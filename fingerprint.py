import hashlib

def build_fingerprint(ip_address: str, user_agent: str) -> str:
    raw = f"{ip_address}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()

def fingerprints_match(original: str, incoming_ip: str, incoming_ua: str) -> bool:
    incoming = build_fingerprint(incoming_ip, incoming_ua)
    return original == incoming
