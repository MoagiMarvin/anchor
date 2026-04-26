import os
import base64
import json
import hashlib
import hmac
from datetime import datetime, timezone

try:
    import oqs
    sig_test = oqs.Signature("ML-DSA-65")
    DILITHIUM_AVAILABLE = True
    print("[Anchor PQC] CRYSTALS-Dilithium (ML-DSA-65) ACTIVE - NIST FIPS 204")
except Exception as e:
    DILITHIUM_AVAILABLE = False
    print("[Anchor PQC] Dilithium unavailable - using SHA3-512 hybrid")


class AnchorPQC:
    def __init__(self, secret: str):
        self.secret = secret.encode()
        self.algorithm = "ML-DSA-65" if DILITHIUM_AVAILABLE else "SHA3-512-HYBRID"

    def sign_token(self, payload: dict) -> str:
        payload["issued_at"] = datetime.now(timezone.utc).isoformat()
        payload["algorithm"] = self.algorithm
        payload["issuer"] = "did:anchor:system"
        payload["quantum_safe"] = True
        payload["standard"] = "NIST FIPS 204" if DILITHIUM_AVAILABLE else "NIST FIPS 202"
        payload_str = json.dumps(payload, sort_keys=True)
        payload_b64 = base64.b64encode(payload_str.encode()).decode()
        if DILITHIUM_AVAILABLE:
            signature = self._dilithium_sign(payload_str)
        else:
            signature = self._hybrid_sign(payload_str)
        return f"{self.algorithm}.{payload_b64}.{signature}"

    def verify_token(self, token: str) -> dict:
        try:
            parts = token.split(".", 2)
            if len(parts) != 3:
                return {"valid": False, "reason": "Invalid token format"}
            algorithm, payload_b64, signature = parts
            payload_str = base64.b64decode(payload_b64).decode()
            payload = json.loads(payload_str)
            if algorithm == "ML-DSA-65" and DILITHIUM_AVAILABLE:
                valid = self._dilithium_verify(payload_str, signature)
            else:
                valid = self._hybrid_verify(payload_str, signature)
            if not valid:
                return {"valid": False, "reason": "Signature verification failed"}
            return {"valid": True, "payload": payload, "algorithm": algorithm, "quantum_safe": True}
        except Exception as e:
            return {"valid": False, "reason": str(e)}

    def _dilithium_sign(self, data: str) -> str:
        with oqs.Signature("ML-DSA-65") as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(data.encode())
            pub_key_b64 = base64.b64encode(public_key).decode()
            sig_b64 = base64.b64encode(signature).decode()
            return pub_key_b64 + ":" + sig_b64

    def _dilithium_verify(self, data: str, combined: str) -> bool:
        try:
            pub_key_b64, sig_b64 = combined.split(":", 1)
            public_key = base64.b64decode(pub_key_b64)
            signature = base64.b64decode(sig_b64)
            with oqs.Signature("ML-DSA-65") as verifier:
                return verifier.verify(data.encode(), signature, public_key)
        except Exception:
            return False

    def _hybrid_sign(self, data: str) -> str:
        sha3_hash = hashlib.sha3_512(data.encode()).digest()
        signature = hmac.new(self.secret, sha3_hash, hashlib.sha3_512).digest()
        salt = os.urandom(16)
        return base64.b64encode(salt + signature).decode()

    def _hybrid_verify(self, data: str, signature_b64: str) -> bool:
        try:
            combined = base64.b64decode(signature_b64)
            stored_sig = combined[16:]
            sha3_hash = hashlib.sha3_512(data.encode()).digest()
            expected = hmac.new(self.secret, sha3_hash, hashlib.sha3_512).digest()
            return hmac.compare_digest(stored_sig, expected)
        except Exception:
            return False

    def get_algorithm_info(self) -> dict:
        if DILITHIUM_AVAILABLE:
            return {
                "algorithm": "CRYSTALS-Dilithium (ML-DSA-65)",
                "standard": "NIST FIPS 204",
                "quantum_safe": True,
                "security_level": "Category 3 - 256-bit quantum security",
                "recommended_by": "CSIR SS26Hack 2026, NIST",
                "description": "Lattice-based digital signature. Resistant to Shors and Grovers algorithms.",
                "status": "ACTIVE - running real Dilithium on Linux"
            }
        else:
            return {
                "algorithm": "SHA3-512 Hybrid HMAC",
                "standard": "NIST FIPS 202",
                "quantum_safe": True,
                "security_level": "256-bit post-quantum security",
                "status": "FALLBACK - SHA3-512 hybrid active"
            }