"""
Anchor Encryption Module
AES-256-GCM encryption for sensitive data fields.

The client holds their own key.
Anchor never sees the raw data or the key.
Even if Anchor is breached — client data is safe.

Usage:
    from encryption import AnchorEncryption
    
    enc = AnchorEncryption(client_key="your-secret-key")
    
    # Encrypt
    encrypted = enc.encrypt("12345678")  # student ID
    
    # Decrypt
    original = enc.decrypt(encrypted)
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AnchorEncryption:
    def __init__(self, client_key: str):
        """
        client_key — the client's own secret key.
        Anchor never stores or sees this key.
        The client generates and manages it themselves.
        """
        # Derive a 32-byte AES key from the client's key string
        self.key = hashlib.sha256(client_key.encode()).digest()

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts a sensitive field using AES-256-GCM.
        Returns a base64 string safe to store in any database.

        Example:
            encrypt("12345678") → "YW5jaG9y..."
        """
        if not plaintext:
            return plaintext

        # Generate a random 12-byte nonce for each encryption
        # This means the same value encrypted twice gives different results
        # Making it impossible to detect patterns in the database
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        # Combine nonce + ciphertext and encode as base64
        combined = nonce + ciphertext
        return "ANC:" + base64.b64encode(combined).decode()

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypts a field encrypted by Anchor.
        Returns the original plaintext.

        Example:
            decrypt("ANC:YW5jaG9y...") → "12345678"
        """
        if not encrypted or not encrypted.startswith("ANC:"):
            return encrypted

        try:
            # Remove prefix and decode base64
            combined = base64.b64decode(encrypted[4:])

            # Split nonce and ciphertext
            nonce = combined[:12]
            ciphertext = combined[12:]

            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception:
            return "[DECRYPTION FAILED]"

    def encrypt_record(self, record: dict, fields: list) -> dict:
        """
        Encrypts specific fields in a dictionary.
        Leaves other fields untouched.

        Example:
            encrypt_record(
                {"student_id": "12345678", "course": "CS101"},
                fields=["student_id"]
            )
            → {"student_id": "ANC:...", "course": "CS101"}
        """
        encrypted_record = record.copy()
        for field in fields:
            if field in encrypted_record and encrypted_record[field]:
                encrypted_record[field] = self.encrypt(str(encrypted_record[field]))
        return encrypted_record

    def decrypt_record(self, record: dict, fields: list) -> dict:
        """
        Decrypts specific fields in a dictionary.

        Example:
            decrypt_record(
                {"student_id": "ANC:...", "course": "CS101"},
                fields=["student_id"]
            )
            → {"student_id": "12345678", "course": "CS101"}
        """
        decrypted_record = record.copy()
        for field in fields:
            if field in decrypted_record and decrypted_record[field]:
                decrypted_record[field] = self.decrypt(str(decrypted_record[field]))
        return decrypted_record

    def is_encrypted(self, value: str) -> bool:
        """
        Checks if a value is already encrypted by Anchor.
        Prevents double-encryption.
        """
        return isinstance(value, str) and value.startswith("ANC:")
