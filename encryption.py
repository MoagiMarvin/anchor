"""
Anchor Encryption Module
AES-256-GCM encryption for sensitive data fields.

The client holds their own key.
Anchor never sees the raw data or the key.
Even if Anchor is breached — client data is safe.

POPIA compliant field-level encryption.
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
        """
        self.key = hashlib.sha256(client_key.encode()).digest()

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts a sensitive field using AES-256-GCM.
        Returns a base64 string safe to store in any database.
        """
        if not plaintext:
            return plaintext

        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        combined = nonce + ciphertext
        return "ANC:" + base64.b64encode(combined).decode()

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypts a field encrypted by Anchor.
        """
        if not encrypted or not encrypted.startswith("ANC:"):
            return encrypted

        try:
            combined = base64.b64decode(encrypted[4:])
            nonce = combined[:12]
            ciphertext = combined[12:]
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception:
            return "[DECRYPTION FAILED]"

    def hash_for_search(self, value: str) -> str:
        """
        Creates a searchable hash of a value.
        Use this for fields like email that need to be
        searchable but not stored in plain text.

        Same input always gives same hash — so you can search.
        But hash cannot be reversed to get original value.

        Example:
            hash_for_search("marvin@ul.ac.za")
            → "a3f9b2c1d4e5..." (always the same)

        Store both:
            email_hash      → for searching/login
            email_encrypted → for displaying to user
        """
        combined = f"anchor_search:{value.lower().strip()}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def prepare_record(self, record: dict, config: dict) -> dict:
        """
        The smart way to handle a full record.

        config tells Anchor what to do with each field:
            "encrypt" — full AES-256 encryption
            "hash"    — searchable hash only
            "both"    — hash for search + encrypt for display

        Example config for a student record:
        {
            "student_id": "encrypt",
            "email": "both",
            "phone": "encrypt",
            "id_number": "encrypt",
            "name": "encrypt",
            "course": "ignore"
        }
        """
        result = record.copy()

        for field, action in config.items():
            if field not in record or not record[field]:
                continue

            value = str(record[field])

            if action == "encrypt":
                result[field] = self.encrypt(value)

            elif action == "hash":
                result[field + "_hash"] = self.hash_for_search(value)
                if field in result:
                    del result[field]

            elif action == "both":
                # Keep hash for searching
                result[field + "_hash"] = self.hash_for_search(value)
                # Encrypt actual value for display
                result[field] = self.encrypt(value)

            elif action == "ignore":
                pass

        return result

    def encrypt_record(self, record: dict, fields: list) -> dict:
        """Simple encrypt specific fields."""
        encrypted_record = record.copy()
        for field in fields:
            if field in encrypted_record and encrypted_record[field]:
                encrypted_record[field] = self.encrypt(str(encrypted_record[field]))
        return encrypted_record

    def decrypt_record(self, record: dict, fields: list) -> dict:
        """Simple decrypt specific fields."""
        decrypted_record = record.copy()
        for field in fields:
            if field in decrypted_record and decrypted_record[field]:
                decrypted_record[field] = self.decrypt(str(decrypted_record[field]))
        return decrypted_record

    def is_encrypted(self, value: str) -> bool:
        """Checks if a value is already encrypted."""
        return isinstance(value, str) and value.startswith("ANC:")