"""Cryptographic operations for DMP protocol.

Each DMP identity has TWO keypairs:
- X25519 for ECDH key exchange + ChaCha20-Poly1305 message encryption
- Ed25519 for sender authentication via signatures

The Ed25519 signing key is deterministically derived from the X25519 private key
bytes (domain-separated SHA-256), so a passphrase yields the same full identity.
"""

import os
import hashlib
from typing import Tuple, Optional
from dataclasses import dataclass

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from dmp.core.ed25519_points import is_low_order as _is_low_order_ed25519

# Argon2id parameters for passphrase → 32-byte X25519 seed.
# Tuned for ~20ms on a modern laptop. Still orders of magnitude more
# resistant to offline brute force than the previous PBKDF2-SHA256 at
# 100_000 iterations against a fixed salt. Operators who need more
# margin can pass their own parameters through from_passphrase(...).
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 32 * 1024  # KiB → 32 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32


@dataclass
class EncryptedMessage:
    """Container for encrypted message data"""

    ephemeral_public_key: bytes  # 32 bytes
    ciphertext: bytes
    nonce: bytes  # 12 bytes

    def to_bytes(self) -> bytes:
        """Serialize encrypted message"""
        return self.ephemeral_public_key + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedMessage":
        """Deserialize encrypted message"""
        if len(data) < 44:  # 32 (key) + 12 (nonce) + min ciphertext
            raise ValueError("Invalid encrypted message: too short")

        return cls(
            ephemeral_public_key=data[:32], nonce=data[32:44], ciphertext=data[44:]
        )


class DMPCrypto:
    """Core cryptographic operations for DMP"""

    # Domain separator for deriving the Ed25519 seed from the X25519 private key
    ED25519_DOMAIN = b"DMP-v1-Ed25519-signing-key"

    def __init__(self, private_key: Optional[X25519PrivateKey] = None):
        """Initialize crypto system with optional X25519 private key.

        The Ed25519 signing keypair is deterministically derived from the X25519
        private bytes, so a passphrase produces both halves of the identity.
        """
        if private_key is None:
            private_key = X25519PrivateKey.generate()
        self.private_key = private_key
        self.public_key = private_key.public_key()

        x25519_bytes = self.get_private_key_bytes()
        ed_seed = hashlib.sha256(x25519_bytes + self.ED25519_DOMAIN).digest()
        self.signing_key = Ed25519PrivateKey.from_private_bytes(ed_seed)
        self.signing_public_key = self.signing_key.public_key()

    @classmethod
    def generate_keypair(cls) -> Tuple[X25519PrivateKey, X25519PublicKey]:
        """Generate a new X25519 keypair"""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> "DMPCrypto":
        """Create crypto instance from private key bytes"""
        if len(private_bytes) != 32:
            raise ValueError("Private key must be 32 bytes")
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        return cls(private_key)

    @classmethod
    def from_passphrase(
        cls,
        passphrase: str,
        salt: Optional[bytes] = None,
        *,
        time_cost: int = ARGON2_TIME_COST,
        memory_cost: int = ARGON2_MEMORY_COST,
        parallelism: int = ARGON2_PARALLELISM,
    ) -> "DMPCrypto":
        """Derive an X25519 keypair from a passphrase using Argon2id.

        Argon2id is memory-hard, which makes offline brute force
        dramatically harder than the previous PBKDF2-SHA256 implementation.
        Callers should pass a per-identity random `salt` so two users who
        happen to pick the same passphrase still end up with different keys
        and one rainbow table can't crack both. For back-compat with code
        paths that don't have a salt handy (tests, quick demos) we default
        to a fixed sentinel — but that path is explicitly weaker and is
        flagged in SECURITY.md.
        """
        if salt is None:
            salt = b"DMP-default-v2-argon2id"
        if len(salt) < 8:
            raise ValueError("salt must be at least 8 bytes")

        key_material = hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=ARGON2_HASH_LEN,
            type=Argon2Type.ID,
        )
        return cls.from_private_bytes(key_material)

    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def get_private_key_bytes(self) -> bytes:
        """Get private key as bytes"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def encrypt_for_recipient(
        self,
        plaintext: bytes,
        recipient_public_key: X25519PublicKey,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedMessage:
        """Encrypt message for recipient using ECDH + ChaCha20-Poly1305"""

        # Generate ephemeral keypair for this message
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        # Perform ECDH key exchange
        shared_secret = ephemeral_private.exchange(recipient_public_key)

        # Derive encryption key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"DMP-v1",
            info=b"DMP-Message-Encryption",
            backend=default_backend(),
        )
        encryption_key = hkdf.derive(shared_secret)

        # Generate random nonce
        nonce = os.urandom(12)

        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(encryption_key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)

        # Package encrypted message
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        return EncryptedMessage(
            ephemeral_public_key=ephemeral_public_bytes,
            ciphertext=ciphertext,
            nonce=nonce,
        )

    def decrypt_message(
        self,
        encrypted_msg: EncryptedMessage,
        associated_data: Optional[bytes] = None,
        *,
        private_key: Optional[X25519PrivateKey] = None,
    ) -> bytes:
        """Decrypt message using our long-term private key, or an override.

        `private_key=X` lets the caller ECDH with a one-time prekey sk instead
        of the long-term identity key. Used by the X3DH-style forward-secrecy
        path — see `dmp.core.prekeys` and `dmp.client.client.receive_messages`.
        """

        decrypt_key = private_key if private_key is not None else self.private_key

        # Reconstruct ephemeral public key
        ephemeral_public = X25519PublicKey.from_public_bytes(
            encrypted_msg.ephemeral_public_key
        )

        # Perform ECDH key exchange
        shared_secret = decrypt_key.exchange(ephemeral_public)

        # Derive decryption key using HKDF (same as encryption)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"DMP-v1",
            info=b"DMP-Message-Encryption",
            backend=default_backend(),
        )
        decryption_key = hkdf.derive(shared_secret)

        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(decryption_key)
        plaintext = cipher.decrypt(
            encrypted_msg.nonce, encrypted_msg.ciphertext, associated_data
        )

        return plaintext

    @staticmethod
    def generate_deterministic_nonce(
        message_id: bytes, chunk_number: int, timestamp: int
    ) -> bytes:
        """Generate deterministic nonce to prevent replay attacks"""
        data = (
            message_id + chunk_number.to_bytes(4, "big") + timestamp.to_bytes(8, "big")
        )
        hash_result = hashlib.sha256(data).digest()
        return hash_result[:12]  # Use first 12 bytes for nonce

    @staticmethod
    def derive_user_id(public_key: X25519PublicKey) -> bytes:
        """Derive user ID from public key"""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(public_bytes).digest()

    def get_signing_public_key_bytes(self) -> bytes:
        """Get Ed25519 signing public key as raw 32 bytes."""
        return self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign_data(self, data: bytes) -> bytes:
        """Create an Ed25519 signature over `data` (64 bytes)."""
        return self.signing_key.sign(data)

    @staticmethod
    def verify_signature(
        data: bytes,
        signature: bytes,
        signing_public_key,
    ) -> bool:
        """Verify an Ed25519 signature.

        Accepts either an Ed25519PublicKey instance or raw 32 pubkey bytes.
        Public keys in the small-subgroup / low-order set are rejected here
        before delegating to the underlying verify; see
        ``dmp.core.ed25519_points`` for the rationale (identity-point forgery
        and grindable small-order forgeries against permissive verifiers).
        """
        if isinstance(signing_public_key, (bytes, bytearray)):
            pub_bytes = bytes(signing_public_key)
            if len(pub_bytes) != 32:
                return False
            if _is_low_order_ed25519(pub_bytes):
                return False
            try:
                signing_public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            except Exception:
                return False
        else:
            try:
                pub_bytes = signing_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            except Exception:
                return False
            if _is_low_order_ed25519(pub_bytes):
                return False
        try:
            signing_public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


class MessageEncryption:
    """High-level encryption interface for DMP messages.

    Two AAD styles:
    - encrypt_message / decrypt_message: AAD = msg_id + chunk_number (legacy path,
      kept for backwards compatibility).
    - encrypt_with_header / decrypt_with_header: AAD = full canonical header bytes
      (binds sender_id, recipient_id, timestamp, ttl, total_chunks, and message
      type so they cannot be silently mutated in transit).
    """

    def __init__(self, crypto: DMPCrypto):
        self.crypto = crypto

    def encrypt_message(
        self,
        message: bytes,
        recipient_public_key: X25519PublicKey,
        message_id: bytes,
        chunk_number: int = 0,
        timestamp: int = 0,
    ) -> EncryptedMessage:
        associated_data = message_id + chunk_number.to_bytes(4, "big")
        return self.crypto.encrypt_for_recipient(
            plaintext=message,
            recipient_public_key=recipient_public_key,
            associated_data=associated_data,
        )

    def decrypt_message(
        self,
        encrypted_msg: EncryptedMessage,
        message_id: bytes,
        chunk_number: int = 0,
    ) -> bytes:
        associated_data = message_id + chunk_number.to_bytes(4, "big")
        return self.crypto.decrypt_message(
            encrypted_msg=encrypted_msg,
            associated_data=associated_data,
        )

    def encrypt_with_header(
        self,
        message: bytes,
        recipient_public_key: X25519PublicKey,
        header_aad: bytes,
    ) -> EncryptedMessage:
        """Encrypt with the full canonical header as AAD.

        `header_aad` should be `DMPHeader.to_bytes()` — the deterministic JSON
        form already used as the header wire format. Any mutation of the header
        fields in transit will cause decryption to fail.
        """
        return self.crypto.encrypt_for_recipient(
            plaintext=message,
            recipient_public_key=recipient_public_key,
            associated_data=header_aad,
        )

    def decrypt_with_header(
        self,
        encrypted_msg: EncryptedMessage,
        header_aad: bytes,
        *,
        private_key: Optional[X25519PrivateKey] = None,
    ) -> bytes:
        """Decrypt a header-AAD ciphertext; raises InvalidTag on header mutation.

        `private_key` routes ECDH through a one-time prekey sk (forward
        secrecy). When None, the instance's long-term private key is used.
        """
        return self.crypto.decrypt_message(
            encrypted_msg=encrypted_msg,
            associated_data=header_aad,
            private_key=private_key,
        )
