"""Tests for DMP cryptographic operations"""

import pytest
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidTag

from dmp.core.crypto import DMPCrypto, EncryptedMessage, MessageEncryption
from dmp.core.ed25519_points import LOW_ORDER_ED25519_PUBKEYS


class TestDMPCrypto:
    """Test core cryptographic operations"""

    def test_keypair_generation(self):
        """Test X25519 keypair generation"""
        private_key, public_key = DMPCrypto.generate_keypair()

        # Verify key types
        assert isinstance(private_key, X25519PrivateKey)
        assert private_key.public_key() == public_key

        # Verify we can create crypto instance
        crypto = DMPCrypto(private_key)
        assert crypto.public_key == public_key

    def test_crypto_from_private_bytes(self):
        """Test creating crypto instance from private key bytes"""
        # Generate a key
        original = DMPCrypto()
        private_bytes = original.get_private_key_bytes()

        # Recreate from bytes
        restored = DMPCrypto.from_private_bytes(private_bytes)

        # Verify keys match
        assert restored.get_private_key_bytes() == private_bytes
        assert restored.get_public_key_bytes() == original.get_public_key_bytes()

    def test_invalid_private_key_bytes(self):
        """Test handling of invalid private key bytes"""
        with pytest.raises(ValueError, match="32 bytes"):
            DMPCrypto.from_private_bytes(b"too short")

    def test_passphrase_derivation(self):
        """Test deterministic key derivation from passphrase"""
        passphrase = "test passphrase 123"

        # Generate twice with same passphrase
        crypto1 = DMPCrypto.from_passphrase(passphrase)
        crypto2 = DMPCrypto.from_passphrase(passphrase)

        # Should produce same keys
        assert crypto1.get_private_key_bytes() == crypto2.get_private_key_bytes()
        assert crypto1.get_public_key_bytes() == crypto2.get_public_key_bytes()

        # Different passphrase should produce different keys
        crypto3 = DMPCrypto.from_passphrase("different passphrase")
        assert crypto3.get_private_key_bytes() != crypto1.get_private_key_bytes()

    def test_passphrase_with_salt(self):
        """Test key derivation with custom salt"""
        passphrase = "test passphrase"
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)

        crypto1 = DMPCrypto.from_passphrase(passphrase, salt1)
        crypto2 = DMPCrypto.from_passphrase(passphrase, salt2)

        # Different salts should produce different keys
        assert crypto1.get_private_key_bytes() != crypto2.get_private_key_bytes()

    def test_passphrase_rejects_short_salt(self):
        """Argon2 needs at least 8 bytes of salt; guard against shorter."""
        import pytest

        with pytest.raises(ValueError, match="8 bytes"):
            DMPCrypto.from_passphrase("x", salt=b"short")

    def test_passphrase_derivation_uses_argon2id(self):
        """Sanity check: same inputs → same output, distinct passphrases → distinct keys.

        Also verifies that swapping the passphrase while holding the salt constant
        really does change the key (i.e. we're not accidentally salt-only keyed).
        """
        salt = os.urandom(32)
        a = DMPCrypto.from_passphrase("phrase-one", salt=salt)
        b = DMPCrypto.from_passphrase("phrase-one", salt=salt)
        c = DMPCrypto.from_passphrase("phrase-two", salt=salt)
        assert a.get_private_key_bytes() == b.get_private_key_bytes()
        assert a.get_private_key_bytes() != c.get_private_key_bytes()

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption"""
        # Create sender and recipient
        sender = DMPCrypto()
        recipient = DMPCrypto()

        # Encrypt message
        plaintext = b"Hello, World!"
        encrypted = sender.encrypt_for_recipient(plaintext, recipient.public_key)

        # Verify encrypted message structure
        assert isinstance(encrypted, EncryptedMessage)
        assert len(encrypted.ephemeral_public_key) == 32
        assert len(encrypted.nonce) == 12
        assert len(encrypted.ciphertext) > 0
        assert encrypted.ciphertext != plaintext

        # Decrypt message
        decrypted = recipient.decrypt_message(encrypted)
        assert decrypted == plaintext

    def test_encrypt_with_associated_data(self):
        """Test encryption with associated data for authentication"""
        sender = DMPCrypto()
        recipient = DMPCrypto()

        plaintext = b"Secret message"
        associated_data = b"metadata"

        # Encrypt with associated data
        encrypted = sender.encrypt_for_recipient(
            plaintext, recipient.public_key, associated_data
        )

        # Decrypt with correct associated data
        decrypted = recipient.decrypt_message(encrypted, associated_data)
        assert decrypted == plaintext

        # Decryption with wrong associated data should fail
        with pytest.raises(InvalidTag):
            recipient.decrypt_message(encrypted, b"wrong metadata")

    def test_wrong_recipient_cannot_decrypt(self):
        """Test that wrong recipient cannot decrypt message"""
        sender = DMPCrypto()
        recipient = DMPCrypto()
        wrong_recipient = DMPCrypto()

        plaintext = b"Secret for recipient only"
        encrypted = sender.encrypt_for_recipient(plaintext, recipient.public_key)

        # Wrong recipient should fail to decrypt
        with pytest.raises(InvalidTag):
            wrong_recipient.decrypt_message(encrypted)

    def test_deterministic_nonce_generation(self):
        """Test deterministic nonce generation"""
        message_id = os.urandom(16)
        chunk_number = 42
        timestamp = 1234567890

        # Generate nonce twice with same inputs
        nonce1 = DMPCrypto.generate_deterministic_nonce(
            message_id, chunk_number, timestamp
        )
        nonce2 = DMPCrypto.generate_deterministic_nonce(
            message_id, chunk_number, timestamp
        )

        # Should be deterministic
        assert nonce1 == nonce2
        assert len(nonce1) == 12

        # Different inputs should produce different nonces
        nonce3 = DMPCrypto.generate_deterministic_nonce(
            message_id, chunk_number + 1, timestamp
        )
        assert nonce3 != nonce1

    def test_derive_user_id(self):
        """Test user ID derivation from public key"""
        crypto = DMPCrypto()
        user_id = DMPCrypto.derive_user_id(crypto.public_key)

        assert len(user_id) == 32

        # Same key should produce same ID
        user_id2 = DMPCrypto.derive_user_id(crypto.public_key)
        assert user_id == user_id2

    def test_sign_verify_data(self):
        """Ed25519 signing and verification."""
        crypto = DMPCrypto()
        data = b"Data to sign"

        signature = crypto.sign_data(data)
        # Ed25519 signatures are always 64 bytes
        assert len(signature) == 64

        # Valid signature verifies
        assert DMPCrypto.verify_signature(data, signature, crypto.signing_public_key)
        # Also accepts raw 32-byte pubkey
        assert DMPCrypto.verify_signature(
            data, signature, crypto.get_signing_public_key_bytes()
        )

        # Tampered data fails
        assert not DMPCrypto.verify_signature(
            b"Tampered data", signature, crypto.signing_public_key
        )

        # Wrong signer fails
        other = DMPCrypto()
        assert not DMPCrypto.verify_signature(data, signature, other.signing_public_key)

    # Independent hard-coded low-order Ed25519 encoding fixtures. These
    # MUST NOT be derived from dmp.core.ed25519_points.LOW_ORDER_ED25519_PUBKEYS
    # — if an entry were accidentally deleted from the production set, a test
    # that imports the same set would silently stop checking it. Source:
    # https://pkg.go.dev/c2sp.org/CCTV/ed25519 + RFC 8032 small-subgroup
    # canonical encodings.
    _IDENTITY_POINT_HEX = (
        "0100000000000000000000000000000000000000000000000000000000000000"
    )
    _LOW_ORDER_VECTORS = (
        # order 1 — identity point. With sig = identity || 0^32, permissive
        # RFC-8032 verify accepts on every message (full forgery).
        _IDENTITY_POINT_HEX,
        # order 2
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        # order 4 — both encodings
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        # order 8 — canonical
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        # non-canonical aliases the cryptography library still parses
        "0100000000000000000000000000000000000000000000000000000000000080",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )

    def test_verify_signature_rejects_identity_point_forgery(self):
        """The canonical Ed25519 forgery against the identity public key:
        sig = identity_pub || 0^32 verifies on every message under permissive
        RFC-8032 verifiers. This is the worst-case attack — full signature
        forgery without holding any private key. The central guard inside
        DMPCrypto.verify_signature must reject it before .verify() runs.
        """
        identity_pub = bytes.fromhex(self._IDENTITY_POINT_HEX)
        forgery_sig = identity_pub + b"\x00" * 32
        # Must be rejected against any message — pick a few representative
        # payloads to make the "every message" property visible in the test.
        for msg in (b"", b"forgery target", b"\x00" * 1024, os.urandom(64)):
            assert not DMPCrypto.verify_signature(msg, forgery_sig, identity_pub), (
                f"identity-point forgery accepted on message of len {len(msg)}"
            )

    def test_verify_signature_rejects_low_order_vectors_bytes(self):
        """Each known low-order encoding must be rejected when passed as raw
        bytes, regardless of signature shape. Uses independent hard-coded
        vectors so an accidental deletion from the production block list
        would not silently disable this check.
        """
        msg = b"forgery target"
        forgery_sig = bytes.fromhex(self._IDENTITY_POINT_HEX) + b"\x00" * 32
        zero_sig = b"\x00" * 64
        for hex_pub in self._LOW_ORDER_VECTORS:
            pub_bytes = bytes.fromhex(hex_pub)
            assert not DMPCrypto.verify_signature(msg, forgery_sig, pub_bytes), (
                f"low-order pubkey {hex_pub} accepted with identity-forgery sig"
            )
            assert not DMPCrypto.verify_signature(msg, zero_sig, pub_bytes), (
                f"low-order pubkey {hex_pub} accepted with zero sig"
            )

    def test_verify_signature_rejects_low_order_vectors_instance(self):
        """Same rejection when an Ed25519PublicKey instance is passed instead
        of raw bytes. Callers that cache parsed keys must not bypass the guard.
        """
        msg = b"forgery target"
        forgery_sig = bytes.fromhex(self._IDENTITY_POINT_HEX) + b"\x00" * 32
        for hex_pub in self._LOW_ORDER_VECTORS:
            pub_bytes = bytes.fromhex(hex_pub)
            try:
                pk_instance = Ed25519PublicKey.from_public_bytes(pub_bytes)
            except Exception:
                # Some non-canonical encodings are rejected at construction
                # time by the underlying library; the bytes-form test above
                # already exercises those.
                continue
            assert not DMPCrypto.verify_signature(msg, forgery_sig, pk_instance), (
                f"low-order pubkey instance {hex_pub} accepted"
            )

    def test_verify_signature_block_list_includes_all_known_vectors(self):
        """The independent vector list MUST be a subset of the production
        block list. If this test fails, the production list has lost an entry
        that this test still expects to be rejected — investigate before
        adding/removing vectors on either side.
        """
        for hex_pub in self._LOW_ORDER_VECTORS:
            pub_bytes = bytes.fromhex(hex_pub)
            assert pub_bytes in LOW_ORDER_ED25519_PUBKEYS, (
                f"vector {hex_pub} missing from LOW_ORDER_ED25519_PUBKEYS"
            )

    def test_verify_signature_wrong_length_pubkey_rejected(self):
        """Defense in depth: bytes pubkeys of the wrong length must fail
        closed rather than raising or being silently coerced."""
        data = b"x"
        sig = b"\x00" * 64
        assert not DMPCrypto.verify_signature(data, sig, b"\x00" * 31)
        assert not DMPCrypto.verify_signature(data, sig, b"\x00" * 33)
        assert not DMPCrypto.verify_signature(data, sig, b"")

    def test_signing_key_deterministic_from_passphrase(self):
        """Same passphrase produces the same Ed25519 signing key."""
        a = DMPCrypto.from_passphrase("my pass")
        b = DMPCrypto.from_passphrase("my pass")
        assert a.get_signing_public_key_bytes() == b.get_signing_public_key_bytes()

        c = DMPCrypto.from_passphrase("different")
        assert c.get_signing_public_key_bytes() != a.get_signing_public_key_bytes()


class TestEncryptedMessage:
    """Test EncryptedMessage container"""

    def test_encrypted_message_serialization(self):
        """Test serialization and deserialization"""
        original = EncryptedMessage(
            ephemeral_public_key=os.urandom(32),
            nonce=os.urandom(12),
            ciphertext=os.urandom(100),
        )

        # Serialize
        serialized = original.to_bytes()
        assert len(serialized) == 32 + 12 + 100

        # Deserialize
        restored = EncryptedMessage.from_bytes(serialized)
        assert restored.ephemeral_public_key == original.ephemeral_public_key
        assert restored.nonce == original.nonce
        assert restored.ciphertext == original.ciphertext

    def test_invalid_encrypted_message(self):
        """Test handling of invalid encrypted message data"""
        with pytest.raises(ValueError, match="too short"):
            EncryptedMessage.from_bytes(b"short")


class TestMessageEncryption:
    """Test high-level message encryption interface"""

    def test_message_encryption_with_metadata(self):
        """Test encrypting messages with metadata"""
        # Setup
        sender = DMPCrypto()
        recipient = DMPCrypto()
        encryption = MessageEncryption(sender)
        decryption = MessageEncryption(recipient)

        # Message details
        message = b"Test message content"
        message_id = os.urandom(16)
        chunk_number = 3

        # Encrypt
        encrypted = encryption.encrypt_message(
            message, recipient.public_key, message_id, chunk_number
        )

        # Decrypt
        decrypted = decryption.decrypt_message(encrypted, message_id, chunk_number)

        assert decrypted == message

    def test_encrypt_with_header_roundtrip(self):
        """encrypt_with_header binds header bytes as AAD; round-trip works."""
        sender = DMPCrypto()
        recipient = DMPCrypto()
        enc = MessageEncryption(sender)
        dec = MessageEncryption(recipient)

        plaintext = b"Header-bound message"
        header_aad = b'{"v":1,"msg_id":"abc","sender":"s","recipient":"r"}'

        encrypted = enc.encrypt_with_header(plaintext, recipient.public_key, header_aad)
        assert dec.decrypt_with_header(encrypted, header_aad) == plaintext

    def test_encrypt_with_header_rejects_mutation(self):
        """Mutating the AAD header bytes causes decrypt to fail."""
        from cryptography.exceptions import InvalidTag

        sender = DMPCrypto()
        recipient = DMPCrypto()
        enc = MessageEncryption(sender)
        dec = MessageEncryption(recipient)

        plaintext = b"payload"
        header_aad = b'{"v":1,"msg_id":"abc"}'
        encrypted = enc.encrypt_with_header(plaintext, recipient.public_key, header_aad)

        # Single-bit change in the AAD breaks authentication
        with pytest.raises(InvalidTag):
            dec.decrypt_with_header(encrypted, b'{"v":1,"msg_id":"abd"}')

    def test_message_decryption_wrong_metadata(self):
        """Test that wrong metadata causes decryption to fail"""
        sender = DMPCrypto()
        recipient = DMPCrypto()
        encryption = MessageEncryption(sender)
        decryption = MessageEncryption(recipient)

        message = b"Test message"
        message_id = os.urandom(16)

        # Encrypt with chunk 0
        encrypted = encryption.encrypt_message(
            message, recipient.public_key, message_id, chunk_number=0
        )

        # Try to decrypt with wrong chunk number
        with pytest.raises(InvalidTag):
            decryption.decrypt_message(
                encrypted, message_id, chunk_number=1  # Wrong chunk number
            )

        # Try to decrypt with wrong message ID
        with pytest.raises(InvalidTag):
            decryption.decrypt_message(
                encrypted, os.urandom(16), chunk_number=0  # Wrong message ID
            )
