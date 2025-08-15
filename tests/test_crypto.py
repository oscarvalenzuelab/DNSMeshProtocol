"""Tests for DMP cryptographic operations"""

import pytest
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.exceptions import InvalidTag

from dmp.core.crypto import (
    DMPCrypto, EncryptedMessage, MessageEncryption
)


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
            DMPCrypto.from_private_bytes(b'too short')
    
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
    
    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption"""
        # Create sender and recipient
        sender = DMPCrypto()
        recipient = DMPCrypto()
        
        # Encrypt message
        plaintext = b"Hello, World!"
        encrypted = sender.encrypt_for_recipient(
            plaintext,
            recipient.public_key
        )
        
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
            plaintext,
            recipient.public_key,
            associated_data
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
        encrypted = sender.encrypt_for_recipient(
            plaintext,
            recipient.public_key
        )
        
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
        """Test data signing and verification"""
        crypto = DMPCrypto()
        data = b"Data to sign"
        
        signature = crypto.sign_data(data)
        assert len(signature) == 32
        
        # Verify signature (simplified for MVP)
        assert crypto.verify_signature(data, signature, crypto.public_key)


class TestEncryptedMessage:
    """Test EncryptedMessage container"""
    
    def test_encrypted_message_serialization(self):
        """Test serialization and deserialization"""
        original = EncryptedMessage(
            ephemeral_public_key=os.urandom(32),
            nonce=os.urandom(12),
            ciphertext=os.urandom(100)
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
            EncryptedMessage.from_bytes(b'short')


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
            message,
            recipient.public_key,
            message_id,
            chunk_number
        )
        
        # Decrypt
        decrypted = decryption.decrypt_message(
            encrypted,
            message_id,
            chunk_number
        )
        
        assert decrypted == message
    
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
            message,
            recipient.public_key,
            message_id,
            chunk_number=0
        )
        
        # Try to decrypt with wrong chunk number
        with pytest.raises(InvalidTag):
            decryption.decrypt_message(
                encrypted,
                message_id,
                chunk_number=1  # Wrong chunk number
            )
        
        # Try to decrypt with wrong message ID
        with pytest.raises(InvalidTag):
            decryption.decrypt_message(
                encrypted,
                os.urandom(16),  # Wrong message ID
                chunk_number=0
            )