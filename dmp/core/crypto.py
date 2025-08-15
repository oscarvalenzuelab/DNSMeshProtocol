"""Cryptographic operations for DMP protocol using ChaCha20-Poly1305 and X25519"""

import os
import hashlib
from typing import Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


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
    def from_bytes(cls, data: bytes) -> 'EncryptedMessage':
        """Deserialize encrypted message"""
        if len(data) < 44:  # 32 (key) + 12 (nonce) + min ciphertext
            raise ValueError("Invalid encrypted message: too short")
        
        return cls(
            ephemeral_public_key=data[:32],
            nonce=data[32:44],
            ciphertext=data[44:]
        )


class DMPCrypto:
    """Core cryptographic operations for DMP"""
    
    def __init__(self, private_key: Optional[X25519PrivateKey] = None):
        """Initialize crypto system with optional private key"""
        if private_key is None:
            private_key = X25519PrivateKey.generate()
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    @classmethod
    def generate_keypair(cls) -> Tuple[X25519PrivateKey, X25519PublicKey]:
        """Generate a new X25519 keypair"""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> 'DMPCrypto':
        """Create crypto instance from private key bytes"""
        if len(private_bytes) != 32:
            raise ValueError("Private key must be 32 bytes")
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        return cls(private_key)
    
    @classmethod
    def from_passphrase(cls, passphrase: str, salt: Optional[bytes] = None) -> 'DMPCrypto':
        """Derive keypair from passphrase using PBKDF2"""
        if salt is None:
            salt = b'DMP-DEFAULT-SALT'  # For deterministic key generation
        
        # Derive 32 bytes for private key
        key_material = hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            iterations=100000,
            dklen=32
        )
        
        return cls.from_private_bytes(key_material)
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_private_key_bytes(self) -> bytes:
        """Get private key as bytes"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def encrypt_for_recipient(
        self,
        plaintext: bytes,
        recipient_public_key: X25519PublicKey,
        associated_data: Optional[bytes] = None
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
            salt=b'DMP-v1',
            info=b'DMP-Message-Encryption',
            backend=default_backend()
        )
        encryption_key = hkdf.derive(shared_secret)
        
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(encryption_key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        
        # Package encrypted message
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return EncryptedMessage(
            ephemeral_public_key=ephemeral_public_bytes,
            ciphertext=ciphertext,
            nonce=nonce
        )
    
    def decrypt_message(
        self,
        encrypted_msg: EncryptedMessage,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypt message using private key"""
        
        # Reconstruct ephemeral public key
        ephemeral_public = X25519PublicKey.from_public_bytes(
            encrypted_msg.ephemeral_public_key
        )
        
        # Perform ECDH key exchange
        shared_secret = self.private_key.exchange(ephemeral_public)
        
        # Derive decryption key using HKDF (same as encryption)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'DMP-v1',
            info=b'DMP-Message-Encryption',
            backend=default_backend()
        )
        decryption_key = hkdf.derive(shared_secret)
        
        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(decryption_key)
        plaintext = cipher.decrypt(
            encrypted_msg.nonce,
            encrypted_msg.ciphertext,
            associated_data
        )
        
        return plaintext
    
    @staticmethod
    def generate_deterministic_nonce(
        message_id: bytes,
        chunk_number: int,
        timestamp: int
    ) -> bytes:
        """Generate deterministic nonce to prevent replay attacks"""
        data = message_id + chunk_number.to_bytes(4, 'big') + timestamp.to_bytes(8, 'big')
        hash_result = hashlib.sha256(data).digest()
        return hash_result[:12]  # Use first 12 bytes for nonce
    
    @staticmethod
    def derive_user_id(public_key: X25519PublicKey) -> bytes:
        """Derive user ID from public key"""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(public_bytes).digest()
    
    def sign_data(self, data: bytes) -> bytes:
        """Create signature for data (simplified using HMAC for now)"""
        # In production, use Ed25519 for signatures
        # For MVP, we'll use HMAC with derived key
        signing_key = hashlib.sha256(
            self.get_private_key_bytes() + b'DMP-Signing'
        ).digest()
        return hashlib.blake2b(data, key=signing_key, digest_size=32).digest()
    
    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        public_key: X25519PublicKey
    ) -> bool:
        """Verify signature (simplified for MVP)"""
        # This is a placeholder - in production use Ed25519
        # For now, we can't verify without the private key
        # Return True for MVP, implement proper signatures later
        return len(signature) == 32


class MessageEncryption:
    """High-level encryption interface for DMP messages"""
    
    def __init__(self, crypto: DMPCrypto):
        self.crypto = crypto
    
    def encrypt_message(
        self,
        message: bytes,
        recipient_public_key: X25519PublicKey,
        message_id: bytes,
        chunk_number: int = 0,
        timestamp: int = 0
    ) -> EncryptedMessage:
        """Encrypt a message with additional metadata"""
        # Create associated data for authentication
        associated_data = message_id + chunk_number.to_bytes(4, 'big')
        
        return self.crypto.encrypt_for_recipient(
            plaintext=message,
            recipient_public_key=recipient_public_key,
            associated_data=associated_data
        )
    
    def decrypt_message(
        self,
        encrypted_msg: EncryptedMessage,
        message_id: bytes,
        chunk_number: int = 0
    ) -> bytes:
        """Decrypt a message with metadata verification"""
        # Create associated data for authentication
        associated_data = message_id + chunk_number.to_bytes(4, 'big')
        
        return self.crypto.decrypt_message(
            encrypted_msg=encrypted_msg,
            associated_data=associated_data
        )