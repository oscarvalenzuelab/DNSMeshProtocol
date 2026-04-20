"""Simple DMP Client implementation"""

import os
import time
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from dmp.core.message import DMPMessage, DMPHeader, MessageType, DMPIdentity
from dmp.core.crypto import DMPCrypto, MessageEncryption
from dmp.core.chunking import MessageChunker, MessageAssembler
from dmp.core.dns import DNSOperations, DNSChunkManager, DNSEncoder, DMPDNSRecord


@dataclass
class Contact:
    """Contact information for a user"""
    username: str
    public_key_bytes: bytes
    domain: str


class DMPClient:
    """Simple DMP client for sending and receiving messages"""
    
    def __init__(self, username: str, passphrase: str, domain: str = "mesh.local"):
        """Initialize client with username and passphrase"""
        self.username = username
        self.domain = domain
        
        # Initialize crypto with deterministic key from passphrase
        self.crypto = DMPCrypto.from_passphrase(passphrase)
        self.user_id = self.crypto.derive_user_id(self.crypto.public_key)
        
        # Initialize components
        self.chunker = MessageChunker(enable_error_correction=True)
        self.assembler = MessageAssembler(enable_error_correction=True)
        self.dns_ops = DNSOperations()
        self.chunk_manager = DNSChunkManager(self.dns_ops)
        self.encryption = MessageEncryption(self.crypto)
        
        # Storage
        self.contacts: Dict[str, Contact] = {}
        self.messages: List[Tuple[str, bytes, int]] = []  # (sender, message, timestamp)
        
        # Create identity
        self.identity = DMPIdentity(
            username=username,
            public_key=self.crypto.get_public_key_bytes(),
            signature=self.crypto.sign_data(username.encode())
        )
    
    def publish_identity(self) -> bool:
        """Publish identity to DNS (simulated)"""
        domain = DNSEncoder.encode_identity_domain(self.username, self.domain)
        record = DMPDNSRecord(
            version=1,
            record_type='identity',
            data=self.identity.public_key,
            metadata={
                'username': self.username,
                'created': self.identity.created_at
            }
        )
        
        # In real implementation, this would publish to DNS
        print(f"Publishing identity to {domain}")
        print(f"  Public key: {self.identity.public_key.hex()[:16]}...")
        return True
    
    def add_contact(self, username: str, public_key_hex: str) -> bool:
        """Add a contact with their public key"""
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            contact = Contact(
                username=username,
                public_key_bytes=public_key_bytes,
                domain=self.domain
            )
            self.contacts[username] = contact
            print(f"Added contact: {username}")
            return True
        except Exception as e:
            print(f"Failed to add contact: {e}")
            return False
    
    def send_message(self, recipient_username: str, message: str) -> bool:
        """Send a message to a recipient"""
        if recipient_username not in self.contacts:
            print(f"Unknown recipient: {recipient_username}")
            return False
        
        contact = self.contacts[recipient_username]
        
        import hashlib
        recipient_id = hashlib.sha256(contact.public_key_bytes).digest()
        msg = DMPMessage(
            header=DMPHeader(
                message_type=MessageType.DATA,
                sender_id=self.user_id,
                recipient_id=recipient_id,
            ),
            payload=message.encode('utf-8')
        )
        
        # Chunk the message
        chunks = self.chunker.chunk_message(msg)
        
        print(f"Sending message to {recipient_username}:")
        print(f"  Message: {message}")
        print(f"  Chunks: {len(chunks)}")
        
        # Simulate sending chunks (in real implementation, would use DNS)
        for chunk_num, chunk_data in chunks:
            domain = DNSEncoder.encode_chunk_domain(
                f"{chunk_num:04d}",
                msg.header.message_id,
                contact.domain
            )
            print(f"  Chunk {chunk_num}: {domain} ({len(chunk_data)} bytes)")
        
        return True
    
    def receive_messages(self) -> List[Tuple[str, str]]:
        """Check for new messages (simulated)"""
        # In real implementation, would poll DNS mailbox
        return []
    
    def get_public_key_hex(self) -> str:
        """Get own public key as hex string"""
        return self.crypto.get_public_key_bytes().hex()
    
    def get_user_info(self) -> dict:
        """Get user information"""
        return {
            'username': self.username,
            'domain': self.domain,
            'public_key': self.get_public_key_hex(),
            'user_id': self.user_id.hex()
        }