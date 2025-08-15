"""Tests for DMP message structures"""

import pytest
import time
import uuid
from dmp.core.message import DMPHeader, DMPMessage, DMPIdentity, MessageType


class TestDMPHeader:
    """Test DMPHeader functionality"""
    
    def test_header_creation(self):
        """Test basic header creation"""
        header = DMPHeader()
        assert header.version == 1
        assert header.message_type == MessageType.DATA
        assert len(header.message_id) == 16
        assert len(header.sender_id) == 32
        assert len(header.recipient_id) == 32
        assert header.total_chunks == 1
        assert header.chunk_number == 0
        assert header.ttl == 300
    
    def test_header_serialization(self):
        """Test header serialization and deserialization"""
        original = DMPHeader(
            message_type=MessageType.ACK,
            message_id=uuid.uuid4().bytes,
            sender_id=b'A' * 32,
            recipient_id=b'B' * 32,
            total_chunks=5,
            chunk_number=2
        )
        
        serialized = original.to_bytes()
        deserialized = DMPHeader.from_bytes(serialized)
        
        assert deserialized.version == original.version
        assert deserialized.message_type == original.message_type
        assert deserialized.message_id == original.message_id
        assert deserialized.sender_id == original.sender_id
        assert deserialized.recipient_id == original.recipient_id
        assert deserialized.total_chunks == original.total_chunks
        assert deserialized.chunk_number == original.chunk_number
    
    def test_header_expiration(self):
        """Test TTL expiration check"""
        # Create expired header
        expired = DMPHeader(
            timestamp=int(time.time()) - 400,
            ttl=300
        )
        assert expired.is_expired()
        
        # Create valid header
        valid = DMPHeader()
        assert not valid.is_expired()
    
    def test_chunk_id_generation(self):
        """Test chunk ID generation"""
        header = DMPHeader(
            message_id=b'\x01' * 16,
            chunk_number=42
        )
        chunk_id = header.get_chunk_id()
        assert chunk_id == "01010101010101010101010101010101-0042"


class TestDMPMessage:
    """Test DMPMessage functionality"""
    
    def test_message_creation(self):
        """Test basic message creation"""
        msg = DMPMessage()
        assert isinstance(msg.header, DMPHeader)
        assert msg.payload == b''
        assert len(msg.signature) == 32
    
    def test_message_serialization(self):
        """Test message serialization and deserialization"""
        original = DMPMessage(
            header=DMPHeader(
                message_type=MessageType.DATA,
                sender_id=b'X' * 32,
                recipient_id=b'Y' * 32
            ),
            payload=b'Hello, World!',
            signature=b'S' * 32
        )
        
        serialized = original.to_bytes()
        deserialized = DMPMessage.from_bytes(serialized)
        
        assert deserialized.header.message_type == original.header.message_type
        assert deserialized.header.sender_id == original.header.sender_id
        assert deserialized.header.recipient_id == original.header.recipient_id
        assert deserialized.payload == original.payload
        assert deserialized.signature == original.signature
    
    def test_invalid_message_deserialization(self):
        """Test handling of invalid message data"""
        # Too short
        with pytest.raises(ValueError, match="too short"):
            DMPMessage.from_bytes(b'short')
        
        # Invalid header length (header says 16 bytes but not enough data)
        with pytest.raises(ValueError, match="incomplete"):
            DMPMessage.from_bytes(b'\x00\x10' + b'A' * 40)  # 2 + 40 = 42 bytes, but needs 2 + 16 + 32 = 50
    
    def test_message_hash(self):
        """Test message hash calculation"""
        msg = DMPMessage(
            payload=b'Test payload'
        )
        hash1 = msg.calculate_message_hash()
        assert len(hash1) == 32
        
        # Same message should produce same hash
        hash2 = msg.calculate_message_hash()
        assert hash1 == hash2
        
        # Different payload should produce different hash
        msg.payload = b'Different payload'
        hash3 = msg.calculate_message_hash()
        assert hash1 != hash3
    
    def test_create_chunk(self):
        """Test chunk creation from message"""
        original = DMPMessage(
            header=DMPHeader(
                message_id=uuid.uuid4().bytes,
                sender_id=b'A' * 32,
                recipient_id=b'B' * 32,
                total_chunks=10
            ),
            payload=b'Original payload',
            signature=b'S' * 32
        )
        
        chunk = original.create_chunk(3, b'Chunk data')
        
        assert chunk.header.message_id == original.header.message_id
        assert chunk.header.sender_id == original.header.sender_id
        assert chunk.header.recipient_id == original.header.recipient_id
        assert chunk.header.total_chunks == 10
        assert chunk.header.chunk_number == 3
        assert chunk.payload == b'Chunk data'
        assert chunk.signature == original.signature
    
    def test_message_validation(self):
        """Test message validation"""
        # Valid message
        msg = DMPMessage()
        valid, reason = msg.validate_basic()
        assert valid
        assert reason == "Valid"
        
        # Expired message
        msg.header.timestamp = int(time.time()) - 400
        msg.header.ttl = 300
        valid, reason = msg.validate_basic()
        assert not valid
        assert "expired" in reason
        
        # Invalid chunk number
        msg = DMPMessage()
        msg.header.chunk_number = 5
        msg.header.total_chunks = 3
        valid, reason = msg.validate_basic()
        assert not valid
        assert "chunk number" in reason
        
        # Invalid message ID length
        msg = DMPMessage()
        msg.header.message_id = b'short'
        valid, reason = msg.validate_basic()
        assert not valid
        assert "message ID" in reason


class TestDMPIdentity:
    """Test DMPIdentity functionality"""
    
    def test_identity_creation(self):
        """Test identity creation"""
        identity = DMPIdentity(
            username="alice",
            public_key=b'P' * 32
        )
        assert identity.username == "alice"
        assert len(identity.public_key) == 32
        assert identity.created_at > 0
    
    def test_user_id_generation(self):
        """Test user ID generation from public key"""
        identity = DMPIdentity(
            username="bob",
            public_key=b'K' * 32
        )
        user_id = identity.get_user_id()
        assert len(user_id) == 32
        
        # Same key should produce same ID
        user_id2 = identity.get_user_id()
        assert user_id == user_id2
    
    def test_dns_record_conversion(self):
        """Test conversion to/from DNS record format"""
        original = DMPIdentity(
            username="charlie",
            public_key=b'C' * 32,
            signature=b'S' * 64,
            metadata={'email': 'charlie@example.com'}
        )
        
        dns_record = original.to_dns_record()
        assert dns_record.startswith("v=dmp1;type=identity;data=")
        assert "charlie" in dns_record
        
        # Round-trip test
        restored = DMPIdentity.from_dns_record(dns_record)
        assert restored.username == original.username
        assert restored.public_key == original.public_key
        assert restored.signature == original.signature
        assert restored.metadata == original.metadata
    
    def test_invalid_dns_record(self):
        """Test handling of invalid DNS record"""
        with pytest.raises(ValueError, match="Invalid identity record"):
            DMPIdentity.from_dns_record("invalid record")


class TestMessageTypes:
    """Test MessageType enum"""
    
    def test_message_types(self):
        """Test all message types are defined"""
        assert MessageType.DATA.value == "DATA"
        assert MessageType.ACK.value == "ACK"
        assert MessageType.DISCOVERY.value == "DISCOVERY"
        assert MessageType.IDENTITY.value == "IDENTITY"
        assert MessageType.MAILBOX.value == "MAILBOX"