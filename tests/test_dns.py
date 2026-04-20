"""Tests for DNS operations and encoding"""

import pytest
import base64
import json
from dmp.core.dns import DMPDNSRecord, DNSEncoder, DNSOperations, DNSChunkManager


class TestDMPDNSRecord:
    """Test DNS record container"""

    def test_record_creation(self):
        """Test basic DNS record creation"""
        record = DMPDNSRecord(
            version=1, record_type="chunk", data=b"test data", metadata={"chunk": 0}
        )

        assert record.version == 1
        assert record.record_type == "chunk"
        assert record.data == b"test data"
        assert record.metadata == {"chunk": 0}

    def test_txt_record_conversion(self):
        """Test conversion to/from TXT record format"""
        original = DMPDNSRecord(
            version=1,
            record_type="identity",
            data=b"identity data here",
            metadata={"username": "alice", "timestamp": 12345},
        )

        # Convert to TXT
        txt = original.to_txt_record()
        assert txt.startswith("v=dmp1")
        assert "t=identity" in txt
        assert "d=" in txt

        # Verify base64 encoding
        parts = dict(p.split("=", 1) for p in txt.split(";") if "=" in p)
        decoded_data = base64.b64decode(parts["d"])
        assert decoded_data == b"identity data here"

        # Round-trip test
        restored = DMPDNSRecord.from_txt_record(txt)
        assert restored.version == original.version
        assert restored.record_type == original.record_type
        assert restored.data == original.data
        assert restored.metadata == original.metadata

    def test_record_without_metadata(self):
        """Test record without metadata"""
        record = DMPDNSRecord(
            version=1, record_type="chunk", data=b"simple data", metadata={}
        )

        txt = record.to_txt_record()
        assert "m=" not in txt

        restored = DMPDNSRecord.from_txt_record(txt)
        assert restored.data == b"simple data"
        assert restored.metadata == {}

    def test_invalid_txt_record(self):
        """Test handling of malformed TXT records"""
        # Missing version
        record = DMPDNSRecord.from_txt_record("t=chunk;d=dGVzdA==")
        assert record.version == 1  # Should default to 1

        # Missing type
        record = DMPDNSRecord.from_txt_record("v=dmp1;d=dGVzdA==")
        assert record.record_type == "chunk"  # Should default

        # Invalid base64
        record = DMPDNSRecord.from_txt_record("v=dmp1;t=chunk;d=invalid!")
        assert record.data == b""  # Should default to empty bytes on error


class TestDNSEncoder:
    """Test DNS encoding utilities"""

    def test_encode_chunk_domain(self):
        """Test chunk domain generation"""
        message_id = b"1234567890123456"
        domain = DNSEncoder.encode_chunk_domain("0001", message_id, "mesh.example.com")

        assert domain.endswith(".mesh.example.com")
        assert "chunk-0001" in domain
        assert len(domain.split(".")[0]) <= 63  # Label length limit

    def test_encode_identity_domain(self):
        """Test identity domain generation"""
        domain = DNSEncoder.encode_identity_domain("alice", "mesh.example.com")

        assert domain.startswith("id-")
        assert domain.endswith(".mesh.example.com")
        assert len(domain.split(".")[0]) <= 63

        # Same username should produce same domain
        domain2 = DNSEncoder.encode_identity_domain("alice", "mesh.example.com")
        assert domain == domain2

    def test_encode_mailbox_domain(self):
        """Test mailbox domain generation"""
        user_id = b"U" * 32
        domain = DNSEncoder.encode_mailbox_domain(user_id, 5, "mesh.example.com")

        assert domain.startswith("mb-")
        assert "-05." in domain  # Slot number
        assert domain.endswith(".mesh.example.com")

    def test_split_for_txt_records(self):
        """Test data splitting for TXT records"""
        # Small data
        small_data = b"A" * 100
        chunks = DNSEncoder.split_for_txt_records(small_data)
        assert len(chunks) == 1
        assert chunks[0] == small_data

        # Large data requiring multiple chunks
        large_data = b"B" * 500
        chunks = DNSEncoder.split_for_txt_records(large_data)
        assert len(chunks) > 1
        assert all(len(chunk) <= DNSEncoder.SAFE_CHUNK_SIZE for chunk in chunks)

        # Reassemble and verify
        reassembled = b"".join(chunks)
        assert reassembled == large_data

    def test_validate_domain(self):
        """Test domain validation"""
        # Valid domains
        assert DNSEncoder.validate_domain("example.com")
        assert DNSEncoder.validate_domain("sub.example.com")
        assert DNSEncoder.validate_domain("a-b.example.com")
        assert DNSEncoder.validate_domain("123.example.com")

        # Invalid domains
        assert not DNSEncoder.validate_domain("")
        assert not DNSEncoder.validate_domain("a" * 254)  # Too long
        assert not DNSEncoder.validate_domain("bad-.example.com")  # Ends with hyphen
        assert not DNSEncoder.validate_domain("-bad.example.com")  # Starts with hyphen
        assert not DNSEncoder.validate_domain("bad..example.com")  # Empty label
        assert not DNSEncoder.validate_domain("bad@.example.com")  # Invalid character
        assert not DNSEncoder.validate_domain(
            "label-" + "a" * 60 + ".com"
        )  # Label too long


class TestDNSOperations:
    """Test DNS query operations"""

    def test_dns_operations_init(self):
        """Test DNS operations initialization"""
        # Default initialization
        ops = DNSOperations()
        assert ops.resolver.timeout == 5.0
        assert ops.resolver.lifetime == 10.0

        # Custom resolvers
        ops = DNSOperations(["8.8.8.8", "1.1.1.1"])
        assert ops.resolver.nameservers == ["8.8.8.8", "1.1.1.1"]

    def test_query_txt_record_mock(self):
        """Test TXT record query (mocked)"""
        ops = DNSOperations()

        # This would need actual DNS or mocking
        # For now, test the method exists and handles None
        result = ops.query_txt_record("nonexistent.example.com")
        assert result is None

    def test_query_dmp_record_parsing(self):
        """Test DMP record query and parsing"""
        ops = DNSOperations()

        # Mock the query_txt_record method for testing
        def mock_query(domain):
            if "test" in domain:
                return ["v=dmp1;t=chunk;d=dGVzdCBkYXRh"]
            return None

        ops.query_txt_record = mock_query

        # Query existing record
        record = ops.query_dmp_record("test.example.com")
        assert record is not None
        assert record.record_type == "chunk"
        assert record.data == b"test data"

        # Query non-existent record
        record = ops.query_dmp_record("none.example.com")
        assert record is None

    def test_discover_nodes(self):
        """Test node discovery"""
        ops = DNSOperations()

        # Mock the query method
        def mock_query(domain):
            if "announce" in domain:
                return ["node=node1.mesh.com", "node=node2.mesh.com"]
            return None

        ops.query_txt_record = mock_query

        nodes = ops.discover_nodes("discovery.mesh.com")
        assert len(nodes) == 2
        assert "node1.mesh.com" in nodes
        assert "node2.mesh.com" in nodes

    def test_check_mailbox(self):
        """Test mailbox checking"""
        ops = DNSOperations()

        # Mock the query_dmp_record method
        def mock_query_dmp(domain):
            if "mb-" in domain and "-03." in domain:
                return DMPDNSRecord(
                    version=1,
                    record_type="mailbox",
                    data=b"message for slot 3",
                    metadata={"slot": 3},
                )
            return None

        ops.query_dmp_record = mock_query_dmp

        user_id = b"U" * 32
        messages = ops.check_mailbox(user_id, "mesh.com", num_slots=5)

        assert len(messages) == 1
        assert messages[0][0] == 3  # Slot number
        assert messages[0][1].data == b"message for slot 3"


class TestDNSChunkManager:
    """Test chunk management"""

    def test_chunk_storage_retrieval(self):
        """Test storing and retrieving chunks"""
        ops = DNSOperations()
        manager = DNSChunkManager(ops)

        # Mock the DNS operations
        stored_records = {}

        def mock_publish(domain, record, ttl=300):
            stored_records[domain] = record
            return True

        def mock_query(domain):
            if domain in stored_records:
                return stored_records[domain]
            return None

        ops.publish_txt_record = mock_publish
        ops.query_dmp_record = mock_query

        # Store a chunk
        message_id = b"MSG123" * 3
        chunk_data = b"This is chunk 0 data"
        success = manager.store_chunk(message_id, 0, chunk_data, "mesh.com")
        assert success

        # Retrieve the chunk
        retrieved = manager.retrieve_chunk(message_id, 0, "mesh.com")
        assert retrieved == chunk_data

        # Try to retrieve non-existent chunk
        missing = manager.retrieve_chunk(message_id, 999, "mesh.com")
        assert missing is None

    def test_retrieve_all_chunks(self):
        """Test retrieving all chunks for a message"""
        ops = DNSOperations()
        manager = DNSChunkManager(ops)

        # Mock storage
        stored_chunks = {}

        def mock_retrieve(message_id, chunk_num, base_domain):
            key = f"{message_id.hex()}-{chunk_num}"
            return stored_chunks.get(key)

        manager.retrieve_chunk = mock_retrieve

        # Store test chunks
        message_id = b"MSG456" * 3
        chunks_data = [b"chunk0", b"chunk1", b"chunk2"]
        for i, data in enumerate(chunks_data):
            key = f"{message_id.hex()}-{i}"
            stored_chunks[key] = data

        # Retrieve all chunks
        retrieved = manager.retrieve_all_chunks(message_id, 3, "mesh.com")
        assert retrieved == chunks_data

        # Test with missing chunk
        del stored_chunks[f"{message_id.hex()}-1"]
        retrieved = manager.retrieve_all_chunks(message_id, 3, "mesh.com")
        assert retrieved is None  # Should return None if any chunk is missing
