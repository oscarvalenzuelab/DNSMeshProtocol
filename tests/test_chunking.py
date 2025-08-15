"""Tests for message chunking and reassembly"""

import pytest
import uuid
from dmp.core.chunking import (
    MessageChunker, MessageAssembler, ChunkInfo, ChunkRouter
)
from dmp.core.message import DMPMessage, DMPHeader, MessageType


class TestMessageChunker:
    """Test message chunking functionality"""
    
    def test_basic_chunking(self):
        """Test basic message chunking"""
        chunker = MessageChunker(enable_error_correction=False)
        
        # Create a test message
        message = DMPMessage(
            header=DMPHeader(
                message_id=uuid.uuid4().bytes,
                sender_id=b'S' * 32,
                recipient_id=b'R' * 32
            ),
            payload=b'A' * 500  # Large enough to require multiple chunks
        )
        
        chunks = chunker.chunk_message(message, include_redundancy=False)
        
        # Verify chunks were created
        assert len(chunks) > 1
        
        # Verify chunk structure
        for chunk_num, chunk_data in chunks:
            assert isinstance(chunk_num, int)
            assert isinstance(chunk_data, bytes)
            assert len(chunk_data) <= chunker.MAX_CHUNK_SIZE + 8  # +8 for checksum
    
    def test_chunking_with_error_correction(self):
        """Test chunking with Reed-Solomon error correction"""
        chunker = MessageChunker(enable_error_correction=True)
        
        message = DMPMessage(
            payload=b'Test message for ECC'
        )
        
        chunks_no_ecc = chunker.chunk_message(message, include_redundancy=False)
        chunks_with_ecc = chunker.chunk_message(message, include_redundancy=True)
        
        # ECC should add more data
        total_size_no_ecc = sum(len(data) for _, data in chunks_no_ecc)
        total_size_with_ecc = sum(len(data) for _, data in chunks_with_ecc)
        assert total_size_with_ecc > total_size_no_ecc
    
    def test_create_message_chunks(self):
        """Test creating chunk messages"""
        chunker = MessageChunker()
        
        original = DMPMessage(
            header=DMPHeader(
                message_id=uuid.uuid4().bytes,
                message_type=MessageType.DATA
            ),
            payload=b'X' * 300
        )
        
        chunk_messages = chunker.create_message_chunks(original)
        
        assert len(chunk_messages) > 0
        for chunk_msg in chunk_messages:
            assert isinstance(chunk_msg, DMPMessage)
            assert chunk_msg.header.message_id == original.header.message_id
            assert chunk_msg.header.total_chunks == len(chunk_messages)
    
    def test_chunk_checksum(self):
        """Test chunk checksum verification"""
        chunk_info = ChunkInfo(
            chunk_number=0,
            total_chunks=5,
            data=b'test chunk data',
            checksum=b'\x00' * 8
        )
        
        # Invalid checksum should fail
        assert not chunk_info.verify_checksum()
        
        # Valid checksum should pass
        import hashlib
        chunk_info.checksum = hashlib.sha256(chunk_info.data).digest()[:8]
        assert chunk_info.verify_checksum()


class TestMessageAssembler:
    """Test message reassembly functionality"""
    
    def test_basic_assembly(self):
        """Test basic message assembly from chunks"""
        chunker = MessageChunker(enable_error_correction=False)
        assembler = MessageAssembler(enable_error_correction=False)
        
        # Create and chunk a message
        original = DMPMessage(
            header=DMPHeader(message_id=uuid.uuid4().bytes),
            payload=b'Test message for assembly'
        )
        
        chunks = chunker.chunk_message(original, include_redundancy=False)
        
        # Add chunks to assembler
        result = None
        for chunk_num, chunk_data in chunks:
            result = assembler.add_chunk(
                original.header.message_id,
                chunk_num,
                chunk_data,
                len(chunks)
            )
        
        # Should return complete message after last chunk
        assert result is not None
        
        # Verify reassembled message
        reassembled = DMPMessage.from_bytes(result)
        assert reassembled.payload == original.payload
    
    def test_out_of_order_assembly(self):
        """Test assembly with chunks arriving out of order"""
        chunker = MessageChunker(enable_error_correction=False)
        assembler = MessageAssembler(enable_error_correction=False)
        
        original = DMPMessage(payload=b'Y' * 500)
        chunks = chunker.chunk_message(original, include_redundancy=False)
        
        # Add chunks in reverse order
        result = None
        for chunk_num, chunk_data in reversed(chunks):
            result = assembler.add_chunk(
                original.header.message_id,
                chunk_num,
                chunk_data,
                len(chunks)
            )
        
        # Should still assemble correctly
        assert result is not None
        reassembled = DMPMessage.from_bytes(result)
        assert reassembled.payload == original.payload
    
    def test_missing_chunks_detection(self):
        """Test detection of missing chunks"""
        assembler = MessageAssembler()
        message_id = uuid.uuid4().bytes
        total_chunks = 5
        
        # Add some but not all chunks
        import hashlib
        for i in [0, 2, 4]:  # Skip 1 and 3
            chunk_data = b'chunk' + str(i).encode()
            checksum = hashlib.sha256(chunk_data).digest()[:8]
            assembler.add_chunk(
                message_id,
                i,
                checksum + chunk_data,
                total_chunks
            )
        
        # Check missing chunks
        missing = assembler.get_missing_chunks(message_id, total_chunks)
        assert missing == [1, 3]
        
        # Check progress
        progress = assembler.get_assembly_progress(message_id, total_chunks)
        assert progress == 0.6  # 3 out of 5
    
    def test_corrupted_chunk_rejection(self):
        """Test that corrupted chunks are rejected"""
        assembler = MessageAssembler()
        
        message_id = uuid.uuid4().bytes
        chunk_data = b'valid chunk data'
        
        # Create chunk with wrong checksum
        bad_checksum = b'\xFF' * 8
        result = assembler.add_chunk(
            message_id,
            0,
            bad_checksum + chunk_data,
            1
        )
        
        # Should reject corrupted chunk
        assert result is None
        assert message_id not in assembler.pending_messages
    
    def test_assembly_with_error_correction(self):
        """Test assembly with Reed-Solomon error correction"""
        chunker = MessageChunker(enable_error_correction=True)
        assembler = MessageAssembler(enable_error_correction=True)
        
        # Use a simple test to verify ECC works
        test_data = b'Test data for ECC'
        
        # Add ECC
        with_ecc = chunker._add_error_correction(test_data)
        assert len(with_ecc) > len(test_data)  # ECC adds data
        
        # Remove ECC
        recovered = chunker._remove_error_correction(with_ecc)
        assert test_data in recovered  # Original data should be present
        
        # For full message test, just verify chunking and assembly complete
        original = DMPMessage(payload=b'Simple test')
        chunks = chunker.chunk_message(original, include_redundancy=True)
        
        result = None
        for chunk_num, chunk_data in chunks:
            result = assembler.add_chunk(
                original.header.message_id,
                chunk_num,
                chunk_data,
                len(chunks),
                original.header
            )
        
        # Just verify we got something back
        assert result is not None
        assert len(result) > 0
    
    def test_cleanup_expired(self):
        """Test cleanup of expired partial messages"""
        assembler = MessageAssembler()
        
        # Add a chunk with old timestamp
        old_header = DMPHeader(
            message_id=b'old_msg',
            timestamp=1000
        )
        
        import hashlib
        chunk_data = b'old chunk'
        checksum = hashlib.sha256(chunk_data).digest()[:8]
        
        assembler.add_chunk(
            old_header.message_id,
            0,
            checksum + chunk_data,
            2,
            old_header
        )
        
        # Should be present initially
        assert old_header.message_id in assembler.pending_messages
        
        # Cleanup with current time past expiry
        assembler.cleanup_expired(current_time=1400, ttl=300)
        
        # Should be removed
        assert old_header.message_id not in assembler.pending_messages


class TestChunkRouter:
    """Test chunk routing functionality"""
    
    def test_duplicate_detection(self):
        """Test that duplicate chunks are detected"""
        router = ChunkRouter()
        
        message_id = b'MSG123'
        chunk_number = 0
        
        # First time should forward
        assert router.should_forward_chunk(message_id, chunk_number)
        
        # Second time should not forward (duplicate)
        assert not router.should_forward_chunk(message_id, chunk_number)
    
    def test_route_management(self):
        """Test routing table management"""
        router = ChunkRouter()
        
        recipient_id = b'R' * 32
        
        # Initially no routes
        destinations = router.get_forward_destinations(recipient_id)
        assert destinations == []
        
        # Add routes
        router.update_route(recipient_id, 'node1.mesh')
        router.update_route(recipient_id, 'node2.mesh')
        
        destinations = router.get_forward_destinations(recipient_id)
        assert 'node1.mesh' in destinations
        assert 'node2.mesh' in destinations
    
    def test_route_exclusion(self):
        """Test excluding nodes from routing"""
        router = ChunkRouter()
        
        recipient_id = b'R' * 32
        router.update_route(recipient_id, 'node1.mesh')
        router.update_route(recipient_id, 'node2.mesh')
        router.update_route(recipient_id, 'node3.mesh')
        
        # Exclude node2
        destinations = router.get_forward_destinations(
            recipient_id,
            exclude_nodes=['node2.mesh']
        )
        
        assert 'node1.mesh' in destinations
        assert 'node2.mesh' not in destinations
        assert 'node3.mesh' in destinations
    
    def test_route_limit(self):
        """Test that route table has size limit"""
        router = ChunkRouter()
        recipient_id = b'R' * 32
        
        # Add more than limit (5)
        for i in range(10):
            router.update_route(recipient_id, f'node{i}.mesh')
        
        destinations = router.get_forward_destinations(recipient_id)
        assert len(destinations) <= 5
        # Should keep most recent
        assert 'node9.mesh' in destinations
        assert 'node0.mesh' not in destinations