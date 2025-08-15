"""Message chunking and reassembly with Reed-Solomon error correction"""

import hashlib
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
import reedsolo

from dmp.core.message import DMPMessage, DMPHeader, MessageType
from dmp.core.dns import DNSEncoder


@dataclass
class ChunkInfo:
    """Information about a message chunk"""
    chunk_number: int
    total_chunks: int
    data: bytes
    checksum: bytes
    
    def verify_checksum(self) -> bool:
        """Verify chunk integrity"""
        calculated = hashlib.sha256(self.data).digest()[:8]
        return calculated == self.checksum


class MessageChunker:
    """Split messages into DNS-compatible chunks with error correction"""
    
    # Conservative chunk size for DNS TXT records
    MAX_CHUNK_SIZE = 240
    
    # Reed-Solomon parameters
    RS_SYMBOLS = 32  # Number of error correction symbols per chunk
    RS_CODEC = reedsolo.RSCodec(RS_SYMBOLS)
    
    def __init__(self, enable_error_correction: bool = True):
        """Initialize chunker with optional error correction"""
        self.enable_error_correction = enable_error_correction
    
    def chunk_message(
        self,
        message: DMPMessage,
        include_redundancy: bool = True
    ) -> List[Tuple[int, bytes]]:
        """
        Split a message into chunks with error correction.
        Returns list of (chunk_number, chunk_data) tuples.
        """
        # Serialize the complete message
        message_bytes = message.to_bytes()
        
        # Add error correction if enabled
        if self.enable_error_correction and include_redundancy:
            chunks_with_ecc = self._add_error_correction(message_bytes)
        else:
            chunks_with_ecc = message_bytes
        
        # Split into chunks
        chunks = []
        chunk_size = self.MAX_CHUNK_SIZE
        total_chunks = (len(chunks_with_ecc) + chunk_size - 1) // chunk_size
        
        for i in range(0, len(chunks_with_ecc), chunk_size):
            chunk_data = chunks_with_ecc[i:i + chunk_size]
            chunk_number = i // chunk_size
            
            # Add checksum for integrity verification
            checksum = hashlib.sha256(chunk_data).digest()[:8]
            chunk_with_checksum = checksum + chunk_data
            
            chunks.append((chunk_number, chunk_with_checksum))
        
        # Update message header with chunk count
        message.header.total_chunks = len(chunks)
        
        return chunks
    
    def _add_error_correction(self, data: bytes) -> bytes:
        """Add Reed-Solomon error correction to data"""
        # Process data in blocks that fit Reed-Solomon constraints
        block_size = 223  # Maximum block size for RS(255, 223)
        encoded_blocks = []
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            # Pad if necessary
            if len(block) < block_size:
                block = block + b'\x00' * (block_size - len(block))
            
            # Encode with Reed-Solomon
            encoded = self.RS_CODEC.encode(block)
            encoded_blocks.append(encoded)
        
        return b''.join(encoded_blocks)
    
    def _remove_error_correction(self, data: bytes) -> bytes:
        """Remove Reed-Solomon error correction and recover data"""
        # Calculate block size including ECC symbols
        block_size = 223 + self.RS_SYMBOLS
        decoded_blocks = []
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            
            try:
                # Decode with error correction
                decoded = self.RS_CODEC.decode(block)[0]
                decoded_blocks.append(decoded)
            except reedsolo.ReedSolomonError:
                # If decoding fails, use the data as-is (minus ECC)
                decoded_blocks.append(block[:223])
        
        result = b''.join(decoded_blocks)
        # Remove padding
        return result.rstrip(b'\x00')
    
    def create_message_chunks(
        self,
        message: DMPMessage
    ) -> List[DMPMessage]:
        """Create chunk messages from a complete message"""
        chunks = self.chunk_message(message)
        chunk_messages = []
        
        for chunk_num, chunk_data in chunks:
            chunk_msg = message.create_chunk(chunk_num, chunk_data)
            chunk_msg.header.total_chunks = len(chunks)
            chunk_messages.append(chunk_msg)
        
        return chunk_messages


class MessageAssembler:
    """Reassemble messages from chunks with error recovery"""
    
    def __init__(self, enable_error_correction: bool = True):
        """Initialize assembler"""
        self.enable_error_correction = enable_error_correction
        self.pending_messages: Dict[bytes, Dict[int, bytes]] = {}
        self.message_metadata: Dict[bytes, DMPHeader] = {}
    
    def add_chunk(
        self,
        message_id: bytes,
        chunk_number: int,
        chunk_data: bytes,
        total_chunks: int,
        header: Optional[DMPHeader] = None
    ) -> Optional[bytes]:
        """
        Add a chunk to the assembly buffer.
        Returns complete message bytes if all chunks are received.
        """
        # Verify chunk data first
        if len(chunk_data) <= 8:  # Must have checksum
            return None  # Invalid chunk
        
        checksum = chunk_data[:8]
        data = chunk_data[8:]
        
        # Verify checksum
        calculated = hashlib.sha256(data).digest()[:8]
        if calculated != checksum:
            return None  # Corrupted chunk
        
        # Initialize storage for this message if needed (only after validation)
        if message_id not in self.pending_messages:
            self.pending_messages[message_id] = {}
            if header:
                self.message_metadata[message_id] = header
        
        # Store valid chunk
        self.pending_messages[message_id][chunk_number] = data
        
        # Check if we have all chunks
        if len(self.pending_messages[message_id]) == total_chunks:
            return self._assemble_message(message_id, total_chunks)
        
        return None
    
    def _assemble_message(
        self,
        message_id: bytes,
        total_chunks: int
    ) -> Optional[bytes]:
        """Assemble complete message from chunks"""
        chunks = self.pending_messages.get(message_id, {})
        
        # Verify we have all chunks
        if len(chunks) != total_chunks:
            return None
        
        # Sort chunks by number and concatenate
        sorted_chunks = [chunks[i] for i in range(total_chunks)]
        combined_data = b''.join(sorted_chunks)
        
        # Remove error correction if enabled
        if self.enable_error_correction:
            chunker = MessageChunker(enable_error_correction=True)
            try:
                message_data = chunker._remove_error_correction(combined_data)
            except Exception:
                # Fallback to raw data if ECC fails
                message_data = combined_data
        else:
            message_data = combined_data
        
        # Clean up
        del self.pending_messages[message_id]
        if message_id in self.message_metadata:
            del self.message_metadata[message_id]
        
        return message_data
    
    def get_missing_chunks(
        self,
        message_id: bytes,
        total_chunks: int
    ) -> List[int]:
        """Get list of missing chunk numbers for a message"""
        if message_id not in self.pending_messages:
            return list(range(total_chunks))
        
        received = set(self.pending_messages[message_id].keys())
        all_chunks = set(range(total_chunks))
        missing = all_chunks - received
        
        return sorted(list(missing))
    
    def get_assembly_progress(
        self,
        message_id: bytes,
        total_chunks: int
    ) -> float:
        """Get assembly progress as percentage (0.0 to 1.0)"""
        if message_id not in self.pending_messages:
            return 0.0
        
        received = len(self.pending_messages[message_id])
        return received / total_chunks
    
    def cleanup_expired(self, current_time: int, ttl: int = 300):
        """Remove expired partial messages"""
        expired = []
        
        for message_id, header in self.message_metadata.items():
            if current_time > (header.timestamp + ttl):
                expired.append(message_id)
        
        for message_id in expired:
            if message_id in self.pending_messages:
                del self.pending_messages[message_id]
            if message_id in self.message_metadata:
                del self.message_metadata[message_id]


class ChunkRouter:
    """Route chunks through the mesh network"""
    
    def __init__(self):
        """Initialize chunk router"""
        self.seen_chunks: set = set()
        self.route_table: Dict[bytes, List[str]] = {}
    
    def should_forward_chunk(
        self,
        message_id: bytes,
        chunk_number: int
    ) -> bool:
        """Determine if a chunk should be forwarded"""
        chunk_id = hashlib.sha256(
            message_id + chunk_number.to_bytes(4, 'big')
        ).digest()
        
        if chunk_id in self.seen_chunks:
            return False
        
        self.seen_chunks.add(chunk_id)
        return True
    
    def get_forward_destinations(
        self,
        recipient_id: bytes,
        exclude_nodes: Optional[List[str]] = None
    ) -> List[str]:
        """Get list of nodes to forward chunk to"""
        if recipient_id in self.route_table:
            destinations = self.route_table[recipient_id].copy()
            if exclude_nodes:
                destinations = [d for d in destinations if d not in exclude_nodes]
            return destinations
        
        # Default: return empty list (no known routes)
        return []
    
    def update_route(
        self,
        recipient_id: bytes,
        node_address: str
    ):
        """Update routing table with new route"""
        if recipient_id not in self.route_table:
            self.route_table[recipient_id] = []
        
        if node_address not in self.route_table[recipient_id]:
            self.route_table[recipient_id].append(node_address)
            # Keep only the most recent routes
            if len(self.route_table[recipient_id]) > 5:
                self.route_table[recipient_id] = self.route_table[recipient_id][-5:]