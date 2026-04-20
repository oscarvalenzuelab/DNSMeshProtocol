"""Message chunking and reassembly with per-chunk Reed-Solomon error correction.

Each chunk is independently protected by Reed-Solomon bytes. This provides bit-error
correction within a chunk but does NOT provide erasure coding across chunks — a lost
chunk still kills the message. True cross-chunk erasure coding is future work.
"""

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
    """Split messages into DNS-compatible chunks with per-chunk error correction.

    Wire format per chunk: checksum(8 bytes) + rs_encoded_payload
    rs_encoded_payload = RSCodec.encode(raw_data) when ECC is enabled, else raw_data.
    reedsolo handles variable-length encode/decode internally, so no padding games.
    """

    # Max bytes of raw message data per chunk (before RS + checksum overhead).
    # Sized so the full TXT record (`v=dmp1;t=chunk;d=<b64>`) fits in one
    # 255-byte DNS TXT string:
    #   128 raw + 32 RS + 8 checksum = 168 bytes  →  224 base64 chars
    #   plus 17-char prefix "v=dmp1;t=chunk;d=" = 241 chars total.
    DATA_PER_CHUNK = 128
    MAX_CHUNK_SIZE = DATA_PER_CHUNK  # back-compat alias
    # Reed-Solomon parameters — 32 parity bytes corrects up to 16 byte-errors per chunk
    RS_SYMBOLS = 32
    RS_CODEC = reedsolo.RSCodec(RS_SYMBOLS)

    def __init__(self, enable_error_correction: bool = True):
        self.enable_error_correction = enable_error_correction

    def chunk_message(
        self,
        message: DMPMessage,
        include_redundancy: bool = True,
    ) -> List[Tuple[int, bytes]]:
        """Split a message into chunks with per-chunk ECC.

        Returns list of (chunk_number, chunk_wire_bytes).
        Mutates message.header.total_chunks.
        """
        use_ecc = self.enable_error_correction and include_redundancy

        # Chunk the raw message bytes first, then compute total_chunks, then
        # re-serialize so the header-in-chunks reflects the final total_chunks.
        raw = message.to_bytes()
        data_size = self.DATA_PER_CHUNK
        total = max(1, (len(raw) + data_size - 1) // data_size)
        message.header.total_chunks = total

        # Re-serialize once header.total_chunks is stable. If chunk count shifts
        # because of the header-size change, re-chunk one more time (at most).
        raw = message.to_bytes()
        new_total = max(1, (len(raw) + data_size - 1) // data_size)
        if new_total != total:
            message.header.total_chunks = new_total
            raw = message.to_bytes()
            total = new_total

        chunks: List[Tuple[int, bytes]] = []
        for chunk_num in range(total):
            offset = chunk_num * data_size
            piece = raw[offset:offset + data_size]
            encoded = bytes(self.RS_CODEC.encode(piece)) if use_ecc else piece
            checksum = hashlib.sha256(encoded).digest()[:8]
            chunks.append((chunk_num, checksum + encoded))

        return chunks

    def create_message_chunks(self, message: DMPMessage) -> List[DMPMessage]:
        """Create chunk messages from a complete message"""
        chunks = self.chunk_message(message)
        return [
            message.create_chunk(chunk_num, chunk_data)
            for chunk_num, chunk_data in chunks
        ]


class MessageAssembler:
    """Reassemble messages from chunks with per-chunk error recovery."""

    def __init__(self, enable_error_correction: bool = True):
        self.enable_error_correction = enable_error_correction
        self.pending_messages: Dict[bytes, Dict[int, bytes]] = {}
        self.message_metadata: Dict[bytes, DMPHeader] = {}

    def add_chunk(
        self,
        message_id: bytes,
        chunk_number: int,
        chunk_data: bytes,
        total_chunks: int,
        header: Optional[DMPHeader] = None,
    ) -> Optional[bytes]:
        """Add a chunk; return full message bytes when complete, else None."""
        if total_chunks <= 0:
            return None
        if chunk_number < 0 or chunk_number >= total_chunks:
            return None
        if len(chunk_data) <= 8:
            return None

        checksum = chunk_data[:8]
        encoded = chunk_data[8:]
        if hashlib.sha256(encoded).digest()[:8] != checksum:
            return None

        if self.enable_error_correction:
            try:
                data = bytes(MessageChunker.RS_CODEC.decode(encoded)[0])
            except reedsolo.ReedSolomonError:
                return None
        else:
            data = encoded

        bucket = self.pending_messages.setdefault(message_id, {})
        if header is not None and message_id not in self.message_metadata:
            self.message_metadata[message_id] = header
        bucket[chunk_number] = data

        if len(bucket) == total_chunks:
            return self._assemble_message(message_id, total_chunks)
        return None

    def _assemble_message(
        self,
        message_id: bytes,
        total_chunks: int,
    ) -> Optional[bytes]:
        chunks = self.pending_messages.get(message_id, {})
        if set(chunks.keys()) != set(range(total_chunks)):
            return None
        message_data = b''.join(chunks[i] for i in range(total_chunks))
        del self.pending_messages[message_id]
        self.message_metadata.pop(message_id, None)
        return message_data

    def get_missing_chunks(self, message_id: bytes, total_chunks: int) -> List[int]:
        received = set(self.pending_messages.get(message_id, {}).keys())
        return sorted(set(range(total_chunks)) - received)

    def get_assembly_progress(self, message_id: bytes, total_chunks: int) -> float:
        if total_chunks <= 0:
            return 0.0
        received = len(self.pending_messages.get(message_id, {}))
        return received / total_chunks

    def cleanup_expired(self, current_time: int, ttl: int = 300) -> None:
        expired = [
            mid for mid, hdr in self.message_metadata.items()
            if current_time > (hdr.timestamp + ttl)
        ]
        for mid in expired:
            self.pending_messages.pop(mid, None)
            self.message_metadata.pop(mid, None)


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