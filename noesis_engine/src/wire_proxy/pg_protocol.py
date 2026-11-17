"""
Apodictic Enterprise PostgreSQL Wire Protocol (Frontend/Backend 3.0) Implementation
Handles raw TCP packet framing:
- StartupMessage / SSLRequest / AuthenticationOk
- Query ('Q') & Parse ('P') / Bind ('B') / Describe ('D') / Execute ('E') / Sync ('S')
- ErrorResponse ('E') synthesis with standard SQLSTATE error codes
- CommandComplete ('C'), ReadyForQuery ('Z'), RowDescription ('T'), DataRow ('D')
"""

import struct
from typing import Dict, List, Optional, Tuple, Any

# PostgreSQL Message Identifiers
MSG_QUERY = b'Q'
MSG_PARSE = b'P'
MSG_BIND = b'B'
MSG_DESCRIBE = b'D'
MSG_EXECUTE = b'E'
MSG_SYNC = b'S'
MSG_TERMINATE = b'X'

MSG_ERROR_RESPONSE = b'E'
MSG_COMMAND_COMPLETE = b'C'
MSG_READY_FOR_QUERY = b'Z'
MSG_ROW_DESCRIPTION = b'T'
MSG_DATA_ROW = b'D'
MSG_AUTHENTICATION = b'R'
MSG_PARAMETER_STATUS = b'S'
MSG_BACKEND_KEY_DATA = b'K'

SSL_REQUEST_CODE = 80877103
CANCEL_REQUEST_CODE = 80877102
PROTOCOL_VERSION_3_0 = 196608  # (3 << 16) | 0

# SQLSTATE Codes
SQLSTATE_VERIFICATION_REJECTED = "28000"  # Invalid authorization / security rejection
SQLSTATE_SOLVENCY_BREACH = "40001"        # Serialization failure / invariant breach
SQLSTATE_DESTRUCTIVE_MUTATION = "42501"   # Insufficient privilege / unauthorized mutation


class PostgresPacket:
    """Represents a discrete framed PostgreSQL wire message."""
    def __init__(self, msg_type: Optional[bytes], length: int, payload: bytes):
        self.msg_type = msg_type  # None for StartupMessage
        self.length = length
        self.payload = payload

    def __repr__(self) -> str:
        t_str = self.msg_type.decode('ascii', errors='replace') if self.msg_type else 'Startup'
        return f"<PostgresPacket type={t_str} len={self.length} payload_len={len(self.payload)}>"


class PostgresWireCodec:
    """
    Decodes and encodes raw byte streams according to PostgreSQL Wire Protocol 3.0.
    """

    @staticmethod
    def decode_packet(buffer: bytes, is_startup: bool = False) -> Tuple[Optional[PostgresPacket], bytes]:
        """
        Parses one message from the buffer. Returns (packet, remaining_buffer).
        If buffer has insufficient bytes for a complete packet, returns (None, buffer).
        """
        if is_startup:
            if len(buffer) < 4:
                return None, buffer
            length = struct.unpack("!I", buffer[:4])[0]
            if len(buffer) < length:
                return None, buffer
            payload = buffer[4:length]
            remaining = buffer[length:]
            return PostgresPacket(None, length, payload), remaining

        if len(buffer) < 5:
            return None, buffer

        msg_type = buffer[0:1]
        length = struct.unpack("!I", buffer[1:5])[0]
        total_len = 1 + length

        if len(buffer) < total_len:
            return None, buffer

        payload = buffer[5:total_len]
        remaining = buffer[total_len:]
        return PostgresPacket(msg_type, length, payload), remaining

    @staticmethod
    def parse_startup_params(payload: bytes) -> Dict[str, str]:
        """Parses null-terminated key-value pairs from StartupMessage payload."""
        if len(payload) < 4:
            return {}
        proto_ver = struct.unpack("!I", payload[:4])[0]
        params = {}
        raw = payload[4:]
        tokens = raw.split(b'\x00')
        idx = 0
        while idx < len(tokens) - 1:
            key = tokens[idx].decode('utf-8', errors='replace')
            if not key:
                break
            val = tokens[idx + 1].decode('utf-8', errors='replace') if idx + 1 < len(tokens) else ''
            params[key] = val
            idx += 2
        return params

    @staticmethod
    def extract_query_string(packet: PostgresPacket) -> Optional[str]:
        """Extracts SQL query string from 'Q' (Query) or 'P' (Parse) packet."""
        if packet.msg_type == MSG_QUERY:
            raw = packet.payload.rstrip(b'\x00')
            return raw.decode('utf-8', errors='replace')
        elif packet.msg_type == MSG_PARSE:
            # Parse format: statement_name\0 query_string\0 num_params (int16) ...
            tokens = packet.payload.split(b'\x00', 2)
            if len(tokens) >= 2:
                return tokens[1].decode('utf-8', errors='replace')
        return None

    @staticmethod
    def encode_error_response(message: str, sqlstate: str = SQLSTATE_VERIFICATION_REJECTED,
                              detail: Optional[str] = None, hint: Optional[str] = None) -> bytes:
        """
        Synthesizes an authentic PostgreSQL 'E' (ErrorResponse) packet.
        Format:
          'S': Severity (FATAL/ERROR)
          'V': Severity (ERROR)
          'C': SQLSTATE code
          'M': Primary Message
          'D': Detail (Optional)
          'H': Hint (Optional)
          '\0': Terminator
        """
        fields = [
            b'S' + b'ERROR\x00',
            b'V' + b'ERROR\x00',
            b'C' + sqlstate.encode('ascii') + b'\x00',
            b'M' + message.encode('utf-8') + b'\x00',
        ]
        if detail:
            fields.append(b'D' + detail.encode('utf-8') + b'\x00')
        if hint:
            fields.append(b'H' + hint.encode('utf-8') + b'\x00')
        fields.append(b'\x00')

        body = b''.join(fields)
        length = len(body) + 4
        return MSG_ERROR_RESPONSE + struct.pack("!I", length) + body

    @staticmethod
    def encode_ready_for_query(tx_status: bytes = b'I') -> bytes:
        """Encodes 'Z' (ReadyForQuery) packet with transaction status indicator."""
        # 'I' = Idle, 'T' = In transaction, 'E' = In failed transaction
        length = 4 + 1
        return MSG_READY_FOR_QUERY + struct.pack("!I", length) + tx_status

    @staticmethod
    def encode_command_complete(tag: str) -> bytes:
        """Encodes 'C' (CommandComplete) packet (e.g. 'SELECT 1', 'UPDATE 1')."""
        body = tag.encode('utf-8') + b'\x00'
        length = len(body) + 4
        return MSG_COMMAND_COMPLETE + struct.pack("!I", length) + body

    @staticmethod
    def encode_auth_ok() -> bytes:
        """Encodes AuthenticationOk (Authentication type 0)."""
        body = struct.pack("!I", 0)
        return MSG_AUTHENTICATION + struct.pack("!I", len(body) + 4) + body
