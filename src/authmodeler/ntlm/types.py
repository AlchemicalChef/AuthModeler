"""
AuthModeler NTLM Types

NTLMv2 message types and protocol structures per MS-NLMP.

SPEC: specs/alloy/ntlm/protocol.als - Message types
SPEC: specs/tla/NTLM.tla - State definitions

WARNING: NTLM has known vulnerabilities. Use Kerberos when possible.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, Flag, auto
from typing import List, Optional, Set

import attrs
from attrs import field

from authmodeler.core.types import Principal, Realm


# =============================================================================
# NTLM STATE MACHINE
# =============================================================================


class NTLMState(Enum):
    """
    NTLM authentication protocol states.

    SPEC: specs/tla/NTLM.tla - NTLMState
    """

    INITIAL = auto()
    NEGOTIATE_SENT = auto()
    CHALLENGE_RECEIVED = auto()
    AUTHENTICATE_SENT = auto()
    AUTHENTICATED = auto()
    ERROR = auto()


@attrs.define
class NTLMContext:
    """
    NTLM session context.

    Mutable state maintained during authentication.

    SPEC: specs/tla/NTLM.tla - client variables
    """

    # Identity
    username: str = ""
    domain: str = ""

    # Challenge-response state
    server_challenge: Optional[bytes] = None
    client_challenge: Optional[bytes] = None
    target_info: Optional[bytes] = None

    # Session state
    session_key: Optional[bytes] = None
    session_base_key: Optional[bytes] = None  # For MIC computation
    nt_proof_str: Optional[bytes] = None

    # Flags negotiated
    negotiate_flags: int = 0

    # Server info from challenge
    server_name: str = ""
    dns_domain_name: str = ""
    dns_computer_name: str = ""

    # Challenge freshness tracking (N-GAP-3)
    # SPEC: specs/tla/NTLM.tla - ChallengeFresh, ChallengeValidityWindow
    challenge_received_time: Optional[datetime] = None
    server_timestamp: Optional[bytes] = None  # MsvAvTimestamp from target_info

    # Channel binding / EPA (N-GAP-1)
    # SPEC: specs/alloy/ntlm/properties.als - epaEnabled, MsvAvChannelBindings
    expected_channel_bindings: Optional[bytes] = None
    server_channel_bindings: Optional[bytes] = None

    # Message storage for MIC computation (N-GAP-2)
    # SPEC: specs/alloy/ntlm/properties.als - MICIntegrity
    negotiate_message: Optional[bytes] = None
    challenge_message: Optional[bytes] = None

    # Error state
    error_code: Optional[int] = None
    error_message: str = ""


# =============================================================================
# NTLM FLAGS
# =============================================================================


class NegotiateFlags(Flag):
    """
    NTLM negotiate flags per MS-NLMP 2.2.2.5.

    SPEC: specs/alloy/ntlm/protocol.als - NTLMFlags
    """

    # Basic flags
    NEGOTIATE_UNICODE = 0x00000001
    NEGOTIATE_OEM = 0x00000002
    REQUEST_TARGET = 0x00000004
    NEGOTIATE_SIGN = 0x00000010
    NEGOTIATE_SEAL = 0x00000020
    NEGOTIATE_DATAGRAM = 0x00000040
    NEGOTIATE_LM_KEY = 0x00000080
    NEGOTIATE_NTLM = 0x00000200
    NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
    NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
    NEGOTIATE_ALWAYS_SIGN = 0x00008000
    TARGET_TYPE_DOMAIN = 0x00010000
    TARGET_TYPE_SERVER = 0x00020000
    NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NEGOTIATE_IDENTIFY = 0x00100000
    REQUEST_NON_NT_SESSION_KEY = 0x00400000
    NEGOTIATE_TARGET_INFO = 0x00800000
    NEGOTIATE_VERSION = 0x02000000
    NEGOTIATE_128 = 0x20000000
    NEGOTIATE_KEY_EXCH = 0x40000000
    NEGOTIATE_56 = 0x80000000

    @classmethod
    def default_client_flags(cls) -> int:
        """Return default negotiate flags for client."""
        return (
            cls.NEGOTIATE_UNICODE.value
            | cls.NEGOTIATE_SIGN.value
            | cls.NEGOTIATE_SEAL.value
            | cls.NEGOTIATE_NTLM.value
            | cls.NEGOTIATE_ALWAYS_SIGN.value
            | cls.NEGOTIATE_EXTENDED_SESSIONSECURITY.value
            | cls.NEGOTIATE_TARGET_INFO.value
            | cls.NEGOTIATE_128.value
            | cls.NEGOTIATE_KEY_EXCH.value
            | cls.REQUEST_TARGET.value
        )

    @classmethod
    def default_server_flags(cls) -> int:
        """Return default negotiate flags for server."""
        return (
            cls.NEGOTIATE_UNICODE.value
            | cls.NEGOTIATE_NTLM.value
            | cls.NEGOTIATE_EXTENDED_SESSIONSECURITY.value
            | cls.NEGOTIATE_TARGET_INFO.value
            | cls.NEGOTIATE_128.value
            | cls.TARGET_TYPE_DOMAIN.value
            | cls.REQUEST_TARGET.value
        )


# =============================================================================
# AV PAIR STRUCTURES
# =============================================================================


class AVPairType(Enum):
    """
    AV_PAIR types per MS-NLMP 2.2.2.1.

    SPEC: specs/alloy/ntlm/protocol.als - AVPairType
    """

    MsvAvEOL = 0x0000
    MsvAvNbComputerName = 0x0001
    MsvAvNbDomainName = 0x0002
    MsvAvDnsComputerName = 0x0003
    MsvAvDnsDomainName = 0x0004
    MsvAvDnsTreeName = 0x0005
    MsvAvFlags = 0x0006
    MsvAvTimestamp = 0x0007
    MsvAvSingleHost = 0x0008
    MsvAvTargetName = 0x0009
    MsvAvChannelBindings = 0x000A


class MsvAvFlagsValue(Flag):
    """
    MsvAvFlags bit values per MS-NLMP 2.2.2.1.

    SPEC: specs/alloy/ntlm/properties.als - MsvAvFlags, MsvAvFlagMICProvided
    """

    # Indicates the client is providing message integrity in the MIC field
    MIC_PROVIDED = 0x00000002
    # Indicates the client is providing a target SPN
    UNTRUSTED_TARGET_SPN = 0x00000004


# Challenge validity window in seconds (per TLA+ spec)
# SPEC: specs/tla/NTLM.tla - ChallengeValidityWindow
CHALLENGE_VALIDITY_WINDOW_SECONDS = 5


@attrs.define(frozen=True, slots=True)
class AVPair:
    """
    AV_PAIR structure per MS-NLMP 2.2.2.1.

    SPEC: specs/alloy/ntlm/protocol.als - AVPair
    """

    av_id: AVPairType
    av_len: int
    av_value: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["AVPair", int]:
        """Parse AV_PAIR from bytes."""
        if len(data) < 4:
            raise ValueError("AV_PAIR too short")

        av_id = AVPairType(int.from_bytes(data[0:2], "little"))
        av_len = int.from_bytes(data[2:4], "little")

        if len(data) < 4 + av_len:
            raise ValueError(f"AV_PAIR value truncated: need {av_len}, have {len(data) - 4}")

        av_value = data[4 : 4 + av_len]
        return cls(av_id=av_id, av_len=av_len, av_value=av_value), 4 + av_len

    def to_bytes(self) -> bytes:
        """Serialize AV_PAIR to bytes."""
        return (
            self.av_id.value.to_bytes(2, "little")
            + len(self.av_value).to_bytes(2, "little")
            + self.av_value
        )


def parse_av_pairs(data: bytes) -> List[AVPair]:
    """Parse list of AV_PAIRs from target_info."""
    pairs = []
    offset = 0

    while offset < len(data):
        pair, consumed = AVPair.from_bytes(data[offset:])
        pairs.append(pair)
        offset += consumed

        if pair.av_id == AVPairType.MsvAvEOL:
            break

    return pairs


def build_av_pairs(pairs: List[AVPair]) -> bytes:
    """Serialize list of AV_PAIRs to bytes."""
    result = b""
    for pair in pairs:
        result += pair.to_bytes()

    # Ensure EOL terminator
    if not pairs or pairs[-1].av_id != AVPairType.MsvAvEOL:
        result += AVPair(AVPairType.MsvAvEOL, 0, b"").to_bytes()

    return result


# =============================================================================
# NTLM MESSAGES
# =============================================================================


NTLM_SIGNATURE = b"NTLMSSP\x00"


@attrs.define(frozen=True, slots=True)
class NegotiateMessage:
    """
    NTLM NEGOTIATE_MESSAGE (Type 1).

    SPEC: specs/alloy/ntlm/protocol.als - NegotiateMessage
    SPEC: specs/tla/NTLM.tla - NTLMNegotiate

    Client -> Server: Initiates NTLM authentication.
    """

    # Message type (always 1)
    message_type: int = 1

    # Flags
    negotiate_flags: int = field(factory=NegotiateFlags.default_client_flags)

    # Optional domain (OEM_DOMAIN_SUPPLIED)
    domain_name: str = ""

    # Optional workstation (OEM_WORKSTATION_SUPPLIED)
    workstation_name: str = ""

    # Version info (if NEGOTIATE_VERSION)
    version: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        flags = self.negotiate_flags

        # Calculate payload offsets
        payload_offset = 32  # Fixed header size
        if self.version:
            payload_offset += 8

        domain_bytes = self.domain_name.encode("utf-8")
        workstation_bytes = self.workstation_name.encode("utf-8")

        # Build header
        header = (
            NTLM_SIGNATURE
            + self.message_type.to_bytes(4, "little")
            + flags.to_bytes(4, "little")
        )

        # Domain fields (offset, length)
        domain_len = len(domain_bytes)
        header += domain_len.to_bytes(2, "little")  # DomainNameLen
        header += domain_len.to_bytes(2, "little")  # DomainNameMaxLen
        header += payload_offset.to_bytes(4, "little")  # DomainNameBufferOffset

        # Workstation fields
        ws_offset = payload_offset + domain_len
        ws_len = len(workstation_bytes)
        header += ws_len.to_bytes(2, "little")  # WorkstationLen
        header += ws_len.to_bytes(2, "little")  # WorkstationMaxLen
        header += ws_offset.to_bytes(4, "little")  # WorkstationBufferOffset

        # Version (optional)
        if self.version:
            header += self.version

        # Payload
        payload = domain_bytes + workstation_bytes

        return header + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "NegotiateMessage":
        """Parse from wire format."""
        if len(data) < 32:
            raise ValueError("NEGOTIATE_MESSAGE too short")

        if data[:8] != NTLM_SIGNATURE:
            raise ValueError("Invalid NTLM signature")

        msg_type = int.from_bytes(data[8:12], "little")
        if msg_type != 1:
            raise ValueError(f"Expected type 1, got {msg_type}")

        flags = int.from_bytes(data[12:16], "little")

        # Parse domain
        domain_len = int.from_bytes(data[16:18], "little")
        domain_offset = int.from_bytes(data[20:24], "little")
        domain = data[domain_offset : domain_offset + domain_len].decode("utf-8")

        # Parse workstation
        ws_len = int.from_bytes(data[24:26], "little")
        ws_offset = int.from_bytes(data[28:32], "little")
        workstation = data[ws_offset : ws_offset + ws_len].decode("utf-8")

        return cls(
            negotiate_flags=flags,
            domain_name=domain,
            workstation_name=workstation,
        )


@attrs.define(frozen=True, slots=True)
class ChallengeMessage:
    """
    NTLM CHALLENGE_MESSAGE (Type 2).

    SPEC: specs/alloy/ntlm/protocol.als - ChallengeMessage
    SPEC: specs/tla/NTLM.tla - NTLMChallenge

    Server -> Client: Contains server challenge and target info.
    """

    # Message type (always 2)
    message_type: int = 2

    # Target name (domain or server)
    target_name: str = ""

    # Flags
    negotiate_flags: int = 0

    # Server challenge (8 bytes)
    server_challenge: bytes = field(factory=lambda: b"\x00" * 8)

    # Target info (AV_PAIRs)
    target_info: bytes = b""

    # Version info
    version: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        # Calculate offsets
        header_size = 56  # Fixed header + reserved

        target_name_bytes = self.target_name.encode("utf-16-le")
        target_info_offset = header_size + len(target_name_bytes)

        # Build message
        msg = NTLM_SIGNATURE
        msg += self.message_type.to_bytes(4, "little")

        # Target name fields
        msg += len(target_name_bytes).to_bytes(2, "little")  # Len
        msg += len(target_name_bytes).to_bytes(2, "little")  # MaxLen
        msg += header_size.to_bytes(4, "little")  # Offset

        # Flags
        msg += self.negotiate_flags.to_bytes(4, "little")

        # Server challenge
        msg += self.server_challenge[:8].ljust(8, b"\x00")

        # Reserved
        msg += b"\x00" * 8

        # Target info fields
        msg += len(self.target_info).to_bytes(2, "little")  # Len
        msg += len(self.target_info).to_bytes(2, "little")  # MaxLen
        msg += target_info_offset.to_bytes(4, "little")  # Offset

        # Version (optional, 8 bytes)
        if self.version:
            msg += self.version[:8].ljust(8, b"\x00")
        else:
            msg += b"\x00" * 8

        # Payload
        msg += target_name_bytes
        msg += self.target_info

        return msg

    @classmethod
    def from_bytes(cls, data: bytes) -> "ChallengeMessage":
        """Parse from wire format."""
        if len(data) < 32:
            raise ValueError("CHALLENGE_MESSAGE too short")

        if data[:8] != NTLM_SIGNATURE:
            raise ValueError("Invalid NTLM signature")

        msg_type = int.from_bytes(data[8:12], "little")
        if msg_type != 2:
            raise ValueError(f"Expected type 2, got {msg_type}")

        # Parse target name
        target_len = int.from_bytes(data[12:14], "little")
        target_offset = int.from_bytes(data[16:20], "little")
        target_name = data[target_offset : target_offset + target_len].decode("utf-16-le")

        # Flags
        flags = int.from_bytes(data[20:24], "little")

        # Server challenge
        server_challenge = data[24:32]

        # Target info
        if len(data) >= 48:
            target_info_len = int.from_bytes(data[40:42], "little")
            target_info_offset = int.from_bytes(data[44:48], "little")
            target_info = data[target_info_offset : target_info_offset + target_info_len]
        else:
            target_info = b""

        return cls(
            target_name=target_name,
            negotiate_flags=flags,
            server_challenge=server_challenge,
            target_info=target_info,
        )


@attrs.define(frozen=True, slots=True)
class AuthenticateMessage:
    """
    NTLM AUTHENTICATE_MESSAGE (Type 3).

    SPEC: specs/alloy/ntlm/protocol.als - AuthenticateMessage
    SPEC: specs/tla/NTLM.tla - NTLMAuthenticate

    Client -> Server: Contains authentication response.
    """

    # Message type (always 3)
    message_type: int = 3

    # LM response (deprecated, usually empty or NTLMv2 hash)
    lm_response: bytes = b""

    # NT response (NTLMv2 response)
    nt_response: bytes = b""

    # Domain name
    domain_name: str = ""

    # User name
    user_name: str = ""

    # Workstation name
    workstation_name: str = ""

    # Encrypted random session key
    encrypted_session_key: bytes = b""

    # Flags
    negotiate_flags: int = 0

    # MIC (Message Integrity Code)
    mic: bytes = field(factory=lambda: b"\x00" * 16)

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        # Encode strings as UTF-16LE
        domain_bytes = self.domain_name.encode("utf-16-le")
        user_bytes = self.user_name.encode("utf-16-le")
        workstation_bytes = self.workstation_name.encode("utf-16-le")

        # Calculate offsets (header is 88 bytes with MIC)
        header_size = 88
        offset = header_size

        lm_offset = offset
        offset += len(self.lm_response)

        nt_offset = offset
        offset += len(self.nt_response)

        domain_offset = offset
        offset += len(domain_bytes)

        user_offset = offset
        offset += len(user_bytes)

        ws_offset = offset
        offset += len(workstation_bytes)

        session_key_offset = offset

        # Build message
        msg = NTLM_SIGNATURE
        msg += self.message_type.to_bytes(4, "little")

        # LM response fields
        msg += len(self.lm_response).to_bytes(2, "little")
        msg += len(self.lm_response).to_bytes(2, "little")
        msg += lm_offset.to_bytes(4, "little")

        # NT response fields
        msg += len(self.nt_response).to_bytes(2, "little")
        msg += len(self.nt_response).to_bytes(2, "little")
        msg += nt_offset.to_bytes(4, "little")

        # Domain fields
        msg += len(domain_bytes).to_bytes(2, "little")
        msg += len(domain_bytes).to_bytes(2, "little")
        msg += domain_offset.to_bytes(4, "little")

        # User fields
        msg += len(user_bytes).to_bytes(2, "little")
        msg += len(user_bytes).to_bytes(2, "little")
        msg += user_offset.to_bytes(4, "little")

        # Workstation fields
        msg += len(workstation_bytes).to_bytes(2, "little")
        msg += len(workstation_bytes).to_bytes(2, "little")
        msg += ws_offset.to_bytes(4, "little")

        # Encrypted session key fields
        msg += len(self.encrypted_session_key).to_bytes(2, "little")
        msg += len(self.encrypted_session_key).to_bytes(2, "little")
        msg += session_key_offset.to_bytes(4, "little")

        # Flags
        msg += self.negotiate_flags.to_bytes(4, "little")

        # Version (8 bytes)
        msg += b"\x00" * 8

        # MIC (16 bytes)
        msg += self.mic[:16].ljust(16, b"\x00")

        # Payload
        msg += self.lm_response
        msg += self.nt_response
        msg += domain_bytes
        msg += user_bytes
        msg += workstation_bytes
        msg += self.encrypted_session_key

        return msg

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuthenticateMessage":
        """Parse from wire format."""
        if len(data) < 64:
            raise ValueError("AUTHENTICATE_MESSAGE too short")

        if data[:8] != NTLM_SIGNATURE:
            raise ValueError("Invalid NTLM signature")

        msg_type = int.from_bytes(data[8:12], "little")
        if msg_type != 3:
            raise ValueError(f"Expected type 3, got {msg_type}")

        # Parse fields
        lm_len = int.from_bytes(data[12:14], "little")
        lm_offset = int.from_bytes(data[16:20], "little")

        nt_len = int.from_bytes(data[20:22], "little")
        nt_offset = int.from_bytes(data[24:28], "little")

        domain_len = int.from_bytes(data[28:30], "little")
        domain_offset = int.from_bytes(data[32:36], "little")

        user_len = int.from_bytes(data[36:38], "little")
        user_offset = int.from_bytes(data[40:44], "little")

        ws_len = int.from_bytes(data[44:46], "little")
        ws_offset = int.from_bytes(data[48:52], "little")

        session_key_len = int.from_bytes(data[52:54], "little")
        session_key_offset = int.from_bytes(data[56:60], "little")

        flags = int.from_bytes(data[60:64], "little")

        return cls(
            lm_response=data[lm_offset : lm_offset + lm_len],
            nt_response=data[nt_offset : nt_offset + nt_len],
            domain_name=data[domain_offset : domain_offset + domain_len].decode("utf-16-le"),
            user_name=data[user_offset : user_offset + user_len].decode("utf-16-le"),
            workstation_name=data[ws_offset : ws_offset + ws_len].decode("utf-16-le"),
            encrypted_session_key=data[session_key_offset : session_key_offset + session_key_len],
            negotiate_flags=flags,
        )


# =============================================================================
# NTLM EVENTS (for state machine)
# =============================================================================


@attrs.define(frozen=True, slots=True)
class InitiateNTLM:
    """Event: Client initiates NTLM authentication."""

    username: str
    domain: str
    password: str = field(repr=False)


@attrs.define(frozen=True, slots=True)
class ChallengeReceived:
    """Event: Client received CHALLENGE_MESSAGE."""

    server_challenge: bytes
    target_info: bytes
    negotiate_flags: int
    target_name: str


@attrs.define(frozen=True, slots=True)
class AuthenticateComplete:
    """Event: Server accepted AUTHENTICATE_MESSAGE."""

    session_key: bytes


@attrs.define(frozen=True, slots=True)
class NTLMErrorReceived:
    """Event: Authentication failed."""

    error_code: int
    error_message: str
