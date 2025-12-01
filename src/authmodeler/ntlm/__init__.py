"""
AuthModeler NTLM Module

Implementation of NTLMv2 authentication protocol (MS-NLMP).

Components:
- types: NTLM message types and structures
- client: High-level NTLM client with security mitigations

SPEC: specs/alloy/ntlm/protocol.als
SPEC: specs/tla/NTLM.tla

Security Mitigations Implemented:
- EPA/Channel Binding (N-GAP-1): Prevents relay attacks via TLS binding
- Challenge Freshness (N-GAP-3): Validates challenge within time window
- MIC (N-GAP-2): Message integrity code binds all messages
- SMB Signing (N-GAP-6): Message signing support

WARNING: NTLM has inherent security vulnerabilities:
- Pass-the-hash attacks (cannot be prevented by protocol)
- Relay attacks (mitigated by EPA when enabled)
- Weak by design (no mutual authentication)

Use Kerberos when possible. NTLM provided for legacy compatibility.
"""

from authmodeler.ntlm.types import (
    NTLMState,
    NTLMContext,
    NegotiateFlags,
    NegotiateMessage,
    ChallengeMessage,
    AuthenticateMessage,
    AVPair,
    AVPairType,
    MsvAvFlagsValue,
    CHALLENGE_VALIDITY_WINDOW_SECONDS,
)
from authmodeler.ntlm.client import (
    NTLMClient,
    NTLMTransportMode,
    create_ntlm_client,
    compute_channel_bindings,
    is_sspi_available,
)

__all__ = [
    # State machine
    "NTLMState",
    "NTLMContext",
    # Flags
    "NegotiateFlags",
    "MsvAvFlagsValue",
    # Messages
    "NegotiateMessage",
    "ChallengeMessage",
    "AuthenticateMessage",
    # AV Pairs
    "AVPair",
    "AVPairType",
    # Constants
    "CHALLENGE_VALIDITY_WINDOW_SECONDS",
    # Client
    "NTLMClient",
    "NTLMTransportMode",
    # Factory functions
    "create_ntlm_client",
    "compute_channel_bindings",
    "is_sspi_available",
]
