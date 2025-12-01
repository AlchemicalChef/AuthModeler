"""
AuthModeler Core Module

Provides foundational types and abstractions used across all protocol implementations.

Components:
- types: Core type definitions (Principal, Key, Ticket, etc.)
- state_machine: Base state machine with invariant checking
- crypto: Cryptographic operations wrapper
- exceptions: Custom exception types
"""

from authmodeler.core.types import (
    Protocol,
    AuthResult,
    Principal,
    Realm,
    EncryptionType,
    Key,
    SessionKey,
    Nonce,
    Timestamp,
)
from authmodeler.core.state_machine import StateMachineBase, Transition
from authmodeler.core.exceptions import (
    AuthModelerError,
    AuthenticationError,
    ProtocolError,
    CryptoError,
)

__all__ = [
    # Types
    "Protocol",
    "AuthResult",
    "Principal",
    "Realm",
    "EncryptionType",
    "Key",
    "SessionKey",
    "Nonce",
    "Timestamp",
    # State Machine
    "StateMachineBase",
    "Transition",
    # Exceptions
    "AuthModelerError",
    "AuthenticationError",
    "ProtocolError",
    "CryptoError",
]
