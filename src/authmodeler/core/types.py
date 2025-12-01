"""
AuthModeler Core Types

Fundamental type definitions for authentication protocol modeling.
These types form the basis for both Kerberos and NTLM implementations.

SPEC: specs/alloy/core/types.als

Design Principles:
- Immutable: All types use frozen attrs for safety
- Validated: Type constraints enforced at construction
- Traceable: Each type maps to formal specification
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Optional, FrozenSet
import secrets

import attrs
from attrs import field, validators


# =============================================================================
# ENUMS
# =============================================================================


class Protocol(Enum):
    """Authentication protocol selection."""

    KERBEROS = auto()
    NTLM = auto()
    NEGOTIATE = auto()  # SPNEGO - tries Kerberos first, falls back to NTLM


class EncryptionType(Enum):
    """
    Kerberos encryption types.
    SPEC: specs/alloy/core/types.als - EncryptionType

    Values match RFC 3961 / RFC 3962 assigned numbers.
    """

    AES256_CTS_HMAC_SHA1_96 = 18
    AES128_CTS_HMAC_SHA1_96 = 17
    RC4_HMAC = 23  # Legacy, still used in NTLM
    DES3_CBC_SHA1 = 16  # Deprecated but may be encountered
    DES_CBC_MD5 = 3  # Deprecated, insecure

    @property
    def key_size(self) -> int:
        """Return key size in bytes for this encryption type."""
        sizes = {
            EncryptionType.AES256_CTS_HMAC_SHA1_96: 32,
            EncryptionType.AES128_CTS_HMAC_SHA1_96: 16,
            EncryptionType.RC4_HMAC: 16,
            EncryptionType.DES3_CBC_SHA1: 24,
            EncryptionType.DES_CBC_MD5: 8,
        }
        return sizes[self]

    @property
    def is_deprecated(self) -> bool:
        """Return True if this encryption type is deprecated/insecure."""
        return self in (EncryptionType.DES3_CBC_SHA1, EncryptionType.DES_CBC_MD5)


class TicketFlag(Enum):
    """
    Kerberos ticket flags per RFC 4120 section 5.3.
    SPEC: specs/alloy/core/types.als - TicketFlag
    """

    RESERVED = 0
    FORWARDABLE = 1
    FORWARDED = 2
    PROXIABLE = 3
    PROXY = 4
    MAY_POSTDATE = 5
    POSTDATED = 6
    INVALID = 7
    RENEWABLE = 8
    INITIAL = 9
    PRE_AUTHENT = 10
    HW_AUTHENT = 11
    TRANSITED_POLICY_CHECKED = 12
    OK_AS_DELEGATE = 13


# =============================================================================
# IDENTITY TYPES
# =============================================================================


@attrs.define(frozen=True, slots=True)
class Realm:
    """
    Kerberos realm / Windows domain.
    SPEC: specs/alloy/core/types.als - Realm

    INVARIANT: name is uppercase per convention
    """

    name: str = field(validator=validators.instance_of(str))

    def __attrs_post_init__(self) -> None:
        # Enforce uppercase for realm names (Kerberos convention)
        if self.name != self.name.upper():
            object.__setattr__(self, "name", self.name.upper())

    def __str__(self) -> str:
        return self.name


@attrs.define(frozen=True, slots=True)
class Principal:
    """
    Uniquely identifiable entity in the authentication system.
    SPEC: specs/alloy/core/types.als - Principal

    Format: name@realm (e.g., user@CORP.CONTOSO.COM)

    INVARIANT: name and realm are non-empty
    """

    name: str = field(validator=[validators.instance_of(str), validators.min_len(1)])
    realm: Realm = field(validator=validators.instance_of(Realm))

    @classmethod
    def from_string(cls, principal_str: str) -> Principal:
        """
        Parse principal from string format.

        Examples:
            "user@REALM.COM" -> Principal(name="user", realm=Realm("REALM.COM"))
            "krbtgt/REALM@REALM.COM" -> Principal(name="krbtgt/REALM", realm=Realm("REALM.COM"))
        """
        if "@" not in principal_str:
            raise ValueError(f"Invalid principal format: {principal_str}")

        # Split on last @ to handle names with @ in them
        at_pos = principal_str.rfind("@")
        name = principal_str[:at_pos]
        realm = principal_str[at_pos + 1 :]

        return cls(name=name, realm=Realm(realm))

    def __str__(self) -> str:
        return f"{self.name}@{self.realm}"


# =============================================================================
# CRYPTOGRAPHIC TYPES
# =============================================================================


@attrs.define(frozen=True, slots=True)
class Key:
    """
    Cryptographic key.
    SPEC: specs/alloy/core/types.als - Key

    INVARIANT: material length matches enctype requirements
    """

    enctype: EncryptionType = field(validator=validators.instance_of(EncryptionType))
    material: bytes = field(validator=validators.instance_of(bytes), repr=False)

    def __attrs_post_init__(self) -> None:
        expected_size = self.enctype.key_size
        if len(self.material) != expected_size:
            raise ValueError(
                f"Key material must be {expected_size} bytes for {self.enctype.name}, "
                f"got {len(self.material)}"
            )

    @classmethod
    def generate(cls, enctype: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96) -> Key:
        """Generate a random key of the specified encryption type."""
        material = secrets.token_bytes(enctype.key_size)
        return cls(enctype=enctype, material=material)


@attrs.define(frozen=True, slots=True)
class SessionKey(Key):
    """
    Session key for protecting communication.
    SPEC: specs/alloy/core/types.als - SessionKey

    Generated by KDC, shared between client and service.

    INVARIANT: valid_until > valid_from
    """

    valid_from: datetime = field(factory=lambda: datetime.now(timezone.utc))
    valid_until: datetime = field()

    @valid_until.default
    def _default_valid_until(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(hours=10)

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")

    def is_valid_at(self, time: Optional[datetime] = None) -> bool:
        """Check if session key is valid at given time (default: now)."""
        if time is None:
            time = datetime.now(timezone.utc)
        return self.valid_from <= time < self.valid_until


@attrs.define(frozen=True, slots=True)
class Nonce:
    """
    Nonce for freshness and replay prevention.
    SPEC: specs/alloy/core/types.als - Nonce

    INVARIANT: value is 4 bytes (32-bit)
    """

    value: bytes = field()

    @value.default
    def _generate_nonce(self) -> bytes:
        return secrets.token_bytes(4)

    def __attrs_post_init__(self) -> None:
        if len(self.value) != 4:
            raise ValueError("Nonce must be exactly 4 bytes")

    @property
    def as_int(self) -> int:
        """Return nonce as integer for protocol messages."""
        return int.from_bytes(self.value, byteorder="big")

    @classmethod
    def from_int(cls, value: int) -> Nonce:
        """Create nonce from integer value."""
        return cls(value=value.to_bytes(4, byteorder="big"))


@attrs.define(frozen=True, slots=True)
class Timestamp:
    """
    Timestamp for protocol messages.
    SPEC: specs/alloy/core/types.als - Timestamp

    Includes microseconds for Kerberos authenticator uniqueness.
    """

    time: datetime = field(factory=lambda: datetime.now(timezone.utc))
    usec: int = field(default=0, validator=validators.and_(
        validators.instance_of(int),
        validators.ge(0),
        validators.lt(1000000)
    ))

    def is_within_skew(
        self, reference: datetime, skew: timedelta = timedelta(minutes=5)
    ) -> bool:
        """
        Check if timestamp is within acceptable clock skew of reference.
        SPEC: specs/alloy/core/types.als - timestampValid
        """
        return abs(self.time - reference) <= skew


# =============================================================================
# RESULT TYPES
# =============================================================================


@attrs.define(frozen=True, slots=True)
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        success: Whether authentication succeeded
        principal: Authenticated principal (if success)
        session_key: Established session key (if success)
        expiration: When the authentication expires
        error_code: Error code (if failure)
        error_message: Human-readable error message (if failure)
    """

    success: bool
    principal: Optional[Principal] = None
    session_key: Optional[bytes] = field(default=None, repr=False)
    expiration: Optional[datetime] = None
    error_code: Optional[int] = None
    error_message: str = ""

    def __attrs_post_init__(self) -> None:
        if self.success:
            if self.principal is None:
                raise ValueError("Successful auth must have principal")
        else:
            if not self.error_message:
                raise ValueError("Failed auth must have error_message")

    @classmethod
    def success_result(
        cls,
        principal: Principal,
        session_key: Optional[bytes] = None,
        expiration: Optional[datetime] = None,
    ) -> AuthResult:
        """Create a successful authentication result."""
        return cls(
            success=True,
            principal=principal,
            session_key=session_key,
            expiration=expiration,
        )

    @classmethod
    def failure_result(
        cls, error_message: str, error_code: Optional[int] = None
    ) -> AuthResult:
        """Create a failed authentication result."""
        return cls(
            success=False,
            error_message=error_message,
            error_code=error_code,
        )


# =============================================================================
# TICKET TYPES (Kerberos-specific but used in core)
# =============================================================================


@attrs.define(frozen=True, slots=True)
class TicketTimes:
    """
    Ticket validity times.
    SPEC: specs/alloy/core/types.als - TicketEncPart times

    INVARIANT: auth_time <= start_time < end_time
    INVARIANT: If renewable, renew_till > end_time
    """

    auth_time: datetime
    start_time: Optional[datetime] = None
    end_time: datetime = field()
    renew_till: Optional[datetime] = None

    @end_time.default
    def _default_end_time(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(hours=10)

    def __attrs_post_init__(self) -> None:
        effective_start = self.start_time or self.auth_time
        if effective_start > self.end_time:
            raise ValueError("start_time must be before end_time")
        if self.auth_time > self.end_time:
            raise ValueError("auth_time must be before end_time")
        if self.renew_till is not None and self.renew_till <= self.end_time:
            raise ValueError("renew_till must be after end_time")

    def is_valid_at(self, time: Optional[datetime] = None) -> bool:
        """Check if ticket times are valid at given time."""
        if time is None:
            time = datetime.now(timezone.utc)
        effective_start = self.start_time or self.auth_time
        return effective_start <= time < self.end_time


@attrs.define(frozen=True, slots=True)
class TicketInfo:
    """
    Information about a Kerberos ticket (client-visible portion).

    This represents the decrypted enc-part that the client receives,
    NOT the ticket itself (which is opaque to the client).
    """

    client: Principal
    server: Principal
    session_key: SessionKey
    times: TicketTimes
    flags: FrozenSet[TicketFlag] = field(factory=frozenset)
    realm: Optional[Realm] = None

    def is_valid(self, time: Optional[datetime] = None) -> bool:
        """Check if ticket is currently valid."""
        if time is None:
            time = datetime.now(timezone.utc)
        return (
            self.times.is_valid_at(time)
            and self.session_key.is_valid_at(time)
            and TicketFlag.INVALID not in self.flags
        )

    @property
    def is_tgt(self) -> bool:
        """Check if this is a TGT (ticket for krbtgt service)."""
        return self.server.name.startswith("krbtgt/")

    @property
    def is_renewable(self) -> bool:
        """Check if ticket is renewable."""
        return TicketFlag.RENEWABLE in self.flags and self.times.renew_till is not None

    @property
    def is_forwardable(self) -> bool:
        """Check if ticket is forwardable."""
        return TicketFlag.FORWARDABLE in self.flags
