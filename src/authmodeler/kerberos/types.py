"""
AuthModeler Kerberos Types

Kerberos V5 message types and protocol structures per RFC 4120.

SPEC: specs/alloy/kerberos/protocol.als - Message types
SPEC: specs/tla/Kerberos.tla - State definitions
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, auto
from typing import FrozenSet, List, Optional, Set

import attrs
from attrs import field, validators

from authmodeler.core.types import (
    EncryptionType,
    Key,
    Nonce,
    Principal,
    Realm,
    SessionKey,
    TicketFlag,
    TicketInfo,
    TicketTimes,
    Timestamp,
)


# =============================================================================
# KERBEROS STATE MACHINE
# =============================================================================


class KerberosState(Enum):
    """
    Kerberos authentication protocol states.

    SPEC: specs/tla/Kerberos.tla - ClientStates
    """

    INITIAL = auto()
    AS_REQ_SENT = auto()
    HAS_TGT = auto()
    TGS_REQ_SENT = auto()
    HAS_SERVICE_TICKET = auto()
    AP_REQ_SENT = auto()
    AUTHENTICATED = auto()
    ERROR = auto()


@attrs.define
class KerberosContext:
    """
    Kerberos session context.

    Mutable state maintained during authentication.

    SPEC: specs/tla/Kerberos.tla - client variables
    """

    # Identity
    principal: Principal
    realm: Realm

    # TGT (Ticket Granting Ticket)
    tgt: Optional[bytes] = None
    tgt_session_key: Optional[SessionKey] = None
    tgt_info: Optional[TicketInfo] = None

    # Service ticket
    service_ticket: Optional[bytes] = None
    service_session_key: Optional[SessionKey] = None
    service_info: Optional[TicketInfo] = None

    # Current operation state
    target_service: Optional[Principal] = None
    pending_nonce: Optional[Nonce] = None

    # Error state
    error_code: Optional[int] = None
    error_message: str = ""

    # Authenticator tracking (for replay prevention)
    used_authenticators: Set[bytes] = field(factory=set)

    def has_valid_tgt(self, time: Optional[datetime] = None) -> bool:
        """Check if we have a valid TGT."""
        if self.tgt is None or self.tgt_info is None:
            return False
        return self.tgt_info.is_valid(time)

    def has_valid_service_ticket(self, time: Optional[datetime] = None) -> bool:
        """Check if we have a valid service ticket."""
        if self.service_ticket is None or self.service_info is None:
            return False
        return self.service_info.is_valid(time)


# =============================================================================
# PRE-AUTHENTICATION DATA
# =============================================================================


class PreAuthType(Enum):
    """Pre-authentication data types per RFC 4120."""

    PA_TGS_REQ = 1
    PA_ENC_TIMESTAMP = 2
    PA_PW_SALT = 3
    PA_ENC_UNIX_TIME = 5
    PA_SANDIA_SECUREID = 6
    PA_SESAME = 7
    PA_OSF_DCE = 8
    PA_CYBERSAFE_SECUREID = 9
    PA_AFS3_SALT = 10
    PA_ETYPE_INFO = 11
    PA_SAM_CHALLENGE = 12
    PA_SAM_RESPONSE = 13
    PA_PK_AS_REQ_OLD = 14
    PA_PK_AS_REP_OLD = 15
    PA_PK_AS_REQ = 16
    PA_PK_AS_REP = 17
    PA_ETYPE_INFO2 = 19
    PA_USE_SPECIFIED_KVNO = 20
    PA_SAM_REDIRECT = 21
    PA_GET_FROM_TYPED_DATA = 22
    PA_PAC_REQUEST = 128
    PA_FOR_USER = 129
    PA_S4U_X509_USER = 130
    PA_PAC_OPTIONS = 167


@attrs.define(frozen=True, slots=True)
class PreAuthData:
    """
    Pre-authentication data.

    SPEC: specs/alloy/kerberos/protocol.als - PreAuthData
    """

    padata_type: PreAuthType
    padata_value: bytes


@attrs.define(frozen=True, slots=True)
class EncryptedTimestamp:
    """
    Encrypted timestamp for PA-ENC-TIMESTAMP pre-authentication.

    SPEC: specs/alloy/kerberos/protocol.als - PreAuthData.encTimestamp
    """

    timestamp: Timestamp
    encrypted_data: bytes


@attrs.define(frozen=True, slots=True)
class EtypeInfo2Entry:
    """
    Entry in PA-ETYPE-INFO2 pre-auth data.

    Provides salt and parameters for key derivation.
    """

    etype: EncryptionType
    salt: Optional[str] = None
    s2kparams: Optional[bytes] = None


# =============================================================================
# KERBEROS MESSAGES
# =============================================================================


@attrs.define(frozen=True, slots=True)
class KDCOptions:
    """
    KDC options flags for AS-REQ and TGS-REQ.
    """

    forwardable: bool = False
    forwarded: bool = False
    proxiable: bool = False
    proxy: bool = False
    allow_postdate: bool = False
    postdated: bool = False
    renewable: bool = False
    renewable_ok: bool = False
    enc_tkt_in_skey: bool = False
    renew: bool = False
    validate: bool = False
    canonicalize: bool = True  # Default for AD

    def to_flags(self) -> int:
        """Convert to bit flags."""
        flags = 0
        if self.forwardable:
            flags |= 0x40000000
        if self.forwarded:
            flags |= 0x20000000
        if self.proxiable:
            flags |= 0x10000000
        if self.proxy:
            flags |= 0x08000000
        if self.allow_postdate:
            flags |= 0x04000000
        if self.postdated:
            flags |= 0x02000000
        if self.renewable:
            flags |= 0x00800000
        if self.renewable_ok:
            flags |= 0x00000010
        if self.enc_tkt_in_skey:
            flags |= 0x00000008
        if self.renew:
            flags |= 0x00000002
        if self.validate:
            flags |= 0x00000001
        if self.canonicalize:
            flags |= 0x00010000
        return flags


@attrs.define(frozen=True, slots=True)
class ASRequest:
    """
    AS-REQ: Authentication Service Request (Client -> KDC).

    SPEC: specs/alloy/kerberos/protocol.als - ASRequest
    SPEC: specs/tla/Kerberos.tla - ASRequestMsg

    Client requests a TGT from the KDC.
    """

    # Required fields first (no defaults)
    client_principal: Principal
    server_principal: Principal  # krbtgt/REALM

    # Fields with defaults
    pvno: int = 5  # Protocol version
    msg_type: int = 10
    padata: List[PreAuthData] = field(factory=list)
    kdc_options: KDCOptions = field(factory=KDCOptions)
    from_time: Optional[datetime] = None
    till_time: datetime = field(factory=lambda: datetime.now(timezone.utc) + __import__('datetime').timedelta(hours=10))
    rtime: Optional[datetime] = None  # Renew until
    nonce: Nonce = field(factory=Nonce)
    etype: List[EncryptionType] = field(factory=lambda: [
        EncryptionType.AES256_CTS_HMAC_SHA1_96,
        EncryptionType.AES128_CTS_HMAC_SHA1_96,
        EncryptionType.RC4_HMAC,
    ])


@attrs.define(frozen=True, slots=True)
class ASReply:
    """
    AS-REP: Authentication Service Reply (KDC -> Client).

    SPEC: specs/alloy/kerberos/protocol.als - ASReply
    SPEC: specs/tla/Kerberos.tla - ASReplyMsg

    Contains the TGT and encrypted session key.
    """

    # Required fields (no defaults)
    client_principal: Principal
    ticket: bytes  # The TGT (encrypted with krbtgt key, opaque to client)
    enc_part: bytes  # Encrypted part (decryptable by client with password-derived key)
    enc_type: EncryptionType

    # Fields with defaults
    pvno: int = 5
    msg_type: int = 11
    padata: List[PreAuthData] = field(factory=list)


@attrs.define(frozen=True, slots=True)
class ASReplyEncPart:
    """
    Encrypted portion of AS-REP (decrypted by client).

    SPEC: specs/alloy/kerberos/protocol.als - ASRepEncPart
    """

    # Required fields (no defaults)
    session_key: SessionKey
    nonce: Nonce
    server_realm: Realm
    server_principal: Principal

    # Fields with defaults
    last_req: Optional[datetime] = None
    key_expiration: Optional[datetime] = None
    flags: FrozenSet[TicketFlag] = field(factory=frozenset)
    auth_time: datetime = field(factory=lambda: datetime.now(timezone.utc))
    start_time: Optional[datetime] = None
    end_time: datetime = field(factory=lambda: datetime.now(timezone.utc) + __import__('datetime').timedelta(hours=10))
    renew_till: Optional[datetime] = None


@attrs.define(frozen=True, slots=True)
class TGSRequest:
    """
    TGS-REQ: Ticket Granting Service Request (Client -> KDC).

    SPEC: specs/alloy/kerberos/protocol.als - TGSRequest
    SPEC: specs/tla/Kerberos.tla - TGSRequestMsg

    Client uses TGT to request a service ticket.
    """

    # Required fields (no defaults)
    server_principal: Principal  # Target service

    # Fields with defaults
    pvno: int = 5
    msg_type: int = 12
    padata: List[PreAuthData] = field(factory=list)
    kdc_options: KDCOptions = field(factory=KDCOptions)
    from_time: Optional[datetime] = None
    till_time: datetime = field(factory=lambda: datetime.now(timezone.utc) + __import__('datetime').timedelta(hours=8))
    rtime: Optional[datetime] = None
    nonce: Nonce = field(factory=Nonce)
    etype: List[EncryptionType] = field(factory=lambda: [
        EncryptionType.AES256_CTS_HMAC_SHA1_96,
        EncryptionType.AES128_CTS_HMAC_SHA1_96,
    ])


@attrs.define(frozen=True, slots=True)
class TGSReply:
    """
    TGS-REP: Ticket Granting Service Reply (KDC -> Client).

    SPEC: specs/alloy/kerberos/protocol.als - TGSReply
    SPEC: specs/tla/Kerberos.tla - TGSReplyMsg

    Contains the service ticket.
    """

    # Required fields (no defaults)
    client_principal: Principal
    ticket: bytes  # Service ticket (encrypted with service key)
    enc_part: bytes  # Encrypted with TGT session key
    enc_type: EncryptionType

    # Fields with defaults
    pvno: int = 5
    msg_type: int = 13
    padata: List[PreAuthData] = field(factory=list)


@attrs.define(frozen=True, slots=True)
class TGSReplyEncPart:
    """
    Encrypted portion of TGS-REP.

    SPEC: specs/alloy/kerberos/protocol.als - TGSRepEncPart
    """

    # Required fields (no defaults)
    session_key: SessionKey
    nonce: Nonce
    server_realm: Realm
    server_principal: Principal

    # Fields with defaults
    flags: FrozenSet[TicketFlag] = field(factory=frozenset)
    auth_time: datetime = field(factory=lambda: datetime.now(timezone.utc))
    start_time: Optional[datetime] = None
    end_time: datetime = field(factory=lambda: datetime.now(timezone.utc) + __import__('datetime').timedelta(hours=8))
    renew_till: Optional[datetime] = None


@attrs.define(frozen=True, slots=True)
class Authenticator:
    """
    Kerberos authenticator.

    SPEC: specs/alloy/core/types.als - Authenticator

    Proves possession of session key. Used in AP-REQ.
    """

    # Required fields (no defaults)
    client_principal: Principal
    client_realm: Realm
    ctime: Timestamp

    # Fields with defaults
    authenticator_vno: int = 5
    cusec: int = 0
    subkey: Optional[SessionKey] = None
    seq_number: Optional[int] = None
    checksum: Optional[bytes] = None


@attrs.define(frozen=True, slots=True)
class APRequest:
    """
    AP-REQ: Application Protocol Request (Client -> Service).

    SPEC: specs/alloy/kerberos/protocol.als - APRequest
    SPEC: specs/tla/Kerberos.tla - APRequestMsg

    Client authenticates to service using service ticket.
    """

    # Required fields (no defaults)
    ticket: bytes  # The service ticket
    authenticator: bytes  # Encrypted authenticator (encrypted with service session key)

    # Fields with defaults
    pvno: int = 5
    msg_type: int = 14
    use_session_key: bool = False
    mutual_required: bool = True


@attrs.define(frozen=True, slots=True)
class APReply:
    """
    AP-REP: Application Protocol Reply (Service -> Client).

    SPEC: specs/alloy/kerberos/protocol.als - APReply
    SPEC: specs/tla/Kerberos.tla - APReplyMsg

    Confirms mutual authentication.
    """

    # Required fields (no defaults)
    enc_part: bytes  # Encrypted with service session key
    enc_type: EncryptionType

    # Fields with defaults
    pvno: int = 5
    msg_type: int = 15


@attrs.define(frozen=True, slots=True)
class APReplyEncPart:
    """
    Encrypted portion of AP-REP.

    SPEC: specs/alloy/kerberos/protocol.als - APRepEncPart
    """

    ctime: Timestamp
    cusec: int
    subkey: Optional[SessionKey] = None
    seq_number: Optional[int] = None


# =============================================================================
# SERVICE-SIDE TYPES
# =============================================================================


@attrs.define(frozen=True, slots=True)
class DecryptedTicket:
    """
    Decrypted service ticket contents.

    SPEC: specs/tla/Kerberos.tla - ticketDB

    Contains the client identity and session key extracted from a
    service ticket after decryption with the service's long-term key.
    """

    # Required fields (no defaults)
    client_principal: Principal
    client_realm: Realm
    session_key: SessionKey
    auth_time: Timestamp
    end_time: Timestamp

    # Fields with defaults
    start_time: Optional[Timestamp] = None
    renew_till: Optional[Timestamp] = None
    flags: FrozenSet[TicketFlag] = field(factory=frozenset)
    transited: Optional[bytes] = None  # Transited realms encoding
    caddr: Optional[List[str]] = None  # Client addresses


@attrs.define(frozen=True, slots=True)
class ServiceAuthResult:
    """
    Result of successful AP-REQ validation.

    SPEC: specs/tla/Kerberos.tla - ServiceProcessAPRequest

    Returned when a service successfully validates an AP-REQ,
    containing the authenticated client identity and session key.
    """

    # Required fields (no defaults)
    client_principal: Principal
    client_realm: Realm
    session_key: SessionKey
    authenticator: Authenticator

    # Fields with defaults
    mutual_auth_required: bool = False
    ticket: Optional[DecryptedTicket] = None


@attrs.define(frozen=True, slots=True)
class KerberosError:
    """
    KRB-ERROR message.

    SPEC: specs/alloy/kerberos/protocol.als - KerberosError
    """

    # Required fields (no defaults)
    error_code: int

    # Fields with defaults
    pvno: int = 5
    msg_type: int = 30
    error_text: Optional[str] = None
    server_time: Timestamp = field(factory=Timestamp)
    server_usec: int = 0
    server_realm: Optional[Realm] = None
    server_principal: Optional[Principal] = None
    client_realm: Optional[Realm] = None
    client_principal: Optional[Principal] = None
    e_data: Optional[bytes] = None


# =============================================================================
# KERBEROS EVENTS (for state machine)
# =============================================================================


@attrs.define(frozen=True, slots=True)
class InitiateAuth:
    """Event: Client initiates authentication."""

    principal: Principal
    realm: Realm
    password: str = field(repr=False)  # Never log passwords


@attrs.define(frozen=True, slots=True)
class ASReplyReceived:
    """Event: Client received AS-REP."""

    tgt: bytes
    tgt_info: TicketInfo
    session_key: SessionKey
    nonce: Nonce


@attrs.define(frozen=True, slots=True)
class ASErrorReceived:
    """Event: Client received KRB-ERROR in AS exchange."""

    error_code: int
    error_message: str


@attrs.define(frozen=True, slots=True)
class RequestServiceTicket:
    """Event: Client requests a service ticket."""

    service_principal: Principal


@attrs.define(frozen=True, slots=True)
class TGSReplyReceived:
    """Event: Client received TGS-REP."""

    ticket: bytes
    ticket_info: TicketInfo
    session_key: SessionKey
    nonce: Nonce


@attrs.define(frozen=True, slots=True)
class TGSErrorReceived:
    """Event: Client received KRB-ERROR in TGS exchange."""

    error_code: int
    error_message: str


@attrs.define(frozen=True, slots=True)
class ServiceAuthenticated:
    """Event: Mutual authentication completed."""

    mutual_auth_token: bytes
    seq_number: Optional[int] = None


@attrs.define(frozen=True, slots=True)
class APErrorReceived:
    """Event: AP exchange failed."""

    error_code: int
    error_message: str


# =============================================================================
# SERVICE-SIDE KERBEROS EVENTS (for service state machine)
# =============================================================================


class ServiceState(Enum):
    """
    Kerberos service protocol states.

    SPEC: specs/tla/Kerberos.tla - serviceState
    """

    READY = auto()  # Ready to receive AP-REQ
    PROCESSING = auto()  # Processing AP-REQ
    AUTHENTICATED = auto()  # Client authenticated
    ERROR = auto()  # Validation failed


@attrs.define(frozen=True, slots=True)
class APRequestReceived:
    """Event: Service received AP-REQ from client."""

    client_principal: str
    timestamp: datetime = field(factory=lambda: datetime.now(timezone.utc))


@attrs.define(frozen=True, slots=True)
class APRequestValidated:
    """Event: AP-REQ successfully validated."""

    client_principal: str
    session_key_established: bool = True


@attrs.define(frozen=True, slots=True)
class APRequestRejected:
    """Event: AP-REQ validation failed."""

    error_code: int
    reason: str


@attrs.define(frozen=True, slots=True)
class APReplyGenerated:
    """Event: AP-REP generated for mutual authentication."""

    ctime: Timestamp
    cusec: int = 0
