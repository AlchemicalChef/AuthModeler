"""
AuthModeler Kerberos Module

Implementation of Kerberos V5 authentication protocol (RFC 4120).

Components:
- types: Kerberos-specific message types
- as_exchange: Authentication Service exchange (TGT acquisition)
- tgs_exchange: Ticket Granting Service exchange (service ticket)
- client: High-level Kerberos client
- service: Service-side AP-REQ validation
- replay_cache: Authenticator replay prevention

Features (K-GAP fixes):
- Ticket Renewal (K-GAP-2): renew_tgt(), is_tgt_renewable(), tgt_needs_renewal()
- S4U Delegation (K-GAP-1): s4u2self(), s4u2proxy() for constrained delegation

SPEC: specs/alloy/kerberos/protocol.als
SPEC: specs/tla/Kerberos.tla
"""

from authmodeler.kerberos.types import (
    # Client state machine
    KerberosState,
    KerberosContext,
    # Service state machine
    ServiceState,
    ServiceAuthResult,
    DecryptedTicket,
    # Messages
    ASRequest,
    ASReply,
    TGSRequest,
    TGSReply,
    APRequest,
    APReply,
    APReplyEncPart,
    PreAuthData,
    Authenticator,
    KDCOptions,
    # Service events
    APRequestReceived,
    APRequestValidated,
    APRequestRejected,
    APReplyGenerated,
)
from authmodeler.kerberos.client import (
    KerberosClient,
    TransportMode,
    create_kerberos_client,
)
from authmodeler.kerberos.service import (
    KerberosService,
    ServiceContext,
    create_kerberos_service,
)
from authmodeler.kerberos.replay_cache import (
    AuthenticatorCache,
    AuthenticatorKey,
    KerberosErrorCode,
)

__all__ = [
    # Client state machine
    "KerberosState",
    "KerberosContext",
    # Service state machine
    "ServiceState",
    "ServiceContext",
    "ServiceAuthResult",
    "DecryptedTicket",
    # Messages
    "ASRequest",
    "ASReply",
    "TGSRequest",
    "TGSReply",
    "APRequest",
    "APReply",
    "APReplyEncPart",
    "PreAuthData",
    "Authenticator",
    "KDCOptions",
    # Service events
    "APRequestReceived",
    "APRequestValidated",
    "APRequestRejected",
    "APReplyGenerated",
    # Client
    "KerberosClient",
    "TransportMode",
    "create_kerberos_client",
    # Service
    "KerberosService",
    "create_kerberos_service",
    # Replay cache
    "AuthenticatorCache",
    "AuthenticatorKey",
    "KerberosErrorCode",
]
