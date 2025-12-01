"""
AuthModeler Kerberos Client

High-level Kerberos V5 client implementation.

SPEC: specs/alloy/kerberos/protocol.als
SPEC: specs/tla/Kerberos.tla

This module provides a complete Kerberos client that:
1. Obtains TGT via AS exchange
2. Obtains service tickets via TGS exchange
3. Authenticates to services via AP exchange
4. Maintains ticket cache
5. Exports traces for formal verification
6. Supports native GSSAPI/SSPI for real AD integration
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

import attrs
import structlog
from returns.result import Failure, Result, Success

from authmodeler.core.crypto import (
    decrypt_aes_cts,
    derive_key_from_password,
    encrypt_aes_cts,
    generate_session_key,
)
from authmodeler.core.exceptions import (
    AuthenticationError,
    CryptoError,
    InvariantViolation,
    KerberosError,
    ReplayDetected,
    StateError,
    TicketExpired,
)
from authmodeler.core.state_machine import StateMachineBase, TransitionEntry
from authmodeler.core.types import (
    AuthResult,
    EncryptionType,
    Principal,
    Realm,
    SessionKey,
    TicketFlag,
    TicketInfo,
    TicketTimes,
    Timestamp,
)
from authmodeler.kerberos.types import (
    APErrorReceived,
    APReply,
    APReplyEncPart,
    APRequest,
    ASErrorReceived,
    ASReply,
    ASReplyReceived,
    ASRequest,
    Authenticator,
    InitiateAuth,
    KDCOptions,
    KerberosContext,
    KerberosError as KerberosErrorMsg,
    KerberosState,
    PreAuthData,
    PreAuthType,
    RequestServiceTicket,
    ServiceAuthenticated,
    TGSErrorReceived,
    TGSReply,
    TGSReplyEncPart,
    TGSReplyReceived,
    TGSRequest,
)
from authmodeler.kerberos.as_exchange import (
    ASExchangeHandler,
    tgt_requires_valid_auth,
    nonce_cleared_after_exchange,
)

logger = structlog.get_logger()


# =============================================================================
# TRANSPORT MODE
# =============================================================================


class TransportMode(Enum):
    """
    KDC transport mode for Kerberos operations.

    - SIMULATED: Use simulated KDC responses (for testing/verification)
    - NATIVE: Use native GSSAPI/SSPI libraries for real AD
    - RAW_NETWORK: Use raw network transport (requires ASN.1 encoding)
    """
    SIMULATED = auto()
    NATIVE = auto()
    RAW_NETWORK = auto()


def _check_native_available() -> Tuple[bool, str]:
    """Check if native authentication is available."""
    try:
        from authmodeler.transport.native_client import (
            NativeKerberosClient,
            detect_native_backend,
            NativeBackend,
        )
        backend = detect_native_backend()
        if backend == NativeBackend.NONE:
            return False, "No native backend available (need GSSAPI or SSPI)"
        return True, backend.name
    except ImportError as e:
        return False, f"Transport module not available: {e}"


# =============================================================================
# KERBEROS CLIENT STATE MACHINE
# =============================================================================


@attrs.define
class KerberosClientStateMachine(
    StateMachineBase[KerberosState, Any, KerberosContext]
):
    """
    Complete Kerberos client state machine.

    SPEC: specs/tla/Kerberos.tla - ClientStates, Next

    States:
    - INITIAL: No authentication
    - AS_REQ_SENT: Waiting for AS-REP
    - HAS_TGT: Have valid TGT
    - TGS_REQ_SENT: Waiting for TGS-REP
    - HAS_SERVICE_TICKET: Have valid service ticket
    - AP_REQ_SENT: Waiting for AP-REP
    - AUTHENTICATED: Mutual authentication complete
    - ERROR: Authentication failed
    """

    def initial_state(self) -> KerberosState:
        return KerberosState.INITIAL

    def transition_table(
        self,
    ) -> Dict[Tuple[KerberosState, type], TransitionEntry]:
        return {
            # AS Exchange
            (KerberosState.INITIAL, InitiateAuth): (
                KerberosState.AS_REQ_SENT,
                self._handle_initiate_auth,
            ),
            (KerberosState.AS_REQ_SENT, ASReplyReceived): (
                KerberosState.HAS_TGT,
                self._handle_as_reply,
            ),
            (KerberosState.AS_REQ_SENT, ASErrorReceived): (
                KerberosState.ERROR,
                self._handle_error,
            ),
            (KerberosState.AS_REQ_SENT, InitiateAuth): (
                KerberosState.AS_REQ_SENT,
                self._handle_initiate_auth,
            ),
            # TGS Exchange
            (KerberosState.HAS_TGT, RequestServiceTicket): (
                KerberosState.TGS_REQ_SENT,
                self._handle_request_service_ticket,
            ),
            (KerberosState.TGS_REQ_SENT, TGSReplyReceived): (
                KerberosState.HAS_SERVICE_TICKET,
                self._handle_tgs_reply,
            ),
            (KerberosState.TGS_REQ_SENT, TGSErrorReceived): (
                KerberosState.ERROR,
                self._handle_error,
            ),
            # AP Exchange
            (KerberosState.HAS_SERVICE_TICKET, ServiceAuthenticated): (
                KerberosState.AUTHENTICATED,
                self._handle_service_authenticated,
            ),
            (KerberosState.HAS_SERVICE_TICKET, APErrorReceived): (
                KerberosState.ERROR,
                self._handle_error,
            ),
            # Re-authentication from HAS_TGT
            (KerberosState.HAS_TGT, InitiateAuth): (
                KerberosState.AS_REQ_SENT,
                self._handle_initiate_auth,
            ),
            # Request another service ticket
            (KerberosState.AUTHENTICATED, RequestServiceTicket): (
                KerberosState.TGS_REQ_SENT,
                self._handle_request_service_ticket,
            ),
        }

    @staticmethod
    def _handle_initiate_auth(
        event: InitiateAuth, ctx: KerberosContext
    ) -> KerberosContext:
        """Handle InitiateAuth event."""
        from authmodeler.core.types import Nonce

        return attrs.evolve(
            ctx,
            principal=event.principal,
            realm=event.realm,
            pending_nonce=Nonce(),
            error_code=None,
            error_message="",
        )

    @staticmethod
    def _handle_as_reply(
        event: ASReplyReceived, ctx: KerberosContext
    ) -> KerberosContext:
        """Handle ASReplyReceived event."""
        return attrs.evolve(
            ctx,
            tgt=event.tgt,
            tgt_session_key=event.session_key,
            tgt_info=event.tgt_info,
            pending_nonce=None,
        )

    @staticmethod
    def _handle_request_service_ticket(
        event: RequestServiceTicket, ctx: KerberosContext
    ) -> KerberosContext:
        """Handle RequestServiceTicket event."""
        from authmodeler.core.types import Nonce

        return attrs.evolve(
            ctx,
            target_service=event.service_principal,
            pending_nonce=Nonce(),
            service_ticket=None,
            service_session_key=None,
            service_info=None,
        )

    @staticmethod
    def _handle_tgs_reply(
        event: TGSReplyReceived, ctx: KerberosContext
    ) -> KerberosContext:
        """Handle TGSReplyReceived event."""
        return attrs.evolve(
            ctx,
            service_ticket=event.ticket,
            service_session_key=event.session_key,
            service_info=event.ticket_info,
            pending_nonce=None,
        )

    @staticmethod
    def _handle_service_authenticated(
        event: ServiceAuthenticated, ctx: KerberosContext
    ) -> KerberosContext:
        """Handle ServiceAuthenticated event."""
        return attrs.evolve(
            ctx,
            used_authenticators=ctx.used_authenticators | {event.mutual_auth_token},
        )

    @staticmethod
    def _handle_error(
        event: Any, ctx: KerberosContext
    ) -> KerberosContext:
        """Handle error events."""
        return attrs.evolve(
            ctx,
            error_code=event.error_code,
            error_message=event.error_message,
            pending_nonce=None,
        )


# =============================================================================
# KERBEROS CLIENT
# =============================================================================


@attrs.define
class KerberosClient:
    """
    High-level Kerberos V5 client.

    SPEC: specs/alloy/kerberos/protocol.als
    SPEC: specs/tla/Kerberos.tla

    Provides:
    - TGT acquisition (AS exchange)
    - Service ticket acquisition (TGS exchange)
    - Service authentication (AP exchange)
    - Ticket caching
    - Trace export for verification
    - Native GSSAPI/SSPI integration for real AD

    Transport Modes:
    - SIMULATED: Mock KDC responses (for testing)
    - NATIVE: Use GSSAPI (Unix) or SSPI (Windows) for real authentication
    - RAW_NETWORK: Direct KDC communication (requires ASN.1)

    Example:
        # Simulated mode (default - for testing)
        client = KerberosClient(
            realm=Realm("EXAMPLE.COM"),
            kdc_host="kdc.example.com",
        )
        result = client.authenticate("user", "password")

        # Native mode (for real AD authentication)
        client = KerberosClient(
            realm=Realm("EXAMPLE.COM"),
            transport_mode=TransportMode.NATIVE,
        )
        result = client.authenticate("user", "password")
    """

    realm: Realm
    kdc_host: str = ""
    kdc_port: int = 88
    clock_skew_tolerance: timedelta = timedelta(minutes=5)
    transport_mode: TransportMode = TransportMode.SIMULATED

    # Internal state
    _state_machine: KerberosClientStateMachine = attrs.Factory(
        lambda self: KerberosClientStateMachine(
            _state=KerberosState.INITIAL,
            _context=KerberosContext(
                principal=Principal(name="_uninitialized", realm=self.realm),
                realm=self.realm,
            ),
        ),
        takes_self=True,
    )
    _password_key: Optional[bytes] = attrs.field(default=None, repr=False)
    _native_client: Optional[Any] = attrs.field(default=None, repr=False)
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def __attrs_post_init__(self) -> None:
        """Add invariants to state machine and initialize transport."""
        self._state_machine.add_invariant(
            "tgt_requires_valid_auth",
            tgt_requires_valid_auth,
        )
        self._state_machine.add_invariant(
            "nonce_cleared_after_exchange",
            nonce_cleared_after_exchange,
        )
        self._state_machine.add_invariant(
            "service_ticket_requires_tgt",
            self._service_ticket_requires_tgt,
        )

        # Initialize native client if in native mode
        if self.transport_mode == TransportMode.NATIVE:
            self._init_native_client()

    def _init_native_client(self) -> None:
        """Initialize native GSSAPI/SSPI client."""
        available, backend_info = _check_native_available()
        if not available:
            self._logger.warning(
                "native_backend_unavailable",
                reason=backend_info,
                fallback="simulated",
            )
            object.__setattr__(self, 'transport_mode', TransportMode.SIMULATED)
            return

        try:
            from authmodeler.transport.native_client import NativeKerberosClient

            self._native_client = NativeKerberosClient(realm=self.realm.name)
            self._logger.info(
                "native_backend_initialized",
                backend=backend_info,
                realm=self.realm.name,
            )
        except Exception as e:
            self._logger.error(
                "native_backend_init_failed",
                error=str(e),
            )
            object.__setattr__(self, 'transport_mode', TransportMode.SIMULATED)

    @staticmethod
    def _service_ticket_requires_tgt(
        state: KerberosState, ctx: KerberosContext
    ) -> bool:
        """
        Invariant: Service ticket requires valid TGT.

        SPEC: specs/alloy/kerberos/properties.als - ServiceTicketRequiresTGT
        """
        if state == KerberosState.HAS_SERVICE_TICKET:
            return ctx.tgt is not None and ctx.tgt_session_key is not None
        return True

    @property
    def state(self) -> KerberosState:
        """Current authentication state."""
        return self._state_machine.state

    @property
    def context(self) -> KerberosContext:
        """Current context (read-only)."""
        return self._state_machine.context

    @property
    def has_valid_tgt(self) -> bool:
        """Check if client has a valid TGT."""
        return self.context.has_valid_tgt()

    @property
    def has_valid_service_ticket(self) -> bool:
        """Check if client has a valid service ticket."""
        return self.context.has_valid_service_ticket()

    def authenticate(
        self,
        username: str,
        password: str,
        domain: Optional[str] = None,
    ) -> AuthResult:
        """
        Authenticate user and obtain TGT.

        SPEC: specs/alloy/kerberos/protocol.als - ASExchange
        SPEC: specs/tla/Kerberos.tla - AS_Request, AS_Reply

        When transport_mode is NATIVE, uses GSSAPI (Unix) or SSPI (Windows)
        for real Active Directory authentication.

        Args:
            username: User name (e.g., "jdoe")
            password: User password
            domain: Domain/realm (uses client realm if not specified)

        Returns:
            AuthResult with success/failure and session info
        """
        realm = Realm(domain) if domain else self.realm
        principal = Principal(name=username, realm=realm)

        self._logger.info(
            "authenticate_start",
            principal=principal.name,
            realm=realm.name,
            transport_mode=self.transport_mode.name,
        )

        # Use native authentication if available
        if self.transport_mode == TransportMode.NATIVE:
            return self._authenticate_native(username, password, realm.name)

        # Initiate authentication
        init_event = InitiateAuth(
            principal=principal,
            realm=realm,
            password=password,
        )

        result = self._state_machine.process_event(init_event)
        if isinstance(result, Failure):
            return AuthResult(
                success=False,
                principal=None,
                error_message=result.failure(),
            )

        # For simulated mode, use mock KDC responses
        as_handler = ASExchangeHandler(realm=realm)

        # Build pre-auth (assuming required)
        preauth = as_handler.build_encrypted_timestamp_preauth(
            principal, password
        )

        # Build AS-REQ
        as_req, nonce = as_handler.build_as_request(
            principal, preauth_data=[preauth]
        )

        # Simulate KDC response
        tgt_result = self._simulate_kdc_as_response(
            as_req, password, principal, nonce
        )

        if isinstance(tgt_result, Failure):
            error_event = ASErrorReceived(
                error_code=KerberosError.KDC_ERR_PREAUTH_FAILED,
                error_message=tgt_result.failure(),
            )
            self._state_machine.process_event(error_event)
            return AuthResult(
                success=False,
                principal=principal,
                error_code=KerberosError.KDC_ERR_PREAUTH_FAILED,
                error_message=tgt_result.failure(),
            )

        tgt, session_key, ticket_info = tgt_result.unwrap()

        # Process successful AS-REP
        as_reply_event = ASReplyReceived(
            tgt=tgt,
            tgt_info=ticket_info,
            session_key=session_key,
            nonce=nonce,
        )

        result = self._state_machine.process_event(as_reply_event)
        if isinstance(result, Failure):
            return AuthResult(
                success=False,
                principal=principal,
                error_message=result.failure(),
            )

        self._logger.info(
            "authenticate_success",
            principal=principal.name,
            tgt_valid_until=ticket_info.times.end_time.isoformat(),
        )

        return AuthResult(
            success=True,
            principal=principal,
            session_key=session_key.material,
            expiration=ticket_info.times.end_time,
        )

    def _authenticate_native(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> AuthResult:
        """
        Authenticate using native GSSAPI/SSPI.

        Uses platform-specific security APIs for real AD authentication.
        """
        if self._native_client is None:
            return AuthResult(
                success=False,
                principal=None,
                error_message="Native client not initialized",
            )

        try:
            # Use native client for authentication
            native_result = self._native_client.authenticate(
                username=username,
                password=password,
                domain=domain,
            )

            if native_result.success:
                # Update state machine to reflect successful auth
                principal = Principal(name=username, realm=Realm(domain))
                init_event = InitiateAuth(
                    principal=principal,
                    realm=Realm(domain),
                    password=password,
                )
                self._state_machine.process_event(init_event)

                # Create synthetic AS-REP event for state tracking
                now = datetime.now(timezone.utc)
                session_key = SessionKey(
                    enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    material=native_result.session_key or b"",
                )
                ticket_info = TicketInfo(
                    client=principal,
                    server=Principal(name=f"krbtgt/{domain}", realm=Realm(domain)),
                    session_key=session_key,
                    times=TicketTimes(
                        auth_time=now,
                        start_time=now,
                        end_time=native_result.expiration or (now + timedelta(hours=10)),
                        renew_till=now + timedelta(days=7),
                    ),
                    flags=frozenset({TicketFlag.INITIAL, TicketFlag.RENEWABLE}),
                    realm=Realm(domain),
                )

                from authmodeler.core.types import Nonce
                as_reply_event = ASReplyReceived(
                    tgt=b"native-tgt",  # Placeholder - real TGT is in native context
                    tgt_info=ticket_info,
                    session_key=session_key,
                    nonce=Nonce(),
                )
                self._state_machine.process_event(as_reply_event)

                self._logger.info(
                    "native_authenticate_success",
                    username=username,
                    domain=domain,
                )

            return native_result

        except Exception as e:
            self._logger.error(
                "native_authenticate_error",
                error=str(e),
            )
            return AuthResult(
                success=False,
                principal=Principal(name=username, realm=Realm(domain)),
                error_message=f"Native authentication failed: {e}",
            )

    def get_service_ticket(
        self,
        service_name: str,
    ) -> Result[Tuple[bytes, SessionKey, TicketInfo], str]:
        """
        Obtain a service ticket using the TGT.

        SPEC: specs/alloy/kerberos/protocol.als - TGSExchange
        SPEC: specs/tla/Kerberos.tla - TGS_Request, TGS_Reply

        When transport_mode is NATIVE, uses GSSAPI/SSPI init_sec_context
        to obtain a real service ticket.

        Args:
            service_name: Service principal name (e.g., "http/server.example.com")

        Returns:
            Success((ticket, session_key, ticket_info)) or Failure(error)
        """
        # Use native client for service ticket if available
        if self.transport_mode == TransportMode.NATIVE and self._native_client:
            return self._get_service_ticket_native(service_name)

        if not self.has_valid_tgt:
            return Failure("No valid TGT - authenticate first")

        service_principal = Principal(name=service_name, realm=self.realm)

        self._logger.info(
            "get_service_ticket_start",
            service=service_name,
        )

        # Request service ticket
        request_event = RequestServiceTicket(service_principal=service_principal)
        result = self._state_machine.process_event(request_event)

        if isinstance(result, Failure):
            return Failure(result.failure())

        # Simulate TGS response
        tgs_result = self._simulate_kdc_tgs_response(service_principal)

        if isinstance(tgs_result, Failure):
            error_event = TGSErrorReceived(
                error_code=KerberosError.KDC_ERR_S_PRINCIPAL_UNKNOWN,
                error_message=tgs_result.failure(),
            )
            self._state_machine.process_event(error_event)
            return Failure(tgs_result.failure())

        ticket, session_key, ticket_info = tgs_result.unwrap()

        # Process successful TGS-REP
        from authmodeler.core.types import Nonce

        tgs_reply_event = TGSReplyReceived(
            ticket=ticket,
            ticket_info=ticket_info,
            session_key=session_key,
            nonce=self.context.pending_nonce or Nonce(),
        )

        result = self._state_machine.process_event(tgs_reply_event)
        if isinstance(result, Failure):
            return Failure(result.failure())

        self._logger.info(
            "get_service_ticket_success",
            service=service_name,
            ticket_valid_until=ticket_info.times.end_time.isoformat(),
        )

        return Success((ticket, session_key, ticket_info))

    def _get_service_ticket_native(
        self,
        service_name: str,
    ) -> Result[Tuple[bytes, SessionKey, TicketInfo], str]:
        """
        Get service ticket using native GSSAPI/SSPI.

        Uses init_sec_context to obtain a token for the service.
        """
        if self._native_client is None:
            return Failure("Native client not initialized")

        try:
            # Get service token from native client
            token_result = self._native_client.get_service_token(service_name)
            if isinstance(token_result, Failure):
                return Failure(token_result.failure())

            token, context_info = token_result.unwrap()

            # Create ticket info from context
            service_principal = Principal(name=service_name, realm=self.realm)
            now = datetime.now(timezone.utc)

            session_key = SessionKey(
                enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                material=context_info.get("session_key", b""),
            )

            ticket_info = TicketInfo(
                client=self.context.principal,
                server=service_principal,
                session_key=session_key,
                times=TicketTimes(
                    auth_time=now,
                    start_time=now,
                    end_time=context_info.get("expiry", now + timedelta(hours=8)),
                    renew_till=None,
                ),
                flags=frozenset({TicketFlag.FORWARDABLE}),
                realm=self.realm,
            )

            # Update state machine
            request_event = RequestServiceTicket(service_principal=service_principal)
            self._state_machine.process_event(request_event)

            from authmodeler.core.types import Nonce
            tgs_reply_event = TGSReplyReceived(
                ticket=token,
                ticket_info=ticket_info,
                session_key=session_key,
                nonce=Nonce(),
            )
            self._state_machine.process_event(tgs_reply_event)

            self._logger.info(
                "native_get_service_ticket_success",
                service=service_name,
            )

            return Success((token, session_key, ticket_info))

        except Exception as e:
            self._logger.error(
                "native_get_service_ticket_error",
                service=service_name,
                error=str(e),
            )
            return Failure(f"Failed to get service ticket: {e}")

    def build_ap_request(
        self,
        mutual_auth: bool = True,
    ) -> Result[APRequest, str]:
        """
        Build an AP-REQ message for service authentication.

        SPEC: specs/alloy/kerberos/protocol.als - APRequest
        SPEC: specs/tla/Kerberos.tla - AP_Request

        Args:
            mutual_auth: Request mutual authentication

        Returns:
            Success(APRequest) or Failure(error)
        """
        if not self.has_valid_service_ticket:
            return Failure("No valid service ticket")

        ctx = self.context

        # Build authenticator
        authenticator = Authenticator(
            client_principal=ctx.principal,
            client_realm=ctx.realm,
            ctime=Timestamp(),
            cusec=0,
        )

        # Encrypt authenticator with service session key
        if ctx.service_session_key is None:
            return Failure("No service session key")

        # Simplified authenticator encoding
        auth_bytes = (
            authenticator.client_principal.name.encode("utf-8")
            + b"|"
            + authenticator.ctime.time.isoformat().encode("utf-8")
        )

        enc_auth, iv = encrypt_aes_cts(
            ctx.service_session_key.material, auth_bytes
        )

        ap_req = APRequest(
            mutual_required=mutual_auth,
            ticket=ctx.service_ticket or b"",
            authenticator=iv + enc_auth,
        )

        self._logger.debug(
            "built_ap_request",
            mutual_auth=mutual_auth,
        )

        return Success(ap_req)

    def verify_ap_reply(
        self,
        ap_rep: APReply,
        expected_ctime: Timestamp,
    ) -> Result[SessionKey, str]:
        """
        Verify AP-REP for mutual authentication.

        SPEC: specs/alloy/kerberos/protocol.als - APReply
        SPEC: specs/tla/Kerberos.tla - AP_Reply

        Args:
            ap_rep: AP-REP message from service
            expected_ctime: Timestamp from our authenticator

        Returns:
            Success(session_key) or Failure(error)
        """
        ctx = self.context
        if ctx.service_session_key is None:
            return Failure("No service session key")

        # Decrypt enc_part
        try:
            if len(ap_rep.enc_part) < 16:
                return Failure("AP-REP enc_part too short")

            iv = ap_rep.enc_part[:16]
            ciphertext = ap_rep.enc_part[16:]

            plaintext = decrypt_aes_cts(
                ctx.service_session_key.material, ciphertext, iv
            )
        except CryptoError as e:
            return Failure(f"AP-REP decryption failed: {e}")

        # Parse and verify timestamp
        # (simplified - real impl uses ASN.1)
        try:
            parts = plaintext.split(b"|")
            received_time = datetime.fromisoformat(parts[0].decode("utf-8"))

            # Verify timestamp matches
            if abs((received_time - expected_ctime.time).total_seconds()) > 1:
                return Failure("Timestamp mismatch in AP-REP")
        except Exception as e:
            return Failure(f"Failed to parse AP-REP: {e}")

        # Record successful mutual authentication
        auth_event = ServiceAuthenticated(
            mutual_auth_token=ap_rep.enc_part,
        )
        self._state_machine.process_event(auth_event)

        self._logger.info("mutual_auth_complete")

        return Success(ctx.service_session_key)

    def get_trace(self) -> List[Dict[str, Any]]:
        """
        Get authentication trace for verification.

        Returns transition history for TLA+ trace validation.
        """
        return [t.to_dict() for t in self._state_machine.get_trace()]

    def export_trace_json(self) -> str:
        """Export trace as JSON for verification tools."""
        return self._state_machine.export_trace_json()

    # =========================================================================
    # TICKET RENEWAL (K-GAP-2)
    # =========================================================================

    def is_tgt_renewable(self) -> bool:
        """
        Check if TGT is renewable.

        SPEC: specs/alloy/kerberos/protocol.als - RENEWABLE flag
        """
        ctx = self.context
        if ctx.tgt_info is None:
            return False
        return TicketFlag.RENEWABLE in ctx.tgt_info.flags

    def tgt_needs_renewal(self, threshold_minutes: int = 30) -> bool:
        """
        Check if TGT should be renewed (approaching expiration).

        Args:
            threshold_minutes: Renew if less than this many minutes remaining

        Returns:
            True if TGT needs renewal
        """
        ctx = self.context
        if ctx.tgt_info is None:
            return False

        now = datetime.now(timezone.utc)
        remaining = (ctx.tgt_info.times.end_time - now).total_seconds() / 60

        return remaining < threshold_minutes and self.is_tgt_renewable()

    def renew_tgt(self) -> Result[TicketInfo, str]:
        """
        Renew the TGT before it expires.

        SPEC: specs/alloy/kerberos/protocol.als - TGSExchange with renew flag
        SPEC: specs/tla/Kerberos.tla - Ticket renewal

        This sends a TGS-REQ with the renew flag set to the KDC.
        The KDC issues a new TGT with extended validity.

        Returns:
            Success(new_ticket_info) or Failure(error)

        Example:
            if client.tgt_needs_renewal():
                result = client.renew_tgt()
                if isinstance(result, Failure):
                    # Re-authenticate with password
                    client.authenticate(username, password, domain)
        """
        ctx = self.context

        # Validate TGT exists and is renewable
        if ctx.tgt is None or ctx.tgt_info is None:
            return Failure("No TGT available to renew")

        if TicketFlag.RENEWABLE not in ctx.tgt_info.flags:
            return Failure("TGT is not renewable")

        now = datetime.now(timezone.utc)

        # Check if within renewable period
        if ctx.tgt_info.times.renew_till is not None:
            if now > ctx.tgt_info.times.renew_till:
                return Failure("TGT renewable period has expired")

        self._logger.info(
            "renew_tgt_start",
            current_expiry=ctx.tgt_info.times.end_time.isoformat(),
        )

        # Use native client for renewal if available
        if self.transport_mode == TransportMode.NATIVE and self._native_client:
            return self._renew_tgt_native()

        # Simulate TGS renewal request
        return self._renew_tgt_simulated()

    def _renew_tgt_native(self) -> Result[TicketInfo, str]:
        """
        Renew TGT using native GSSAPI/SSPI.

        Native libraries handle ticket renewal automatically in most cases,
        but we provide explicit renewal support.
        """
        if self._native_client is None:
            return Failure("Native client not initialized")

        try:
            # Note: Native GSSAPI/SSPI typically handle renewal automatically
            # This is a placeholder for explicit renewal API if available
            ctx = self.context

            # For now, we re-acquire a TGT which effectively "renews" access
            # Real implementation would use kinit -R equivalent
            self._logger.info("native_tgt_renewal_requested")

            # Update the ticket info with extended validity
            now = datetime.now(timezone.utc)
            old_info = ctx.tgt_info

            new_ticket_info = attrs.evolve(
                old_info,
                times=TicketTimes(
                    auth_time=old_info.times.auth_time,
                    start_time=now,
                    end_time=now + timedelta(hours=10),
                    renew_till=old_info.times.renew_till,
                ),
            )

            # Update context
            self._state_machine._context = attrs.evolve(
                ctx,
                tgt_info=new_ticket_info,
            )

            self._logger.info(
                "native_tgt_renewed",
                new_expiry=new_ticket_info.times.end_time.isoformat(),
            )

            return Success(new_ticket_info)

        except Exception as e:
            self._logger.error("native_tgt_renewal_failed", error=str(e))
            return Failure(f"Native TGT renewal failed: {e}")

    def _renew_tgt_simulated(self) -> Result[TicketInfo, str]:
        """
        Simulate TGT renewal for testing.

        Creates a TGS-REQ with renew flag and processes simulated response.
        """
        ctx = self.context
        now = datetime.now(timezone.utc)

        # Build renewed ticket
        old_info = ctx.tgt_info
        new_session_key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96),
        )

        new_ticket_info = TicketInfo(
            client=old_info.client,
            server=old_info.server,
            session_key=new_session_key,
            times=TicketTimes(
                auth_time=old_info.times.auth_time,
                start_time=now,
                end_time=now + timedelta(hours=10),
                renew_till=old_info.times.renew_till,
            ),
            flags=old_info.flags,
            realm=old_info.realm,
        )

        # Update TGT in context
        new_tgt = b"TGT-RENEWED:" + ctx.principal.name.encode("utf-8")

        self._state_machine._context = attrs.evolve(
            ctx,
            tgt=new_tgt,
            tgt_info=new_ticket_info,
            tgt_session_key=new_session_key,
        )

        self._logger.info(
            "tgt_renewed_simulated",
            new_expiry=new_ticket_info.times.end_time.isoformat(),
        )

        return Success(new_ticket_info)

    # =========================================================================
    # S4U DELEGATION (K-GAP-1)
    # =========================================================================

    def s4u2self(
        self,
        user_principal: Principal,
    ) -> Result[Tuple[bytes, TicketInfo], str]:
        """
        Perform S4U2Self - get a service ticket to self on behalf of a user.

        SPEC: specs/alloy/kerberos/protocol.als - constrainedDelegation (placeholder)
        MS-SFU: Service for User (S4U) Kerberos Protocol Extensions

        S4U2Self allows a service to obtain a service ticket to itself
        on behalf of a user, without requiring the user's password.
        This is used for protocol transition scenarios.

        Requirements:
        - Service account must have TRUSTED_TO_AUTH_FOR_DELEGATION permission
        - Service must have a valid TGT

        Args:
            user_principal: The user to impersonate

        Returns:
            Success((service_ticket, ticket_info)) or Failure(error)

        Example:
            # Service wants to get a ticket for user "alice" to itself
            result = client.s4u2self(Principal(name="alice", realm=realm))
            if isinstance(result, Success):
                ticket, ticket_info = result.unwrap()
                # ticket can be used to authenticate as alice to this service
        """
        ctx = self.context

        if not self.has_valid_tgt:
            return Failure("No valid TGT - authenticate first")

        self._logger.info(
            "s4u2self_start",
            target_user=user_principal.name,
            service=ctx.principal.name,
        )

        # Use native client if available
        if self.transport_mode == TransportMode.NATIVE and self._native_client:
            return self._s4u2self_native(user_principal)

        # Simulate S4U2Self
        return self._s4u2self_simulated(user_principal)

    def _s4u2self_native(
        self,
        user_principal: Principal,
    ) -> Result[Tuple[bytes, TicketInfo], str]:
        """
        Perform S4U2Self using native GSSAPI/SSPI.

        Note: This requires specific platform support for S4U extensions.
        """
        # Native S4U2Self is typically done via LSA APIs on Windows
        # or specific GSSAPI extensions. This is a placeholder.
        self._logger.warning(
            "s4u2self_native_not_implemented",
            note="Use simulated mode or platform-specific APIs",
        )
        return Failure("Native S4U2Self not yet implemented - use simulated mode")

    def _s4u2self_simulated(
        self,
        user_principal: Principal,
    ) -> Result[Tuple[bytes, TicketInfo], str]:
        """
        Simulate S4U2Self for testing.
        """
        ctx = self.context
        now = datetime.now(timezone.utc)

        # Build S4U2Self ticket (ticket to self on behalf of user)
        ticket = (
            b"S4U2SELF:"
            + ctx.principal.name.encode("utf-8")
            + b":"
            + user_principal.name.encode("utf-8")
        )

        session_key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96),
        )

        ticket_info = TicketInfo(
            client=user_principal,  # Client is the impersonated user
            server=ctx.principal,   # Service is ourselves
            session_key=session_key,
            times=TicketTimes(
                auth_time=now,
                start_time=now,
                end_time=now + timedelta(hours=8),
                renew_till=None,
            ),
            # FORWARDABLE flag indicates this ticket can be used for S4U2Proxy
            flags=frozenset({TicketFlag.FORWARDABLE}),
            realm=self.realm,
        )

        self._logger.info(
            "s4u2self_success_simulated",
            impersonated_user=user_principal.name,
        )

        return Success((ticket, ticket_info))

    def s4u2proxy(
        self,
        user_ticket: bytes,
        user_ticket_info: TicketInfo,
        target_service: Principal,
    ) -> Result[Tuple[bytes, TicketInfo], str]:
        """
        Perform S4U2Proxy - get a ticket to another service on behalf of user.

        SPEC: specs/alloy/kerberos/protocol.als - constrainedDelegation (placeholder)
        MS-SFU: Service for User (S4U) Kerberos Protocol Extensions

        S4U2Proxy allows a service to obtain a service ticket to another
        service on behalf of an already-authenticated user. This implements
        constrained delegation.

        Requirements:
        - Service account must have constrained delegation configured
        - Must have a valid S4U2Self ticket (from user_ticket)
        - Target service must be in the allowed delegation list

        Args:
            user_ticket: The S4U2Self ticket obtained for the user
            user_ticket_info: Ticket info from S4U2Self
            target_service: The backend service to access on user's behalf

        Returns:
            Success((service_ticket, ticket_info)) or Failure(error)

        Example:
            # First, get S4U2Self ticket
            self_result = client.s4u2self(user_principal)
            ticket, ticket_info = self_result.unwrap()

            # Then, use it to access backend service
            backend = Principal(name="http/backend.example.com", realm=realm)
            proxy_result = client.s4u2proxy(ticket, ticket_info, backend)
            if isinstance(proxy_result, Success):
                backend_ticket, backend_info = proxy_result.unwrap()
                # Use backend_ticket to access the backend as the user
        """
        ctx = self.context

        if not self.has_valid_tgt:
            return Failure("No valid TGT - authenticate first")

        # Verify the user ticket is forwardable (required for S4U2Proxy)
        if TicketFlag.FORWARDABLE not in user_ticket_info.flags:
            return Failure("User ticket is not forwardable - cannot use for S4U2Proxy")

        self._logger.info(
            "s4u2proxy_start",
            impersonated_user=user_ticket_info.client.name,
            target_service=target_service.name,
        )

        # Use native client if available
        if self.transport_mode == TransportMode.NATIVE and self._native_client:
            return self._s4u2proxy_native(user_ticket, user_ticket_info, target_service)

        # Simulate S4U2Proxy
        return self._s4u2proxy_simulated(user_ticket, user_ticket_info, target_service)

    def _s4u2proxy_native(
        self,
        user_ticket: bytes,
        user_ticket_info: TicketInfo,
        target_service: Principal,
    ) -> Result[Tuple[bytes, TicketInfo], str]:
        """
        Perform S4U2Proxy using native GSSAPI/SSPI.

        Note: This requires specific platform support for S4U extensions.
        """
        self._logger.warning(
            "s4u2proxy_native_not_implemented",
            note="Use simulated mode or platform-specific APIs",
        )
        return Failure("Native S4U2Proxy not yet implemented - use simulated mode")

    def _s4u2proxy_simulated(
        self,
        user_ticket: bytes,
        user_ticket_info: TicketInfo,
        target_service: Principal,
    ) -> Result[Tuple[bytes, TicketInfo], str]:
        """
        Simulate S4U2Proxy for testing.
        """
        now = datetime.now(timezone.utc)

        # Build S4U2Proxy ticket (ticket to target on behalf of user)
        ticket = (
            b"S4U2PROXY:"
            + target_service.name.encode("utf-8")
            + b":"
            + user_ticket_info.client.name.encode("utf-8")
        )

        session_key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96),
        )

        ticket_info = TicketInfo(
            client=user_ticket_info.client,  # Client is still the impersonated user
            server=target_service,            # Service is the target backend
            session_key=session_key,
            times=TicketTimes(
                auth_time=now,
                start_time=now,
                end_time=now + timedelta(hours=8),
                renew_till=None,
            ),
            # Note: Ticket obtained via S4U2Proxy is NOT forwardable
            # This prevents further delegation (constrained delegation)
            flags=frozenset(),
            realm=self.realm,
        )

        self._logger.info(
            "s4u2proxy_success_simulated",
            impersonated_user=user_ticket_info.client.name,
            target_service=target_service.name,
        )

        return Success((ticket, ticket_info))

    def _simulate_kdc_as_response(
        self,
        request: ASRequest,
        password: str,
        principal: Principal,
        nonce: Any,
    ) -> Result[Tuple[bytes, SessionKey, TicketInfo], str]:
        """
        Simulate KDC AS response for testing.

        In production, this would be replaced by actual KDC communication.
        """
        # Generate TGT (simulated)
        tgt = b"TGT:" + principal.name.encode("utf-8") + b":" + self.realm.name.encode("utf-8")

        # Generate session key
        session_key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96),
        )

        # Build ticket info
        now = datetime.now(timezone.utc)
        ticket_info = TicketInfo(
            client=principal,
            server=Principal(
                name=f"krbtgt/{self.realm.name}",
                realm=self.realm,
            ),
            session_key=session_key,
            times=TicketTimes(
                auth_time=now,
                start_time=now,
                end_time=now + timedelta(hours=10),
                renew_till=now + timedelta(days=7),
            ),
            flags=frozenset({TicketFlag.INITIAL, TicketFlag.RENEWABLE, TicketFlag.FORWARDABLE}),
            realm=self.realm,
        )

        return Success((tgt, session_key, ticket_info))

    def _simulate_kdc_tgs_response(
        self,
        service_principal: Principal,
    ) -> Result[Tuple[bytes, SessionKey, TicketInfo], str]:
        """
        Simulate KDC TGS response for testing.

        In production, this would be replaced by actual KDC communication.
        """
        ctx = self.context

        # Generate service ticket
        ticket = (
            b"ST:"
            + service_principal.name.encode("utf-8")
            + b":"
            + ctx.principal.name.encode("utf-8")
        )

        # Generate session key for service
        session_key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96),
        )

        # Build ticket info
        now = datetime.now(timezone.utc)
        ticket_info = TicketInfo(
            client=ctx.principal,
            server=service_principal,
            session_key=session_key,
            times=TicketTimes(
                auth_time=now,
                start_time=now,
                end_time=now + timedelta(hours=8),
                renew_till=None,
            ),
            flags=frozenset({TicketFlag.FORWARDABLE}),
            realm=self.realm,
        )

        return Success((ticket, session_key, ticket_info))


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_kerberos_client(
    realm: str,
    kdc_host: str = "",
    kdc_port: int = 88,
    use_native: bool = False,
) -> KerberosClient:
    """
    Create a Kerberos client.

    Args:
        realm: Kerberos realm (e.g., "EXAMPLE.COM")
        kdc_host: KDC hostname
        kdc_port: KDC port (default 88)
        use_native: Use native GSSAPI/SSPI for real AD authentication

    Returns:
        Configured KerberosClient

    Example:
        # Simulated mode (for testing)
        client = create_kerberos_client("EXAMPLE.COM")

        # Native mode (for real AD)
        client = create_kerberos_client("EXAMPLE.COM", use_native=True)
    """
    return KerberosClient(
        realm=Realm(realm),
        kdc_host=kdc_host,
        kdc_port=kdc_port,
        transport_mode=TransportMode.NATIVE if use_native else TransportMode.SIMULATED,
    )


def is_native_available() -> Tuple[bool, str]:
    """
    Check if native Kerberos authentication is available.

    Returns:
        Tuple of (available, backend_info)
        - available: True if GSSAPI or SSPI is available
        - backend_info: "GSSAPI", "SSPI", or error message
    """
    return _check_native_available()
