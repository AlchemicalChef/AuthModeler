"""
AuthModeler Kerberos Service

Service-side Kerberos V5 implementation for validating AP-REQ messages.

SPEC: specs/tla/Kerberos.tla - ServiceProcessAPRequest

This module provides a complete Kerberos service that:
1. Validates AP-REQ messages from clients
2. Decrypts service tickets using the service's long-term key
3. Validates authenticators (timestamp, replay prevention)
4. Generates AP-REP for mutual authentication
5. Exports traces for formal verification
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import attrs
import structlog
from returns.result import Failure, Result, Success, ResultE

from authmodeler.core.crypto import (
    decrypt_aes_cts,
    encrypt_aes_cts,
    generate_session_key,
)
from authmodeler.core.exceptions import (
    AuthenticationError,
    CryptoError,
)
from authmodeler.core.state_machine import StateMachineBase, TransitionEntry
from authmodeler.core.types import (
    EncryptionType,
    Principal,
    Realm,
    SessionKey,
    TicketFlag,
    Timestamp,
)
from authmodeler.kerberos.types import (
    APReply,
    APReplyEncPart,
    APRequest,
    APRequestReceived,
    APRequestRejected,
    APRequestValidated,
    APReplyGenerated,
    Authenticator,
    DecryptedTicket,
    ServiceAuthResult,
    ServiceState,
)
from authmodeler.kerberos.replay_cache import (
    AuthenticatorCache,
    KerberosErrorCode,
)

logger = structlog.get_logger()


# =============================================================================
# SERVICE CONTEXT
# =============================================================================


@attrs.define
class ServiceContext:
    """
    Service authentication context.

    Mutable state maintained during AP exchange validation.

    SPEC: specs/tla/Kerberos.tla - service variables
    """

    # Service identity
    principal: Principal
    realm: Realm

    # Current session state
    current_client: Optional[Principal] = None
    current_realm: Optional[Realm] = None
    session_key: Optional[SessionKey] = None
    last_authenticator: Optional[Authenticator] = None

    # Validation results
    decrypted_ticket: Optional[DecryptedTicket] = None
    mutual_auth_required: bool = False

    # Error state
    error_code: Optional[int] = None
    error_message: str = ""


# =============================================================================
# SERVICE STATE MACHINE
# =============================================================================


@attrs.define
class ServiceStateMachine(
    StateMachineBase[ServiceState, Any, ServiceContext]
):
    """
    Service-side Kerberos state machine.

    SPEC: specs/tla/Kerberos.tla - serviceState, ServiceProcessAPRequest

    States:
    - READY: Waiting for AP-REQ
    - PROCESSING: Validating AP-REQ
    - AUTHENTICATED: Client authenticated
    - ERROR: Validation failed
    """

    def initial_state(self) -> ServiceState:
        return ServiceState.READY

    def transition_table(
        self,
    ) -> Dict[Tuple[ServiceState, type], TransitionEntry]:
        return {
            # Receive AP-REQ
            (ServiceState.READY, APRequestReceived): (
                ServiceState.PROCESSING,
                self._handle_ap_request_received,
            ),
            # Validation successful
            (ServiceState.PROCESSING, APRequestValidated): (
                ServiceState.AUTHENTICATED,
                self._handle_ap_request_validated,
            ),
            # Validation failed
            (ServiceState.PROCESSING, APRequestRejected): (
                ServiceState.ERROR,
                self._handle_ap_request_rejected,
            ),
            # Generate AP-REP for mutual auth
            (ServiceState.AUTHENTICATED, APReplyGenerated): (
                ServiceState.AUTHENTICATED,
                self._handle_ap_reply_generated,
            ),
            # Reset after authentication (ready for next request)
            (ServiceState.AUTHENTICATED, APRequestReceived): (
                ServiceState.PROCESSING,
                self._handle_ap_request_received,
            ),
            # Retry after error
            (ServiceState.ERROR, APRequestReceived): (
                ServiceState.PROCESSING,
                self._handle_ap_request_received,
            ),
        }

    @staticmethod
    def _handle_ap_request_received(
        event: APRequestReceived, ctx: ServiceContext
    ) -> ServiceContext:
        """Handle APRequestReceived event."""
        return attrs.evolve(
            ctx,
            current_client=None,
            current_realm=None,
            session_key=None,
            last_authenticator=None,
            decrypted_ticket=None,
            error_code=None,
            error_message="",
        )

    @staticmethod
    def _handle_ap_request_validated(
        event: APRequestValidated, ctx: ServiceContext
    ) -> ServiceContext:
        """Handle APRequestValidated event."""
        return attrs.evolve(
            ctx,
            error_code=None,
            error_message="",
        )

    @staticmethod
    def _handle_ap_request_rejected(
        event: APRequestRejected, ctx: ServiceContext
    ) -> ServiceContext:
        """Handle APRequestRejected event."""
        return attrs.evolve(
            ctx,
            error_code=event.error_code,
            error_message=event.reason,
            session_key=None,
        )

    @staticmethod
    def _handle_ap_reply_generated(
        event: APReplyGenerated, ctx: ServiceContext
    ) -> ServiceContext:
        """Handle APReplyGenerated event."""
        return ctx  # No context changes needed


# =============================================================================
# KERBEROS SERVICE
# =============================================================================


@attrs.define
class KerberosService:
    """
    Service-side Kerberos authentication handler.

    SPEC: specs/tla/Kerberos.tla - ServiceProcessAPRequest

    Validates AP-REQ messages and generates AP-REP for mutual authentication.

    Example:
        # Create service
        service = KerberosService(
            principal=Principal(name="HTTP/server.example.com"),
            realm=Realm(name="EXAMPLE.COM"),
        )

        # Validate AP-REQ from client
        result = service.validate_ap_request(ap_req)
        if isinstance(result, Success):
            auth_result = result.unwrap()
            print(f"Client authenticated: {auth_result.client_principal.name}")

            # Generate AP-REP if mutual auth requested
            if auth_result.mutual_auth_required:
                ap_rep = service.build_ap_reply(auth_result)
    """

    # Service identity
    principal: Principal
    realm: Realm

    # Service key (from keytab or generated for simulation)
    service_key: Optional[SessionKey] = None
    keytab_path: Optional[str] = None

    # Replay prevention
    _replay_cache: AuthenticatorCache = attrs.field(
        factory=AuthenticatorCache, alias="_replay_cache"
    )

    # State machine
    _state_machine: ServiceStateMachine = attrs.field(
        alias="_state_machine",
        default=None,
    )

    # Simulation mode (for testing)
    simulation_mode: bool = True
    _simulated_tickets: Dict[bytes, DecryptedTicket] = attrs.field(
        factory=dict, alias="_simulated_tickets"
    )

    _logger: structlog.BoundLogger = attrs.field(
        factory=lambda: structlog.get_logger(), alias="_logger"
    )

    def __attrs_post_init__(self) -> None:
        """Initialize state machine after attrs initialization."""
        if self._state_machine is None:
            object.__setattr__(
                self,
                "_state_machine",
                ServiceStateMachine(
                    _state=ServiceState.READY,
                    _context=ServiceContext(
                        principal=self.principal,
                        realm=self.realm,
                    ),
                ),
            )

    @property
    def state(self) -> ServiceState:
        """Current state machine state."""
        return self._state_machine.state

    @property
    def context(self) -> ServiceContext:
        """Current context."""
        return self._state_machine.context

    def validate_ap_request(
        self, ap_req: APRequest
    ) -> Result[ServiceAuthResult, str]:
        """
        Validate incoming AP-REQ from client.

        SPEC: specs/tla/Kerberos.tla - ServiceProcessAPRequest

        Steps:
        1. Signal AP-REQ received
        2. Decrypt service ticket using service's long-term key
        3. Extract session key from decrypted ticket
        4. Decrypt authenticator using session key
        5. Validate authenticator (timestamp, principal match)
        6. Check replay cache
        7. Add authenticator to replay cache

        Args:
            ap_req: The AP-REQ message from client

        Returns:
            Success(ServiceAuthResult) with client identity and session key
            Failure(error) if validation fails
        """
        # Signal AP-REQ received
        self._state_machine.process_event(
            APRequestReceived(client_principal="<pending>")
        )

        # Step 1: Decrypt the service ticket
        ticket_result = self._decrypt_ticket(ap_req.ticket)
        if isinstance(ticket_result, Failure):
            error_code = KerberosErrorCode.KRB_AP_ERR_BAD_INTEGRITY
            self._state_machine.process_event(
                APRequestRejected(
                    error_code=error_code,
                    reason=ticket_result.failure(),
                )
            )
            return ticket_result

        ticket = ticket_result.unwrap()

        # Step 2: Validate ticket timestamps
        now = datetime.now(timezone.utc)
        if ticket.end_time.time < now:
            error_code = KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED
            reason = "Ticket has expired"
            self._state_machine.process_event(
                APRequestRejected(error_code=error_code, reason=reason)
            )
            return Failure(reason)

        if ticket.start_time and ticket.start_time.time > now:
            error_code = KerberosErrorCode.KRB_AP_ERR_TKT_NYV
            reason = "Ticket not yet valid"
            self._state_machine.process_event(
                APRequestRejected(error_code=error_code, reason=reason)
            )
            return Failure(reason)

        # Step 3: Decrypt the authenticator using session key from ticket
        auth_result = self._decrypt_authenticator(
            ap_req.authenticator, ticket.session_key
        )
        if isinstance(auth_result, Failure):
            error_code = KerberosErrorCode.KRB_AP_ERR_BAD_INTEGRITY
            self._state_machine.process_event(
                APRequestRejected(
                    error_code=error_code,
                    reason=auth_result.failure(),
                )
            )
            return auth_result

        authenticator = auth_result.unwrap()

        # Step 4: Validate authenticator timestamp (clock skew)
        valid, skew_error = self._replay_cache.check_timestamp(authenticator)
        if not valid:
            error_code = KerberosErrorCode.KRB_AP_ERR_SKEW
            self._state_machine.process_event(
                APRequestRejected(error_code=error_code, reason=skew_error)
            )
            return Failure(skew_error)

        # Step 5: Verify client principal matches
        if authenticator.client_principal.name != ticket.client_principal.name:
            error_code = KerberosErrorCode.KRB_AP_ERR_BADMATCH
            reason = "Authenticator client does not match ticket"
            self._state_machine.process_event(
                APRequestRejected(error_code=error_code, reason=reason)
            )
            return Failure(reason)

        # Step 6: Check replay cache (SPEC: msg.authenticator \notin serviceAuthCache[s])
        if not self._replay_cache.check_and_add(authenticator):
            error_code = KerberosErrorCode.KRB_AP_ERR_REPEAT
            reason = "Authenticator replay detected"
            self._state_machine.process_event(
                APRequestRejected(error_code=error_code, reason=reason)
            )
            return Failure(reason)

        # Update context with validated data
        ctx = self._state_machine._context
        self._state_machine._context = attrs.evolve(
            ctx,
            current_client=ticket.client_principal,
            current_realm=ticket.client_realm,
            session_key=ticket.session_key,
            last_authenticator=authenticator,
            decrypted_ticket=ticket,
            mutual_auth_required=ap_req.mutual_required,
        )

        # Signal validation success
        self._state_machine.process_event(
            APRequestValidated(
                client_principal=ticket.client_principal.name,
                session_key_established=True,
            )
        )

        # Build result
        result = ServiceAuthResult(
            client_principal=ticket.client_principal,
            client_realm=ticket.client_realm,
            session_key=ticket.session_key,
            authenticator=authenticator,
            mutual_auth_required=ap_req.mutual_required,
            ticket=ticket,
        )

        self._logger.info(
            "ap_request_validated",
            client=ticket.client_principal.name,
            realm=ticket.client_realm.name,
            mutual_auth=ap_req.mutual_required,
        )

        return Success(result)

    def build_ap_reply(
        self, auth_result: ServiceAuthResult
    ) -> Result[APReply, str]:
        """
        Build AP-REP for mutual authentication.

        SPEC: specs/tla/Kerberos.tla - APReplyMsg

        Encrypts the client's authenticator timestamp with session key
        to prove the service possesses the session key.

        Args:
            auth_result: Result from validate_ap_request

        Returns:
            Success(APReply) for mutual authentication
            Failure(error) if building fails
        """
        if not auth_result.mutual_auth_required:
            return Failure("Mutual authentication not requested")

        session_key = auth_result.session_key
        authenticator = auth_result.authenticator

        # Build AP-REP enc part
        enc_part = APReplyEncPart(
            ctime=authenticator.ctime,
            cusec=authenticator.cusec,
            subkey=authenticator.subkey,
            seq_number=authenticator.seq_number,
        )

        # Encode and encrypt (simplified - real impl uses ASN.1)
        enc_data = (
            authenticator.ctime.time.isoformat().encode("utf-8")
            + b"|"
            + str(authenticator.cusec).encode("utf-8")
        )

        encrypted, iv = encrypt_aes_cts(session_key.material, enc_data)

        ap_rep = APReply(
            enc_part=iv + encrypted,
            enc_type=session_key.enctype,
        )

        # Signal AP-REP generation
        self._state_machine.process_event(
            APReplyGenerated(
                ctime=authenticator.ctime,
                cusec=authenticator.cusec,
            )
        )

        self._logger.info(
            "ap_reply_generated",
            client=auth_result.client_principal.name,
        )

        return Success(ap_rep)

    def _decrypt_ticket(self, ticket_bytes: bytes) -> Result[DecryptedTicket, str]:
        """
        Decrypt service ticket using service's long-term key.

        In simulation mode, looks up pre-registered tickets.
        In real mode, uses keytab to decrypt.
        """
        if self.simulation_mode:
            # Simulation: Look up pre-registered ticket
            if ticket_bytes in self._simulated_tickets:
                return Success(self._simulated_tickets[ticket_bytes])

            # Try to parse simulated ticket format
            # Format: "SVC_TKT:<client>:<realm>:<session_key_hex>:<end_time>"
            try:
                if ticket_bytes.startswith(b"SVC_TKT:"):
                    parts = ticket_bytes[8:].split(b":")
                    if len(parts) >= 4:
                        client_name = parts[0].decode("utf-8")
                        realm_name = parts[1].decode("utf-8")
                        session_key_hex = parts[2].decode("utf-8")
                        end_time_str = parts[3].decode("utf-8")

                        client_realm = Realm(name=realm_name)
                        # Parse end time and ensure it's timezone-aware
                        parsed_end_time = datetime.fromisoformat(end_time_str)
                        if parsed_end_time.tzinfo is None:
                            parsed_end_time = parsed_end_time.replace(tzinfo=timezone.utc)
                        ticket = DecryptedTicket(
                            client_principal=Principal(name=client_name, realm=client_realm),
                            client_realm=client_realm,
                            session_key=SessionKey(
                                enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                                material=bytes.fromhex(session_key_hex),
                            ),
                            auth_time=Timestamp(),
                            end_time=Timestamp(time=parsed_end_time),
                        )
                        return Success(ticket)
            except Exception as e:
                self._logger.warning("ticket_parse_error", error=str(e))

            return Failure("Unknown ticket (not registered in simulation)")

        # Real mode: Decrypt with service key
        if self.service_key is None:
            return Failure("No service key configured")

        try:
            if len(ticket_bytes) < 16:
                return Failure("Ticket too short")

            iv = ticket_bytes[:16]
            ciphertext = ticket_bytes[16:]

            plaintext = decrypt_aes_cts(
                self.service_key.material, ciphertext, iv
            )

            # Parse decrypted ticket (simplified)
            # Real implementation would use ASN.1
            return self._parse_decrypted_ticket(plaintext)

        except CryptoError as e:
            return Failure(f"Ticket decryption failed: {e}")

    def _decrypt_authenticator(
        self, auth_bytes: bytes, session_key: SessionKey
    ) -> Result[Authenticator, str]:
        """
        Decrypt authenticator using session key from ticket.
        """
        try:
            if len(auth_bytes) < 16:
                return Failure("Authenticator too short")

            iv = auth_bytes[:16]
            ciphertext = auth_bytes[16:]

            plaintext = decrypt_aes_cts(session_key.material, ciphertext, iv)

            # Parse authenticator (simplified - matches client.py format)
            # Format: client_principal|timestamp
            parts = plaintext.split(b"|")
            if len(parts) < 2:
                return Failure("Invalid authenticator format")

            client_name = parts[0].decode("utf-8")
            timestamp_str = parts[1].decode("utf-8")

            # Parse the client name (may be in domain\user format)
            if "\\" in client_name:
                domain, user = client_name.split("\\", 1)
                realm = Realm(name=domain)
                principal = Principal(name=user, realm=realm)
            else:
                realm = self.realm
                principal = Principal(name=client_name, realm=realm)

            authenticator = Authenticator(
                client_principal=principal,
                client_realm=realm,
                ctime=Timestamp(time=datetime.fromisoformat(timestamp_str)),
            )

            return Success(authenticator)

        except CryptoError as e:
            return Failure(f"Authenticator decryption failed: {e}")
        except Exception as e:
            return Failure(f"Authenticator parse failed: {e}")

    def _parse_decrypted_ticket(
        self, plaintext: bytes
    ) -> Result[DecryptedTicket, str]:
        """Parse decrypted ticket bytes into DecryptedTicket."""
        # Simplified parsing for demonstration
        # Real implementation would use ASN.1 DER decoding
        try:
            # Expected format: client|realm|session_key_hex|end_time
            parts = plaintext.split(b"|")
            if len(parts) < 4:
                return Failure("Invalid ticket format")

            client_realm = Realm(name=parts[1].decode("utf-8"))
            # Parse end time and ensure it's timezone-aware
            parsed_end_time = datetime.fromisoformat(parts[3].decode("utf-8"))
            if parsed_end_time.tzinfo is None:
                parsed_end_time = parsed_end_time.replace(tzinfo=timezone.utc)
            ticket = DecryptedTicket(
                client_principal=Principal(name=parts[0].decode("utf-8"), realm=client_realm),
                client_realm=client_realm,
                session_key=SessionKey(
                    enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    material=bytes.fromhex(parts[2].decode("utf-8")),
                ),
                auth_time=Timestamp(),
                end_time=Timestamp(time=parsed_end_time),
            )
            return Success(ticket)

        except Exception as e:
            return Failure(f"Ticket parse failed: {e}")

    def register_simulated_ticket(
        self,
        ticket_bytes: bytes,
        client_principal: Principal,
        client_realm: Realm,
        session_key: SessionKey,
        end_time: datetime,
    ) -> None:
        """
        Register a simulated ticket for testing.

        Allows testing without real KDC ticket generation.
        """
        ticket = DecryptedTicket(
            client_principal=client_principal,
            client_realm=client_realm,
            session_key=session_key,
            auth_time=Timestamp(),
            end_time=Timestamp(time=end_time),
        )
        self._simulated_tickets[ticket_bytes] = ticket

        self._logger.debug(
            "simulated_ticket_registered",
            client=client_principal.name,
            realm=client_realm.name,
        )

    def get_trace(self) -> List[Dict[str, Any]]:
        """
        Get authentication trace for verification.

        Returns transition history for TLA+ trace validation.
        """
        return [t.to_dict() for t in self._state_machine.get_trace()]

    def export_trace_json(self) -> str:
        """Export trace as JSON for verification tools."""
        return self._state_machine.export_trace_json()

    def clear_replay_cache(self) -> int:
        """Clear the replay cache. Returns number of entries cleared."""
        return self._replay_cache.clear()

    def get_replay_cache_stats(self) -> Dict[str, int]:
        """Get replay cache statistics."""
        return self._replay_cache.get_stats()


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_kerberos_service(
    service_name: str,
    realm: str,
    service_key: Optional[bytes] = None,
    simulation_mode: bool = True,
) -> KerberosService:
    """
    Create a KerberosService instance.

    Args:
        service_name: Service principal name (e.g., "HTTP/server.example.com")
        realm: Kerberos realm (e.g., "EXAMPLE.COM")
        service_key: Optional service key bytes (32 bytes for AES-256)
        simulation_mode: If True, use simulated ticket validation

    Returns:
        Configured KerberosService instance
    """
    realm_obj = Realm(name=realm.upper())
    principal = Principal(name=service_name, realm=realm_obj)

    session_key = None
    if service_key:
        session_key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=service_key,
        )

    return KerberosService(
        principal=principal,
        realm=realm_obj,
        service_key=session_key,
        simulation_mode=simulation_mode,
    )
