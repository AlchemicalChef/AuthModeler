"""
AuthModeler NTLM Client

High-level NTLMv2 client implementation.

SPEC: specs/alloy/ntlm/protocol.als
SPEC: specs/tla/NTLM.tla

WARNING: NTLM has known security vulnerabilities:
- Pass-the-hash: Attacker with NT hash can authenticate without password
- Relay attacks: Attacker can relay authentication to another server
- No mutual authentication: Client cannot verify server identity

Use Kerberos when possible. NTLM provided for legacy compatibility only.

Supports:
- Pure Python NTLM implementation (simulated mode)
- SSPI-based NTLM on Windows (native mode)
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

import attrs
import structlog
from returns.result import Failure, Result, Success

from authmodeler.core.crypto import (
    compute_nt_hash,
    compute_ntlmv2_response,
    encrypt_rc4,
    hmac_md5,
)
from authmodeler.core.exceptions import AuthenticationError, NTLMError
from authmodeler.core.state_machine import StateMachineBase, TransitionEntry
from authmodeler.core.types import AuthResult
from authmodeler.ntlm.types import (
    AuthenticateComplete,
    AuthenticateMessage,
    AVPair,
    AVPairType,
    CHALLENGE_VALIDITY_WINDOW_SECONDS,
    ChallengeMessage,
    ChallengeReceived,
    InitiateNTLM,
    MsvAvFlagsValue,
    NegotiateFlags,
    NegotiateMessage,
    NTLMContext,
    NTLMErrorReceived,
    NTLMState,
    build_av_pairs,
    parse_av_pairs,
)

logger = structlog.get_logger()


# =============================================================================
# TRANSPORT MODE
# =============================================================================


class NTLMTransportMode(Enum):
    """
    NTLM transport mode.

    - SIMULATED: Pure Python NTLM (for testing/verification)
    - NATIVE: SSPI-based NTLM on Windows
    """
    SIMULATED = auto()
    NATIVE = auto()


def _check_sspi_available() -> Tuple[bool, str]:
    """Check if SSPI is available for native NTLM."""
    try:
        from authmodeler.transport.sspi_wrapper import sspi_available
        if sspi_available():
            return True, "SSPI"
        return False, "SSPI not available (Windows only)"
    except ImportError as e:
        return False, f"SSPI wrapper not available: {e}"


# =============================================================================
# NTLM CLIENT STATE MACHINE
# =============================================================================


@attrs.define
class NTLMClientStateMachine(
    StateMachineBase[NTLMState, Any, NTLMContext]
):
    """
    State machine for NTLM authentication.

    SPEC: specs/tla/NTLM.tla - NTLMState, Next

    States:
    - INITIAL: No authentication
    - NEGOTIATE_SENT: Sent NEGOTIATE, waiting for CHALLENGE
    - CHALLENGE_RECEIVED: Processing server challenge
    - AUTHENTICATE_SENT: Sent AUTHENTICATE, waiting for result
    - AUTHENTICATED: Authentication successful
    - ERROR: Authentication failed
    """

    def initial_state(self) -> NTLMState:
        return NTLMState.INITIAL

    def transition_table(
        self,
    ) -> Dict[Tuple[NTLMState, type], TransitionEntry]:
        return {
            # INITIAL -> NEGOTIATE_SENT
            (NTLMState.INITIAL, InitiateNTLM): (
                NTLMState.NEGOTIATE_SENT,
                self._handle_initiate,
            ),
            # NEGOTIATE_SENT -> CHALLENGE_RECEIVED
            (NTLMState.NEGOTIATE_SENT, ChallengeReceived): (
                NTLMState.CHALLENGE_RECEIVED,
                self._handle_challenge,
            ),
            (NTLMState.NEGOTIATE_SENT, NTLMErrorReceived): (
                NTLMState.ERROR,
                self._handle_error,
            ),
            # CHALLENGE_RECEIVED -> AUTHENTICATE_SENT
            # (implicit in client - we build and send authenticate immediately)
            # AUTHENTICATE_SENT -> AUTHENTICATED
            (NTLMState.CHALLENGE_RECEIVED, AuthenticateComplete): (
                NTLMState.AUTHENTICATED,
                self._handle_authenticated,
            ),
            (NTLMState.CHALLENGE_RECEIVED, NTLMErrorReceived): (
                NTLMState.ERROR,
                self._handle_error,
            ),
        }

    @staticmethod
    def _handle_initiate(
        event: InitiateNTLM, ctx: NTLMContext
    ) -> NTLMContext:
        """Handle InitiateNTLM event."""
        return attrs.evolve(
            ctx,
            username=event.username,
            domain=event.domain,
            error_code=None,
            error_message="",
        )

    @staticmethod
    def _handle_challenge(
        event: ChallengeReceived, ctx: NTLMContext
    ) -> NTLMContext:
        """Handle ChallengeReceived event."""
        return attrs.evolve(
            ctx,
            server_challenge=event.server_challenge,
            target_info=event.target_info,
            negotiate_flags=event.negotiate_flags,
            server_name=event.target_name,
        )

    @staticmethod
    def _handle_authenticated(
        event: AuthenticateComplete, ctx: NTLMContext
    ) -> NTLMContext:
        """Handle AuthenticateComplete event."""
        return attrs.evolve(
            ctx,
            session_key=event.session_key,
        )

    @staticmethod
    def _handle_error(
        event: NTLMErrorReceived, ctx: NTLMContext
    ) -> NTLMContext:
        """Handle error event."""
        return attrs.evolve(
            ctx,
            error_code=event.error_code,
            error_message=event.error_message,
        )


# =============================================================================
# NTLM CLIENT
# =============================================================================


@attrs.define
class NTLMClient:
    """
    High-level NTLMv2 client.

    SPEC: specs/alloy/ntlm/protocol.als
    SPEC: specs/tla/NTLM.tla

    WARNING: NTLM has known security vulnerabilities.
    Use Kerberos when possible.

    Transport Modes:
    - SIMULATED: Pure Python NTLM (for testing)
    - NATIVE: SSPI-based NTLM on Windows (for real AD)

    Security Features (N-GAP fixes):
    - EPA/Channel Binding (N-GAP-1): Set channel_bindings parameter
    - Challenge Freshness (N-GAP-3): Set require_fresh_challenge=True
    - MIC (N-GAP-2): Set require_mic=True
    - Signing (N-GAP-6): Set require_signing=True

    Example (simulated):
        client = NTLMClient()

        # Step 1: Generate NEGOTIATE message
        negotiate = client.create_negotiate_message()

        # Step 2: Process server's CHALLENGE
        client.process_challenge(challenge_bytes)

        # Step 3: Generate AUTHENTICATE message
        authenticate = client.create_authenticate_message("user", "password", "DOMAIN")

    Example (native - Windows only):
        client = NTLMClient(transport_mode=NTLMTransportMode.NATIVE)
        result = client.authenticate("user", "password", "DOMAIN")

    Example (with security mitigations):
        # Get TLS channel binding from SSL socket
        channel_bindings = compute_channel_bindings(ssl_socket.getpeercert(binary_form=True))

        client = NTLMClient(
            channel_bindings=channel_bindings,  # EPA (N-GAP-1)
            require_fresh_challenge=True,        # Freshness (N-GAP-3)
            require_mic=True,                    # MIC (N-GAP-2)
            require_signing=True,                # Signing (N-GAP-6)
        )
    """

    workstation_name: str = ""
    transport_mode: NTLMTransportMode = NTLMTransportMode.SIMULATED

    # Security mitigations (N-GAP fixes)
    # SPEC: specs/alloy/ntlm/properties.als - allMitigationsEnabled

    # EPA / Channel Binding (N-GAP-1)
    # SPEC: specs/alloy/ntlm/properties.als - epaEnabled, EPAPreventsRelay
    channel_bindings: Optional[bytes] = None

    # Challenge Freshness (N-GAP-3)
    # SPEC: specs/tla/NTLM.tla - ChallengeFresh, ChallengeValidityWindow
    require_fresh_challenge: bool = True
    challenge_validity_seconds: int = CHALLENGE_VALIDITY_WINDOW_SECONDS

    # MIC (N-GAP-2)
    # SPEC: specs/alloy/ntlm/properties.als - MICIntegrity, micRequired
    require_mic: bool = True

    # SMB Signing (N-GAP-6)
    # SPEC: specs/alloy/ntlm/properties.als - smbSigningEnabled
    require_signing: bool = True

    # Internal state
    _state_machine: NTLMClientStateMachine = attrs.Factory(
        lambda: NTLMClientStateMachine(
            _state=NTLMState.INITIAL,
            _context=NTLMContext(),
        )
    )
    _password: str = attrs.field(default="", repr=False)
    _nt_hash: Optional[bytes] = attrs.field(default=None, repr=False)
    _native_client: Optional[Any] = attrs.field(default=None, repr=False)
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def __attrs_post_init__(self) -> None:
        """Add invariants to state machine and initialize transport."""
        self._state_machine.add_invariant(
            "challenge_before_authenticate",
            self._challenge_before_authenticate,
        )

        # Initialize native client if in native mode
        if self.transport_mode == NTLMTransportMode.NATIVE:
            self._init_native_client()

    def _init_native_client(self) -> None:
        """Initialize native SSPI client for NTLM."""
        available, info = _check_sspi_available()
        if not available:
            self._logger.warning(
                "sspi_unavailable",
                reason=info,
                fallback="simulated",
            )
            object.__setattr__(self, 'transport_mode', NTLMTransportMode.SIMULATED)
            return

        try:
            from authmodeler.transport.native_client import NativeNTLMClient

            self._native_client = NativeNTLMClient()
            self._logger.info(
                "sspi_ntlm_initialized",
                backend=info,
            )
        except Exception as e:
            self._logger.error(
                "sspi_init_failed",
                error=str(e),
            )
            object.__setattr__(self, 'transport_mode', NTLMTransportMode.SIMULATED)

    @staticmethod
    def _challenge_before_authenticate(
        state: NTLMState, ctx: NTLMContext
    ) -> bool:
        """
        Invariant: Must have challenge before authenticating.

        SPEC: specs/alloy/ntlm/properties.als - ChallengeBeforeAuth
        """
        if state in (NTLMState.AUTHENTICATED, NTLMState.CHALLENGE_RECEIVED):
            return ctx.server_challenge is not None
        return True

    @property
    def state(self) -> NTLMState:
        """Current authentication state."""
        return self._state_machine.state

    @property
    def context(self) -> NTLMContext:
        """Current context (read-only)."""
        return self._state_machine.context

    @property
    def session_key(self) -> Optional[bytes]:
        """Session key (available after authentication)."""
        return self.context.session_key

    def create_negotiate_message(
        self,
        domain: str = "",
    ) -> NegotiateMessage:
        """
        Create NTLM NEGOTIATE_MESSAGE (Type 1).

        SPEC: specs/alloy/ntlm/protocol.als - NegotiateMessage
        SPEC: specs/tla/NTLM.tla - SendNegotiate

        Args:
            domain: Optional domain hint

        Returns:
            NegotiateMessage to send to server
        """
        flags = NegotiateFlags.default_client_flags()

        # Ensure signing flags if required (N-GAP-6)
        if self.require_signing:
            flags |= NegotiateFlags.NEGOTIATE_SIGN.value
            flags |= NegotiateFlags.NEGOTIATE_ALWAYS_SIGN.value

        msg = NegotiateMessage(
            negotiate_flags=flags,
            domain_name=domain,
            workstation_name=self.workstation_name,
        )

        # Store negotiate message for MIC computation (N-GAP-2)
        msg_bytes = msg.to_bytes()
        ctx = self.context
        ctx_update = attrs.evolve(
            ctx,
            negotiate_message=msg_bytes,
            expected_channel_bindings=self.channel_bindings,
        )
        self._state_machine._context = ctx_update

        self._logger.debug(
            "created_negotiate_message",
            flags=hex(flags),
            require_signing=self.require_signing,
            require_mic=self.require_mic,
        )

        return msg

    def process_challenge(
        self,
        challenge: ChallengeMessage | bytes,
        raw_challenge_bytes: Optional[bytes] = None,
    ) -> Result[ChallengeMessage, str]:
        """
        Process server's CHALLENGE_MESSAGE (Type 2).

        SPEC: specs/alloy/ntlm/protocol.als - ChallengeMessage
        SPEC: specs/tla/NTLM.tla - ReceiveChallenge

        Args:
            challenge: ChallengeMessage or raw bytes
            raw_challenge_bytes: Original bytes (for MIC computation)

        Returns:
            Success(ChallengeMessage) or Failure(error)
        """
        challenge_bytes_for_mic = raw_challenge_bytes

        if isinstance(challenge, bytes):
            challenge_bytes_for_mic = challenge
            try:
                challenge = ChallengeMessage.from_bytes(challenge)
            except Exception as e:
                return Failure(f"Failed to parse challenge: {e}")

        # Record challenge received time for freshness validation (N-GAP-3)
        # SPEC: specs/tla/NTLM.tla - serverChallengeTime
        challenge_received_time = datetime.now(timezone.utc)

        # Extract server info from target_info
        server_name = challenge.target_name
        dns_domain = ""
        dns_computer = ""
        server_timestamp: Optional[bytes] = None
        server_channel_bindings: Optional[bytes] = None

        if challenge.target_info:
            try:
                av_pairs = parse_av_pairs(challenge.target_info)
                for pair in av_pairs:
                    if pair.av_id == AVPairType.MsvAvDnsDomainName:
                        dns_domain = pair.av_value.decode("utf-16-le")
                    elif pair.av_id == AVPairType.MsvAvDnsComputerName:
                        dns_computer = pair.av_value.decode("utf-16-le")
                    elif pair.av_id == AVPairType.MsvAvTimestamp:
                        # Extract server timestamp for freshness check (N-GAP-3)
                        server_timestamp = pair.av_value
                    elif pair.av_id == AVPairType.MsvAvChannelBindings:
                        # Extract server channel bindings for EPA (N-GAP-1)
                        server_channel_bindings = pair.av_value
            except Exception as e:
                self._logger.warning("av_pair_parse_error", error=str(e))

        # Validate EPA/Channel Bindings if configured (N-GAP-1)
        # SPEC: specs/alloy/ntlm/properties.als - EPAPreventsRelay
        if self.channel_bindings is not None:
            if server_channel_bindings is not None:
                # Server expects channel binding - verify it matches
                expected_hash = self._compute_channel_binding_hash(self.channel_bindings)
                if server_channel_bindings != expected_hash:
                    self._logger.warning(
                        "channel_binding_mismatch",
                        expected=expected_hash.hex(),
                        received=server_channel_bindings.hex(),
                    )
                    return Failure("Channel binding mismatch - possible relay attack (EPA)")

        # Update state machine
        event = ChallengeReceived(
            server_challenge=challenge.server_challenge,
            target_info=challenge.target_info,
            negotiate_flags=challenge.negotiate_flags,
            target_name=server_name,
        )

        # First, ensure we're in NEGOTIATE_SENT state
        if self.state == NTLMState.INITIAL:
            init_event = InitiateNTLM(
                username="",
                domain="",
                password="",
            )
            self._state_machine.process_event(init_event)

        result = self._state_machine.process_event(event)
        if isinstance(result, Failure):
            return Failure(result.failure())

        # Store additional context for security validations
        ctx = self.context
        ctx_update = attrs.evolve(
            ctx,
            challenge_received_time=challenge_received_time,
            server_timestamp=server_timestamp,
            server_channel_bindings=server_channel_bindings,
            expected_channel_bindings=self.channel_bindings,
            challenge_message=challenge_bytes_for_mic or challenge.to_bytes(),
        )
        self._state_machine._context = ctx_update

        self._logger.info(
            "challenge_processed",
            server_name=server_name,
            dns_domain=dns_domain,
            flags=hex(challenge.negotiate_flags),
            has_timestamp=server_timestamp is not None,
            has_channel_bindings=server_channel_bindings is not None,
        )

        return Success(challenge)

    def create_authenticate_message(
        self,
        username: str,
        password: str,
        domain: str = "",
    ) -> Result[AuthenticateMessage, str]:
        """
        Create NTLM AUTHENTICATE_MESSAGE (Type 3).

        SPEC: specs/alloy/ntlm/protocol.als - AuthenticateMessage
        SPEC: specs/tla/NTLM.tla - SendAuthenticate

        Security validations performed:
        - Challenge freshness (N-GAP-3) if require_fresh_challenge=True
        - MIC computation (N-GAP-2) if require_mic=True
        - Signing flags (N-GAP-6) if require_signing=True

        Args:
            username: User name
            password: User password
            domain: Domain name

        Returns:
            Success(AuthenticateMessage) or Failure(error)
        """
        if self.state != NTLMState.CHALLENGE_RECEIVED:
            return Failure(f"Invalid state: {self.state.name}, expected CHALLENGE_RECEIVED")

        ctx = self.context
        if ctx.server_challenge is None:
            return Failure("No server challenge")

        # Validate challenge freshness (N-GAP-3)
        # SPEC: specs/tla/NTLM.tla - ChallengeFresh
        if self.require_fresh_challenge:
            freshness_result = self._validate_challenge_freshness(ctx)
            if isinstance(freshness_result, Failure):
                return freshness_result

        # Validate signing flags (N-GAP-6)
        # SPEC: specs/alloy/ntlm/properties.als - smbSigningEnabled
        if self.require_signing:
            signing_result = self._validate_signing_flags(ctx.negotiate_flags)
            if isinstance(signing_result, Failure):
                return signing_result

        # Store credentials
        self._password = password

        # Compute NT hash
        nt_hash = compute_nt_hash(password)
        self._nt_hash = nt_hash

        # Generate client challenge
        client_challenge = secrets.token_bytes(8)

        # Get timestamp from target_info or generate current
        timestamp = self._get_timestamp_from_target_info(ctx.target_info)
        if timestamp is None:
            timestamp = self._generate_filetime()

        # Build modified target_info for response with security features
        # SPEC: specs/alloy/ntlm/properties.als - TargetInfo modifications
        modified_target_info = self._build_secure_target_info(
            ctx.target_info or b"",
            timestamp,
        )

        # Compute NTLMv2 response with modified target_info
        ntlmv2_response, session_base_key = compute_ntlmv2_response(
            nt_hash=nt_hash,
            username=username,
            domain=domain or ctx.server_name,
            server_challenge=ctx.server_challenge,
            client_challenge=client_challenge,
            timestamp=timestamp,
            target_info=modified_target_info,
        )

        # Generate session key
        # SPEC: specs/alloy/ntlm/protocol.als - SessionKeyDerivation
        session_key = self._derive_session_key(
            session_base_key,
            ctx.negotiate_flags,
        )

        # Encrypt session key if KEY_EXCH negotiated
        if ctx.negotiate_flags & NegotiateFlags.NEGOTIATE_KEY_EXCH.value:
            encrypted_session_key = encrypt_rc4(session_base_key, session_key)
        else:
            encrypted_session_key = b""

        # Build authenticate message (initially with zero MIC)
        authenticate = AuthenticateMessage(
            lm_response=b"\x00" * 24,  # NTLMv2 doesn't use LM response
            nt_response=ntlmv2_response,
            domain_name=domain or ctx.server_name,
            user_name=username,
            workstation_name=self.workstation_name,
            encrypted_session_key=encrypted_session_key,
            negotiate_flags=ctx.negotiate_flags,
            mic=b"\x00" * 16,  # Placeholder for MIC
        )

        # Compute MIC if required (N-GAP-2)
        # SPEC: specs/alloy/ntlm/properties.als - MICIntegrity
        if self.require_mic:
            mic = self._compute_mic(
                session_base_key,
                ctx.negotiate_message,
                ctx.challenge_message,
                authenticate.to_bytes(),
            )
            # Update authenticate message with computed MIC
            authenticate = attrs.evolve(authenticate, mic=mic)

        # Store for later use
        ctx_update = attrs.evolve(
            ctx,
            username=username,
            domain=domain or ctx.server_name,
            client_challenge=client_challenge,
            session_key=session_key,
            session_base_key=session_base_key,
            nt_proof_str=ntlmv2_response[:16],
        )
        self._state_machine._context = ctx_update

        self._logger.info(
            "created_authenticate_message",
            username=username,
            domain=domain or ctx.server_name,
            has_mic=self.require_mic,
            has_channel_binding=self.channel_bindings is not None,
        )

        return Success(authenticate)

    def complete_authentication(
        self,
        success: bool = True,
        error_code: int = 0,
        error_message: str = "",
    ) -> AuthResult:
        """
        Complete authentication after server response.

        Args:
            success: Whether server accepted authentication
            error_code: Error code if failed
            error_message: Error message if failed

        Returns:
            AuthResult with final status
        """
        ctx = self.context

        if success:
            event = AuthenticateComplete(session_key=ctx.session_key or b"")
            self._state_machine.process_event(event)

            self._logger.info(
                "authentication_complete",
                username=ctx.username,
                domain=ctx.domain,
            )

            return AuthResult(
                success=True,
                principal=None,  # NTLM doesn't use Principal in same way
                session_key=ctx.session_key,
            )
        else:
            event = NTLMErrorReceived(
                error_code=error_code,
                error_message=error_message,
            )
            self._state_machine.process_event(event)

            return AuthResult(
                success=False,
                principal=None,
                error_code=error_code,
                error_message=error_message,
            )

    def authenticate(
        self,
        username: str,
        password: str,
        domain: str = "",
        send_receive: Optional[Any] = None,
    ) -> AuthResult:
        """
        Perform complete NTLM authentication.

        When transport_mode is NATIVE (Windows), uses SSPI for real authentication.
        Otherwise, requires a send_receive callback for network I/O.

        Args:
            username: User name
            password: User password
            domain: Domain name
            send_receive: Function to send/receive messages (for simulated mode)

        Returns:
            AuthResult with success/failure
        """
        self._logger.info(
            "authenticate_start",
            username=username,
            domain=domain,
            transport_mode=self.transport_mode.name,
        )

        # Use native SSPI if available
        if self.transport_mode == NTLMTransportMode.NATIVE:
            return self._authenticate_native(username, password, domain)

        # For simulated mode, require send_receive callback
        if send_receive is None:
            return AuthResult(
                success=False,
                principal=None,
                error_message="Network I/O not implemented - use step-by-step methods or native mode",
            )

        # Perform three-step NTLM with callback
        return self._authenticate_with_callback(username, password, domain, send_receive)

    def _authenticate_native(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> AuthResult:
        """
        Authenticate using native SSPI.

        Uses Windows SSPI for real NTLM authentication.
        """
        if self._native_client is None:
            return AuthResult(
                success=False,
                principal=None,
                error_message="Native client not initialized",
            )

        try:
            # Use native NTLM client
            result = self._native_client.authenticate(
                username=username,
                password=password,
                domain=domain,
            )

            if result.success:
                # Update state machine to track authentication
                init_event = InitiateNTLM(
                    username=username,
                    domain=domain,
                    password=password,
                )
                self._state_machine.process_event(init_event)

                # Create synthetic events for state tracking
                challenge_event = ChallengeReceived(
                    server_challenge=b"\x00" * 8,  # Placeholder
                    target_info=None,
                    negotiate_flags=0,
                    target_name=domain,
                )
                self._state_machine.process_event(challenge_event)

                auth_event = AuthenticateComplete(
                    session_key=result.session_key or b"",
                )
                self._state_machine.process_event(auth_event)

                self._logger.info(
                    "native_ntlm_success",
                    username=username,
                    domain=domain,
                )

            return result

        except Exception as e:
            self._logger.error(
                "native_ntlm_error",
                error=str(e),
            )
            return AuthResult(
                success=False,
                principal=None,
                error_message=f"Native NTLM authentication failed: {e}",
            )

    def _authenticate_with_callback(
        self,
        username: str,
        password: str,
        domain: str,
        send_receive: Any,
    ) -> AuthResult:
        """
        Authenticate using callback for network I/O.

        Performs the three NTLM steps using the provided callback.
        """
        try:
            # Step 1: Create and send NEGOTIATE
            negotiate = self.create_negotiate_message(domain)
            negotiate_bytes = negotiate.to_bytes()

            # Send negotiate, receive challenge
            challenge_bytes = send_receive(negotiate_bytes)

            # Step 2: Process CHALLENGE
            challenge_result = self.process_challenge(challenge_bytes)
            if isinstance(challenge_result, Failure):
                return AuthResult(
                    success=False,
                    principal=None,
                    error_message=challenge_result.failure(),
                )

            # Step 3: Create and send AUTHENTICATE
            auth_result = self.create_authenticate_message(username, password, domain)
            if isinstance(auth_result, Failure):
                return AuthResult(
                    success=False,
                    principal=None,
                    error_message=auth_result.failure(),
                )

            authenticate = auth_result.unwrap()
            auth_bytes = authenticate.to_bytes()

            # Send authenticate, receive result
            result_bytes = send_receive(auth_bytes)

            # Check result (depends on protocol - HTTP 200/401, SMB response, etc.)
            # For now, assume empty response means success
            success = len(result_bytes) == 0 or result_bytes[0:4] != b"FAIL"

            return self.complete_authentication(
                success=success,
                error_code=0 if success else 1,
                error_message="" if success else "Authentication rejected",
            )

        except Exception as e:
            self._logger.error(
                "ntlm_authenticate_error",
                error=str(e),
            )
            return AuthResult(
                success=False,
                principal=None,
                error_message=f"NTLM authentication failed: {e}",
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

    def _get_timestamp_from_target_info(
        self, target_info: Optional[bytes]
    ) -> Optional[bytes]:
        """Extract MsvAvTimestamp from target_info."""
        if not target_info:
            return None

        try:
            av_pairs = parse_av_pairs(target_info)
            for pair in av_pairs:
                if pair.av_id == AVPairType.MsvAvTimestamp:
                    return pair.av_value
        except Exception:
            pass

        return None

    def _generate_filetime(self) -> bytes:
        """Generate Windows FILETIME timestamp."""
        # FILETIME is 100-nanosecond intervals since 1601-01-01
        # Python datetime is since 1970-01-01
        # Difference is 116444736000000000 (100-ns intervals)
        epoch_diff = 116444736000000000

        now = datetime.now(timezone.utc)
        # Convert to 100-ns intervals since Unix epoch
        unix_100ns = int(now.timestamp() * 10000000)
        # Add epoch difference
        filetime = unix_100ns + epoch_diff

        return struct.pack("<Q", filetime)

    def _derive_session_key(
        self,
        session_base_key: bytes,
        flags: int,
    ) -> bytes:
        """
        Derive session key from base key.

        SPEC: specs/alloy/ntlm/protocol.als - SessionKeyDerivation
        """
        if flags & NegotiateFlags.NEGOTIATE_KEY_EXCH.value:
            # Generate random session key
            return secrets.token_bytes(16)
        else:
            return session_base_key

    # =========================================================================
    # SECURITY VALIDATION METHODS (N-GAP fixes)
    # =========================================================================

    def _validate_challenge_freshness(
        self,
        ctx: NTLMContext,
    ) -> Result[None, str]:
        """
        Validate challenge freshness (N-GAP-3).

        SPEC: specs/tla/NTLM.tla - ChallengeFresh, ChallengeValidityWindow

        Checks that the challenge was received within the validity window.
        """
        if ctx.challenge_received_time is None:
            self._logger.warning("challenge_freshness_no_timestamp")
            # Allow if no timestamp tracking (backwards compatibility)
            return Success(None)

        now = datetime.now(timezone.utc)
        elapsed = (now - ctx.challenge_received_time).total_seconds()

        if elapsed > self.challenge_validity_seconds:
            self._logger.warning(
                "challenge_stale",
                elapsed_seconds=elapsed,
                max_seconds=self.challenge_validity_seconds,
            )
            return Failure(
                f"Challenge is stale: {elapsed:.1f}s elapsed "
                f"(max: {self.challenge_validity_seconds}s)"
            )

        self._logger.debug(
            "challenge_fresh",
            elapsed_seconds=elapsed,
        )
        return Success(None)

    def _validate_signing_flags(
        self,
        flags: int,
    ) -> Result[None, str]:
        """
        Validate SMB signing flags are negotiated (N-GAP-6).

        SPEC: specs/alloy/ntlm/properties.als - smbSigningEnabled
        """
        sign_flag = NegotiateFlags.NEGOTIATE_SIGN.value
        always_sign_flag = NegotiateFlags.NEGOTIATE_ALWAYS_SIGN.value

        if not (flags & sign_flag):
            self._logger.warning("signing_not_negotiated", flags=hex(flags))
            return Failure("NEGOTIATE_SIGN not set - signing not available")

        if not (flags & always_sign_flag):
            self._logger.warning("always_sign_not_negotiated", flags=hex(flags))
            # Warning only - ALWAYS_SIGN is optional but recommended
            self._logger.info("signing_available_but_always_sign_not_set")

        return Success(None)

    def _build_secure_target_info(
        self,
        original_target_info: bytes,
        timestamp: bytes,
    ) -> bytes:
        """
        Build modified target_info with security features.

        SPEC: specs/alloy/ntlm/properties.als - TargetInfo

        Adds:
        - MsvAvFlags with MIC_PROVIDED (N-GAP-2)
        - MsvAvChannelBindings for EPA (N-GAP-1)
        - MsvAvTimestamp if not present
        """
        # Parse existing AV pairs
        av_pairs: List[AVPair] = []
        has_timestamp = False
        has_flags = False
        has_channel_bindings = False

        if original_target_info:
            try:
                av_pairs = parse_av_pairs(original_target_info)
                # Remove EOL - we'll add it at the end
                av_pairs = [p for p in av_pairs if p.av_id != AVPairType.MsvAvEOL]

                for pair in av_pairs:
                    if pair.av_id == AVPairType.MsvAvTimestamp:
                        has_timestamp = True
                    elif pair.av_id == AVPairType.MsvAvFlags:
                        has_flags = True
                    elif pair.av_id == AVPairType.MsvAvChannelBindings:
                        has_channel_bindings = True
            except Exception as e:
                self._logger.warning("parse_target_info_error", error=str(e))

        # Add MsvAvTimestamp if not present
        if not has_timestamp:
            av_pairs.append(AVPair(
                av_id=AVPairType.MsvAvTimestamp,
                av_len=8,
                av_value=timestamp,
            ))

        # Add/update MsvAvFlags with MIC_PROVIDED (N-GAP-2)
        if self.require_mic:
            flags_value = MsvAvFlagsValue.MIC_PROVIDED.value
            if has_flags:
                # Update existing flags
                av_pairs = [
                    p if p.av_id != AVPairType.MsvAvFlags
                    else AVPair(
                        av_id=AVPairType.MsvAvFlags,
                        av_len=4,
                        av_value=struct.pack("<I",
                            int.from_bytes(p.av_value, "little") | flags_value
                        ),
                    )
                    for p in av_pairs
                ]
            else:
                av_pairs.append(AVPair(
                    av_id=AVPairType.MsvAvFlags,
                    av_len=4,
                    av_value=struct.pack("<I", flags_value),
                ))

        # Add MsvAvChannelBindings for EPA (N-GAP-1)
        if self.channel_bindings is not None and not has_channel_bindings:
            channel_binding_hash = self._compute_channel_binding_hash(
                self.channel_bindings
            )
            av_pairs.append(AVPair(
                av_id=AVPairType.MsvAvChannelBindings,
                av_len=16,
                av_value=channel_binding_hash,
            ))

        # Add EOL terminator
        av_pairs.append(AVPair(
            av_id=AVPairType.MsvAvEOL,
            av_len=0,
            av_value=b"",
        ))

        return build_av_pairs(av_pairs)

    def _compute_channel_binding_hash(
        self,
        channel_bindings: bytes,
    ) -> bytes:
        """
        Compute MD5 hash for channel bindings (EPA).

        SPEC: specs/alloy/ntlm/properties.als - MsvAvChannelBindings

        The channel bindings structure is hashed with MD5.

        Args:
            channel_bindings: Raw TLS channel binding data
                             (typically tls-server-end-point binding)

        Returns:
            16-byte MD5 hash of the channel bindings
        """
        # Per MS-NLMP, channel bindings are MD5 hashed
        return hashlib.md5(channel_bindings).digest()

    def _compute_mic(
        self,
        session_base_key: bytes,
        negotiate_msg: Optional[bytes],
        challenge_msg: Optional[bytes],
        authenticate_msg: bytes,
    ) -> bytes:
        """
        Compute Message Integrity Code (MIC) for NTLM messages (N-GAP-2).

        SPEC: specs/alloy/ntlm/properties.als - MICIntegrity

        MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)

        The MIC binds all three messages together, preventing tampering.
        """
        # Concatenate all three messages
        msg_data = b""
        if negotiate_msg:
            msg_data += negotiate_msg
        if challenge_msg:
            msg_data += challenge_msg
        msg_data += authenticate_msg

        # Compute HMAC-MD5 using session base key
        mic = hmac_md5(session_base_key, msg_data)

        self._logger.debug(
            "computed_mic",
            negotiate_len=len(negotiate_msg) if negotiate_msg else 0,
            challenge_len=len(challenge_msg) if challenge_msg else 0,
            authenticate_len=len(authenticate_msg),
        )

        return mic

    def sign_message(
        self,
        message: bytes,
        sequence_number: int = 0,
    ) -> bytes:
        """
        Sign a message using the session key (N-GAP-6).

        SPEC: specs/alloy/ntlm/properties.als - smbSigningEnabled

        Creates a signature for the message that can be verified by the server.

        Args:
            message: Message to sign
            sequence_number: Message sequence number

        Returns:
            Signature bytes (16 bytes)
        """
        ctx = self.context
        if ctx.session_key is None:
            raise NTLMError("No session key available for signing")

        # Per MS-NLMP, signature is HMAC_MD5(SigningKey, SeqNum || Message)
        seq_bytes = struct.pack("<I", sequence_number)
        data = seq_bytes + message
        signature = hmac_md5(ctx.session_key, data)

        return signature

    def verify_signature(
        self,
        message: bytes,
        signature: bytes,
        sequence_number: int = 0,
    ) -> bool:
        """
        Verify a message signature (N-GAP-6).

        Args:
            message: Original message
            signature: Signature to verify
            sequence_number: Expected sequence number

        Returns:
            True if signature is valid
        """
        expected_sig = self.sign_message(message, sequence_number)
        return secrets.compare_digest(expected_sig, signature)


# =============================================================================
# CHANNEL BINDING HELPER FUNCTIONS
# =============================================================================


def compute_channel_bindings(
    server_certificate: bytes,
) -> bytes:
    """
    Compute TLS channel bindings from server certificate.

    SPEC: RFC 5929 - Channel Bindings for TLS
    SPEC: specs/alloy/ntlm/properties.als - MsvAvChannelBindings

    This creates the 'tls-server-end-point' channel binding value
    used for EPA (Extended Protection for Authentication).

    Args:
        server_certificate: DER-encoded server certificate

    Returns:
        Channel binding structure suitable for NTLM EPA

    Example:
        # Get certificate from SSL socket
        cert_der = ssl_socket.getpeercert(binary_form=True)
        channel_bindings = compute_channel_bindings(cert_der)

        # Use with NTLM client
        client = NTLMClient(channel_bindings=channel_bindings)
    """
    # Per RFC 5929, tls-server-end-point binding is the hash of the
    # server certificate using the hash algorithm from the certificate
    # signature algorithm. For simplicity, we use SHA-256 which is
    # most common in modern TLS.
    cert_hash = hashlib.sha256(server_certificate).digest()

    # Build GSS_C_NO_CHANNEL_BINDINGS / SEC_CHANNEL_BINDINGS structure
    # This is the format expected by SSPI/GSSAPI
    # struct {
    #     uint32 initiator_addrtype = 0;
    #     uint32 initiator_address_length = 0;
    #     uint32 acceptor_addrtype = 0;
    #     uint32 acceptor_address_length = 0;
    #     uint32 application_data_length;
    #     uint8 application_data[];  // "tls-server-end-point:" + hash
    # }

    # Application data format: "tls-server-end-point:" + cert_hash
    app_data = b"tls-server-end-point:" + cert_hash

    # Build the channel bindings structure
    cb_struct = (
        struct.pack("<I", 0)  # initiator_addrtype
        + struct.pack("<I", 0)  # initiator_address_length
        + struct.pack("<I", 0)  # acceptor_addrtype
        + struct.pack("<I", 0)  # acceptor_address_length
        + struct.pack("<I", len(app_data))  # application_data_length
        + app_data
    )

    return cb_struct


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_ntlm_client(
    workstation_name: str = "",
    use_native: bool = False,
    channel_bindings: Optional[bytes] = None,
    require_fresh_challenge: bool = True,
    require_mic: bool = True,
    require_signing: bool = True,
) -> NTLMClient:
    """
    Create an NTLM client with security mitigations.

    Args:
        workstation_name: Optional workstation name
        use_native: Use native SSPI on Windows (requires Windows)
        channel_bindings: TLS channel bindings for EPA (N-GAP-1)
        require_fresh_challenge: Validate challenge freshness (N-GAP-3)
        require_mic: Compute/verify MIC (N-GAP-2)
        require_signing: Require SMB signing (N-GAP-6)

    Returns:
        Configured NTLMClient with security features enabled

    Example:
        # Basic client (simulated mode)
        client = create_ntlm_client()

        # Secure client with EPA
        cert_der = ssl_socket.getpeercert(binary_form=True)
        channel_bindings = compute_channel_bindings(cert_der)
        client = create_ntlm_client(
            channel_bindings=channel_bindings,
            require_mic=True,
            require_signing=True,
        )

        # Native mode (Windows only)
        client = create_ntlm_client(use_native=True)
    """
    return NTLMClient(
        workstation_name=workstation_name,
        transport_mode=NTLMTransportMode.NATIVE if use_native else NTLMTransportMode.SIMULATED,
        channel_bindings=channel_bindings,
        require_fresh_challenge=require_fresh_challenge,
        require_mic=require_mic,
        require_signing=require_signing,
    )


def is_sspi_available() -> Tuple[bool, str]:
    """
    Check if native SSPI is available for NTLM.

    Returns:
        Tuple of (available, info)
        - available: True if SSPI is available (Windows)
        - info: "SSPI" or error message
    """
    return _check_sspi_available()
