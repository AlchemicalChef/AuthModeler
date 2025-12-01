"""
AuthModeler Active Directory Authenticator

High-level interface for Active Directory authentication supporting
both Kerberos V5 and NTLMv2 protocols.

SPEC: specs/alloy/kerberos/protocol.als
SPEC: specs/alloy/ntlm/protocol.als
SPEC: specs/tla/Kerberos.tla
SPEC: specs/tla/NTLM.tla

Protocol Selection:
1. Kerberos is preferred (stronger security)
2. NTLM is fallback (legacy compatibility)
3. SPNEGO/Negotiate handles automatic selection

Security Considerations:
- Kerberos provides mutual authentication
- NTLM vulnerable to pass-the-hash and relay attacks
- Always prefer Kerberos when available

Native Support:
- GSSAPI: Unix/Linux/macOS Kerberos
- SSPI: Windows Kerberos and NTLM
- Auto-detected based on platform
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

import attrs
import structlog
from returns.result import Failure, Result, Success

from authmodeler.core.types import AuthResult, Protocol, Principal, Realm
from authmodeler.core.exceptions import AuthenticationError
from authmodeler.kerberos.client import KerberosClient, TransportMode
from authmodeler.ntlm.client import NTLMClient, NTLMTransportMode

logger = structlog.get_logger()


# =============================================================================
# CONFIGURATION
# =============================================================================


@attrs.define
class ADConfig:
    """
    Active Directory configuration.

    Attributes:
        domain: AD domain name (e.g., "EXAMPLE.COM")
        dc_host: Domain controller hostname
        kdc_port: Kerberos KDC port (default 88)
        ldap_port: LDAP port (default 389)
        ldaps_port: LDAPS port (default 636)
        preferred_protocol: Preferred authentication protocol
        allow_ntlm_fallback: Allow NTLM if Kerberos fails
        verify_server_cert: Verify LDAPS certificate
        use_native: Use native GSSAPI/SSPI for real AD authentication
    """

    domain: str
    dc_host: str = ""
    kdc_port: int = 88
    ldap_port: int = 389
    ldaps_port: int = 636
    preferred_protocol: Protocol = Protocol.KERBEROS
    allow_ntlm_fallback: bool = True
    verify_server_cert: bool = True
    use_native: bool = False

    @property
    def realm(self) -> Realm:
        """Get Kerberos realm (uppercase domain)."""
        return Realm(self.domain.upper())

    @classmethod
    def from_domain(cls, domain: str, use_native: bool = False) -> "ADConfig":
        """
        Create config from domain name.

        Attempts to discover DC via DNS SRV records.

        Args:
            domain: AD domain name
            use_native: Use native GSSAPI/SSPI libraries
        """
        # In production, would use DNS SRV lookup:
        # _ldap._tcp.dc._msdcs.{domain}
        # _kerberos._tcp.{domain}
        return cls(domain=domain, use_native=use_native)


# =============================================================================
# AD AUTHENTICATOR
# =============================================================================


class AuthState(Enum):
    """Authentication state for AD authenticator."""

    INITIAL = auto()
    KERBEROS_ATTEMPTED = auto()
    NTLM_ATTEMPTED = auto()
    AUTHENTICATED = auto()
    FAILED = auto()


@attrs.define
class ADAuthenticator:
    """
    High-level Active Directory authenticator.

    SPEC: Combines Kerberos and NTLM specifications

    Provides:
    - Automatic protocol selection (Kerberos preferred)
    - NTLM fallback for legacy systems
    - Unified authentication interface
    - Native GSSAPI/SSPI support for real AD
    - Trace export for verification

    Transport Modes:
    - Simulated (default): Mock responses for testing/verification
    - Native: Real AD authentication via GSSAPI/SSPI

    Example (simulated):
        config = ADConfig(
            domain="EXAMPLE.COM",
            dc_host="dc.example.com",
        )
        auth = ADAuthenticator(config)
        result = auth.authenticate("jdoe", "password")

    Example (native - real AD):
        config = ADConfig(
            domain="EXAMPLE.COM",
            use_native=True,
        )
        auth = ADAuthenticator(config)
        result = auth.authenticate("jdoe", "password")
        if result.success:
            print(f"Authenticated as {result.principal}")
            print(f"Session expires: {result.expiration}")
    """

    config: ADConfig

    # Protocol clients (created on demand)
    _kerberos_client: Optional[KerberosClient] = None
    _ntlm_client: Optional[NTLMClient] = None

    # State tracking
    _state: AuthState = AuthState.INITIAL
    _last_protocol: Optional[Protocol] = None
    _auth_traces: List[Dict[str, Any]] = attrs.Factory(list)

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @property
    def kerberos_client(self) -> KerberosClient:
        """Get or create Kerberos client."""
        if self._kerberos_client is None:
            transport_mode = (
                TransportMode.NATIVE if self.config.use_native
                else TransportMode.SIMULATED
            )
            self._kerberos_client = KerberosClient(
                realm=self.config.realm,
                kdc_host=self.config.dc_host,
                kdc_port=self.config.kdc_port,
                transport_mode=transport_mode,
            )
        return self._kerberos_client

    @property
    def ntlm_client(self) -> NTLMClient:
        """Get or create NTLM client."""
        if self._ntlm_client is None:
            transport_mode = (
                NTLMTransportMode.NATIVE if self.config.use_native
                else NTLMTransportMode.SIMULATED
            )
            self._ntlm_client = NTLMClient(
                transport_mode=transport_mode,
            )
        return self._ntlm_client

    @property
    def is_native_mode(self) -> bool:
        """Check if authenticator is using native libraries."""
        return self.config.use_native

    def authenticate(
        self,
        username: str,
        password: str,
        domain: Optional[str] = None,
        protocol: Optional[Protocol] = None,
    ) -> AuthResult:
        """
        Authenticate user against Active Directory.

        SPEC: specs/alloy/kerberos/protocol.als - ASExchange
        SPEC: specs/alloy/ntlm/protocol.als - NTLMAuthentication

        When use_native is True, uses GSSAPI (Unix) or SSPI (Windows)
        for real Active Directory authentication.

        Protocol selection:
        1. If protocol specified, use that protocol
        2. Otherwise, try Kerberos first
        3. If Kerberos fails and allow_ntlm_fallback, try NTLM

        Args:
            username: User name (e.g., "jdoe")
            password: User password
            domain: Override domain (uses config domain if not specified)
            protocol: Force specific protocol

        Returns:
            AuthResult with success/failure and session info
        """
        domain = domain or self.config.domain
        protocol = protocol or self.config.preferred_protocol

        self._logger.info(
            "authenticate_start",
            username=username,
            domain=domain,
            protocol=protocol.name,
            native_mode=self.config.use_native,
        )

        # Try preferred protocol
        if protocol == Protocol.KERBEROS:
            result = self._authenticate_kerberos(username, password, domain)
            self._state = AuthState.KERBEROS_ATTEMPTED
            self._last_protocol = Protocol.KERBEROS

            if result.success:
                self._state = AuthState.AUTHENTICATED
                self._record_trace("kerberos", True)
                return result

            # Try NTLM fallback if enabled
            if self.config.allow_ntlm_fallback:
                self._logger.info(
                    "kerberos_failed_trying_ntlm",
                    kerberos_error=result.error_message,
                )
                result = self._authenticate_ntlm(username, password, domain)
                self._state = AuthState.NTLM_ATTEMPTED
                self._last_protocol = Protocol.NTLM

                if result.success:
                    self._state = AuthState.AUTHENTICATED
                    self._record_trace("ntlm", True)
                else:
                    self._state = AuthState.FAILED
                    self._record_trace("ntlm", False)
                return result

            self._state = AuthState.FAILED
            self._record_trace("kerberos", False)
            return result

        elif protocol == Protocol.NTLM:
            result = self._authenticate_ntlm(username, password, domain)
            self._state = AuthState.NTLM_ATTEMPTED
            self._last_protocol = Protocol.NTLM

            if result.success:
                self._state = AuthState.AUTHENTICATED
                self._record_trace("ntlm", True)
            else:
                self._state = AuthState.FAILED
                self._record_trace("ntlm", False)
            return result

        elif protocol == Protocol.NEGOTIATE:
            # SPNEGO: Try Kerberos, fall back to NTLM
            return self.authenticate(
                username,
                password,
                domain,
                protocol=Protocol.KERBEROS,
            )

        else:
            return AuthResult(
                success=False,
                principal=None,
                error_message=f"Unknown protocol: {protocol}",
            )

    def _authenticate_kerberos(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> AuthResult:
        """
        Authenticate using Kerberos.

        SPEC: specs/alloy/kerberos/protocol.als - ASExchange
        SPEC: specs/tla/Kerberos.tla
        """
        self._logger.debug(
            "kerberos_authenticate",
            username=username,
            domain=domain,
        )

        try:
            result = self.kerberos_client.authenticate(
                username=username,
                password=password,
                domain=domain,
            )

            # Collect trace
            if self._kerberos_client:
                self._auth_traces.extend(self.kerberos_client.get_trace())

            return result

        except Exception as e:
            self._logger.error(
                "kerberos_authenticate_error",
                error=str(e),
            )
            return AuthResult(
                success=False,
                principal=Principal(name=username, realm=Realm(domain)),
                error_message=f"Kerberos authentication failed: {e}",
            )

    def _authenticate_ntlm(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> AuthResult:
        """
        Authenticate using NTLM.

        SPEC: specs/alloy/ntlm/protocol.als - NTLMAuthentication
        SPEC: specs/tla/NTLM.tla

        When native mode is enabled (Windows), uses SSPI for real NTLM.

        WARNING: NTLM has known security vulnerabilities.
        """
        self._logger.debug(
            "ntlm_authenticate",
            username=username,
            domain=domain,
            native_mode=self.config.use_native,
        )
        self._logger.warning(
            "ntlm_security_warning",
            message="NTLM authentication used - vulnerable to pass-the-hash and relay attacks",
        )

        try:
            # In native mode, use SSPI directly
            if self.config.use_native:
                result = self.ntlm_client.authenticate(
                    username=username,
                    password=password,
                    domain=domain,
                )

                # Collect trace
                self._auth_traces.extend(self.ntlm_client.get_trace())

                return result

            # For simulated mode, step-by-step process
            # Step 1: Create NEGOTIATE message
            negotiate = self.ntlm_client.create_negotiate_message(domain)

            # In a real implementation, we would:
            # 1. Send NEGOTIATE to server
            # 2. Receive CHALLENGE
            # 3. Process challenge
            # 4. Create and send AUTHENTICATE
            # 5. Receive result

            # Collect trace
            self._auth_traces.extend(self.ntlm_client.get_trace())

            # Return result indicating manual steps required
            return AuthResult(
                success=False,
                principal=None,
                error_message="NTLM simulated mode requires manual message exchange - use native mode for real AD",
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

    def get_service_ticket(
        self,
        service_name: str,
    ) -> Result[Tuple[bytes, Any, Any], str]:
        """
        Get a Kerberos service ticket.

        Requires prior successful Kerberos authentication.

        SPEC: specs/alloy/kerberos/protocol.als - TGSExchange

        Args:
            service_name: Service principal (e.g., "http/server.example.com")

        Returns:
            Success((ticket, session_key, ticket_info)) or Failure(error)
        """
        if self._last_protocol != Protocol.KERBEROS:
            return Failure("Service tickets require Kerberos authentication")

        if not self.kerberos_client.has_valid_tgt:
            return Failure("No valid TGT - authenticate first")

        return self.kerberos_client.get_service_ticket(service_name)

    def validate_credentials(
        self,
        username: str,
        password: str,
        domain: Optional[str] = None,
    ) -> bool:
        """
        Validate credentials without establishing a session.

        Args:
            username: User name
            password: User password
            domain: Domain name

        Returns:
            True if credentials are valid
        """
        result = self.authenticate(username, password, domain)
        return result.success

    def get_traces(self) -> List[Dict[str, Any]]:
        """
        Get all authentication traces.

        Returns traces from both Kerberos and NTLM for verification.
        """
        traces = list(self._auth_traces)

        if self._kerberos_client:
            traces.extend(self.kerberos_client.get_trace())

        if self._ntlm_client:
            traces.extend(self.ntlm_client.get_trace())

        return traces

    def export_traces_json(self) -> str:
        """Export all traces as JSON for verification tools."""
        import json

        return json.dumps(
            {
                "ad_authenticator": {
                    "state": self._state.name,
                    "last_protocol": self._last_protocol.name if self._last_protocol else None,
                    "config": {
                        "domain": self.config.domain,
                        "preferred_protocol": self.config.preferred_protocol.name,
                        "allow_ntlm_fallback": self.config.allow_ntlm_fallback,
                    },
                },
                "kerberos_trace": (
                    self.kerberos_client.get_trace()
                    if self._kerberos_client
                    else []
                ),
                "ntlm_trace": (
                    self.ntlm_client.get_trace()
                    if self._ntlm_client
                    else []
                ),
                "auth_events": self._auth_traces,
            },
            indent=2,
            default=str,
        )

    def _record_trace(self, protocol: str, success: bool) -> None:
        """Record authentication attempt in trace."""
        self._auth_traces.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": protocol,
            "success": success,
            "state": self._state.name,
        })


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_ad_authenticator(
    domain: str,
    dc_host: str = "",
    prefer_kerberos: bool = True,
    allow_ntlm: bool = True,
    use_native: bool = False,
) -> ADAuthenticator:
    """
    Create an AD authenticator.

    Args:
        domain: AD domain name
        dc_host: Domain controller hostname (optional, uses DNS if empty)
        prefer_kerberos: Prefer Kerberos over NTLM
        allow_ntlm: Allow NTLM fallback
        use_native: Use native GSSAPI/SSPI for real AD authentication

    Returns:
        Configured ADAuthenticator

    Example:
        # Simulated mode (for testing/verification)
        auth = create_ad_authenticator("EXAMPLE.COM")

        # Native mode (for real AD authentication)
        auth = create_ad_authenticator("EXAMPLE.COM", use_native=True)
        result = auth.authenticate("jdoe", "password")
    """
    config = ADConfig(
        domain=domain,
        dc_host=dc_host,
        preferred_protocol=Protocol.KERBEROS if prefer_kerberos else Protocol.NTLM,
        allow_ntlm_fallback=allow_ntlm,
        use_native=use_native,
    )

    return ADAuthenticator(config=config)


def is_native_available() -> Dict[str, Tuple[bool, str]]:
    """
    Check if native authentication backends are available.

    Returns:
        Dict with availability status for each backend:
        - "kerberos": (available, backend_info) - GSSAPI or SSPI
        - "ntlm": (available, backend_info) - SSPI only
    """
    from authmodeler.kerberos.client import is_native_available as kerberos_available
    from authmodeler.ntlm.client import is_sspi_available as ntlm_available

    return {
        "kerberos": kerberos_available(),
        "ntlm": ntlm_available(),
    }
