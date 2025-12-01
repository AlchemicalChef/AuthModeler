"""
AuthModeler Native Client

Unified interface for native Kerberos/NTLM authentication using
GSSAPI (Unix/Linux/macOS) or SSPI (Windows).

SPEC: specs/alloy/kerberos/protocol.als
SPEC: specs/alloy/ntlm/protocol.als

This module provides platform-independent authentication by
automatically selecting the appropriate native library.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Union

import attrs
import structlog

from authmodeler.core.types import AuthResult, Principal, Realm, Protocol
from authmodeler.core.exceptions import AuthenticationError

from authmodeler.transport.gssapi_wrapper import (
    GSSAPIContext,
    GSSAPICredentials,
    gssapi_available,
)
from authmodeler.transport.sspi_wrapper import (
    SSPIContext,
    SSPICredentials,
    SSPIPackage,
    sspi_available,
)

logger = structlog.get_logger()


# =============================================================================
# PLATFORM DETECTION
# =============================================================================


class NativeBackend(Enum):
    """Native authentication backend."""
    GSSAPI = auto()   # Unix/Linux/macOS
    SSPI = auto()     # Windows
    NONE = auto()     # No native support


def get_available_backend() -> NativeBackend:
    """
    Detect the available native authentication backend.

    Returns:
        NativeBackend enum indicating which library is available
    """
    if sys.platform == "win32" and sspi_available():
        return NativeBackend.SSPI
    elif gssapi_available():
        return NativeBackend.GSSAPI
    return NativeBackend.NONE


def is_native_available() -> bool:
    """Check if any native authentication backend is available."""
    return get_available_backend() != NativeBackend.NONE


# Alias for backwards compatibility
detect_native_backend = get_available_backend


# =============================================================================
# NATIVE KERBEROS CLIENT
# =============================================================================


@attrs.define
class NativeKerberosClient:
    """
    Native Kerberos client using GSSAPI or SSPI.

    SPEC: specs/alloy/kerberos/protocol.als
    SPEC: specs/tla/Kerberos.tla

    This class provides platform-independent Kerberos authentication
    by automatically using GSSAPI on Unix-like systems and SSPI on Windows.

    Features:
    - TGT acquisition via kinit/password
    - Service ticket acquisition
    - Mutual authentication
    - Message protection (signing/encryption)
    - Credential caching

    Example:
        client = NativeKerberosClient(realm="EXAMPLE.COM")

        # Authenticate with password
        result = client.authenticate("user", "password")

        if result.success:
            # Get GSSAPI/SSPI token for service
            token = client.get_service_token("HTTP/server.example.com")

            # Send token to server...
    """

    realm: str
    kdc_host: Optional[str] = None

    _backend: NativeBackend = attrs.Factory(get_available_backend)
    _credentials: Any = None
    _context: Any = None
    _authenticated: bool = False

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def __attrs_post_init__(self) -> None:
        """Verify native library is available."""
        if self._backend == NativeBackend.NONE:
            self._logger.warning(
                "native_backend_not_available",
                message="No native authentication library available. "
                        "Install gssapi (Unix) or pywin32 (Windows).",
            )

    @property
    def backend(self) -> NativeBackend:
        """Get the native backend being used."""
        return self._backend

    @property
    def is_authenticated(self) -> bool:
        """Check if client has valid credentials."""
        return self._authenticated and self._credentials is not None

    def authenticate(
        self,
        username: str,
        password: str,
        domain: Optional[str] = None,
    ) -> AuthResult:
        """
        Authenticate and acquire TGT.

        SPEC: specs/alloy/kerberos/protocol.als - ASExchange

        Args:
            username: User name
            password: User password
            domain: Domain/realm (uses client realm if not specified)

        Returns:
            AuthResult with success/failure
        """
        domain = domain or self.realm

        self._logger.info(
            "native_authenticate_start",
            username=username,
            domain=domain,
            backend=self._backend.name,
        )

        try:
            if self._backend == NativeBackend.SSPI:
                return self._authenticate_sspi(username, password, domain)
            elif self._backend == NativeBackend.GSSAPI:
                return self._authenticate_gssapi(username, password, domain)
            else:
                return AuthResult(
                    success=False,
                    principal=None,
                    error_message="No native authentication backend available",
                )

        except Exception as e:
            self._logger.error(
                "native_authenticate_failed",
                error=str(e),
            )
            return AuthResult(
                success=False,
                principal=Principal(name=username, realm=Realm(domain)),
                error_message=str(e),
            )

    def _authenticate_sspi(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> AuthResult:
        """Authenticate using SSPI."""
        try:
            # Acquire credentials with password
            self._credentials = SSPICredentials.acquire_with_password(
                username=username,
                password=password,
                domain=domain,
                package=SSPIPackage.KERBEROS,
            )

            self._authenticated = True

            self._logger.info(
                "sspi_authenticate_success",
                username=username,
                domain=domain,
            )

            return AuthResult(
                success=True,
                principal=Principal(name=username, realm=Realm(domain)),
                expiration=self._credentials.expiry,
            )

        except Exception as e:
            raise AuthenticationError(f"SSPI authentication failed: {e}") from e

    def _authenticate_gssapi(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> AuthResult:
        """Authenticate using GSSAPI."""
        try:
            # Acquire credentials with password
            self._credentials = GSSAPICredentials.acquire_with_password(
                username=username,
                password=password,
                realm=domain,
            )

            self._authenticated = True

            # Get expiry
            expiry = None
            if self._credentials.lifetime:
                expiry = datetime.now(timezone.utc) + timedelta(
                    seconds=self._credentials.lifetime
                )

            self._logger.info(
                "gssapi_authenticate_success",
                principal=self._credentials.name,
            )

            return AuthResult(
                success=True,
                principal=Principal(name=username, realm=Realm(domain)),
                expiration=expiry,
            )

        except Exception as e:
            raise AuthenticationError(f"GSSAPI authentication failed: {e}") from e

    def authenticate_from_cache(self) -> AuthResult:
        """
        Use existing credentials from system cache.

        On Windows: Uses logged-in user's credentials
        On Unix: Uses default credential cache (kinit)

        Returns:
            AuthResult with cached credential info
        """
        self._logger.info(
            "native_authenticate_from_cache",
            backend=self._backend.name,
        )

        try:
            if self._backend == NativeBackend.SSPI:
                self._credentials = SSPICredentials.acquire_current_user(
                    package=SSPIPackage.KERBEROS,
                )
                self._authenticated = True

                return AuthResult(
                    success=True,
                    principal=None,  # Current user
                    expiration=self._credentials.expiry,
                )

            elif self._backend == NativeBackend.GSSAPI:
                self._credentials = GSSAPICredentials.from_ccache()
                self._authenticated = self._credentials.is_valid

                if not self._authenticated:
                    return AuthResult(
                        success=False,
                        principal=None,
                        error_message="No valid credentials in cache. Run kinit first.",
                    )

                expiry = None
                if self._credentials.lifetime:
                    expiry = datetime.now(timezone.utc) + timedelta(
                        seconds=self._credentials.lifetime
                    )

                return AuthResult(
                    success=True,
                    principal=Principal(
                        name=self._credentials.name.split("@")[0] if self._credentials.name else "",
                        realm=Realm(self._credentials.name.split("@")[1] if self._credentials.name and "@" in self._credentials.name else self.realm),
                    ),
                    expiration=expiry,
                )

            else:
                return AuthResult(
                    success=False,
                    principal=None,
                    error_message="No native backend available",
                )

        except Exception as e:
            return AuthResult(
                success=False,
                principal=None,
                error_message=str(e),
            )

    def get_service_token(
        self,
        service_name: str,
        mutual_auth: bool = True,
    ) -> Optional[bytes]:
        """
        Get an authentication token for a service.

        SPEC: specs/alloy/kerberos/protocol.als - APRequest

        This generates the token to send to a service for authentication.
        The service name should be in SPN format: service/hostname

        Args:
            service_name: Service principal name (e.g., "HTTP/server.example.com")
            mutual_auth: Request mutual authentication

        Returns:
            Token bytes to send to service, or None on error
        """
        if not self._authenticated:
            self._logger.error("not_authenticated", message="Must authenticate first")
            return None

        self._logger.debug(
            "get_service_token",
            service=service_name,
            mutual_auth=mutual_auth,
        )

        try:
            if self._backend == NativeBackend.SSPI:
                ctx = SSPIContext.create_client(
                    target_name=service_name,
                    package=SSPIPackage.KERBEROS,
                )
                token = ctx.step(None)
                self._context = ctx
                return token

            elif self._backend == NativeBackend.GSSAPI:
                ctx = GSSAPIContext.create_client(
                    target_name=service_name,
                    credentials=self._credentials.credentials if self._credentials else None,
                )
                token = ctx.step(None)
                self._context = ctx
                return token

            return None

        except Exception as e:
            self._logger.error(
                "get_service_token_failed",
                service=service_name,
                error=str(e),
            )
            return None

    def process_service_response(
        self,
        response_token: bytes,
    ) -> bool:
        """
        Process service response for mutual authentication.

        SPEC: specs/alloy/kerberos/protocol.als - APReply

        Args:
            response_token: Token received from service

        Returns:
            True if mutual authentication succeeded
        """
        if not self._context:
            return False

        try:
            result = self._context.step(response_token)

            if self._context.is_complete:
                self._logger.info(
                    "mutual_auth_complete",
                    target=self._context.target_name,
                )
                return True

            return False

        except Exception as e:
            self._logger.error(
                "mutual_auth_failed",
                error=str(e),
            )
            return False

    def wrap_message(self, data: bytes, encrypt: bool = True) -> bytes:
        """
        Wrap (sign and optionally encrypt) a message.

        Args:
            data: Plaintext data
            encrypt: Whether to encrypt

        Returns:
            Wrapped message
        """
        if not self._context or not self._context.is_complete:
            raise RuntimeError("Security context not established")

        return self._context.wrap(data, encrypt)

    def unwrap_message(self, data: bytes) -> Tuple[bytes, bool, bool]:
        """
        Unwrap a message.

        Args:
            data: Wrapped message

        Returns:
            Tuple of (plaintext, was_encrypted, was_signed)
        """
        if not self._context or not self._context.is_complete:
            raise RuntimeError("Security context not established")

        return self._context.unwrap(data)


# =============================================================================
# NATIVE NTLM CLIENT
# =============================================================================


@attrs.define
class NativeNTLMClient:
    """
    Native NTLM client using SSPI (Windows only).

    SPEC: specs/alloy/ntlm/protocol.als
    SPEC: specs/tla/NTLM.tla

    Note: NTLM is only natively available on Windows via SSPI.
    On Unix systems, use the pure Python NTLMClient.

    WARNING: NTLM has known security vulnerabilities:
    - Pass-the-hash attacks
    - Relay attacks
    Use Kerberos when possible.
    """

    _credentials: Any = None
    _context: Any = None
    _authenticated: bool = False

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @property
    def is_available(self) -> bool:
        """Check if native NTLM is available."""
        return sspi_available

    def create_negotiate_message(
        self,
        target_name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Optional[bytes]:
        """
        Create NTLM NEGOTIATE message.

        Args:
            target_name: Target service name (optional)
            username: Username for explicit credentials
            password: Password for explicit credentials
            domain: Domain for explicit credentials

        Returns:
            NEGOTIATE message bytes
        """
        if not sspi_available:
            self._logger.error(
                "sspi_not_available",
                message="Native NTLM requires Windows and pywin32",
            )
            return None

        self._logger.warning(
            "ntlm_security_warning",
            message="NTLM is vulnerable to pass-the-hash and relay attacks",
        )

        try:
            self._context = SSPIContext.create_client(
                target_name=target_name or "",
                package=SSPIPackage.NTLM,
                username=username,
                domain=domain,
                password=password,
            )

            token = self._context.step(None)
            return token

        except Exception as e:
            self._logger.error("ntlm_negotiate_failed", error=str(e))
            return None

    def process_challenge(
        self,
        challenge_token: bytes,
    ) -> Optional[bytes]:
        """
        Process CHALLENGE and generate AUTHENTICATE message.

        Args:
            challenge_token: CHALLENGE message from server

        Returns:
            AUTHENTICATE message bytes
        """
        if not self._context:
            return None

        try:
            token = self._context.step(challenge_token)

            if self._context.is_complete:
                self._authenticated = True
                self._logger.info("ntlm_auth_complete")

            return token

        except Exception as e:
            self._logger.error("ntlm_challenge_failed", error=str(e))
            return None

    @property
    def is_complete(self) -> bool:
        """Check if authentication is complete."""
        return self._authenticated


# =============================================================================
# UNIFIED NATIVE CLIENT
# =============================================================================


@attrs.define
class NativeAuthClient:
    """
    Unified native authentication client.

    Automatically selects Kerberos or NTLM based on availability
    and server requirements.

    Example:
        client = NativeAuthClient(domain="EXAMPLE.COM")

        # Try Kerberos first, fall back to NTLM
        result = client.authenticate(
            username="user",
            password="password",
            prefer_kerberos=True,
        )

        if result.success:
            # Get token for service
            token = client.get_token_for_service("HTTP/server.example.com")
    """

    domain: str
    kdc_host: Optional[str] = None

    _kerberos_client: Optional[NativeKerberosClient] = None
    _ntlm_client: Optional[NativeNTLMClient] = None
    _active_protocol: Optional[Protocol] = None

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def __attrs_post_init__(self) -> None:
        """Initialize clients."""
        backend = get_available_backend()

        if backend != NativeBackend.NONE:
            self._kerberos_client = NativeKerberosClient(
                realm=self.domain,
                kdc_host=self.kdc_host,
            )

        if backend == NativeBackend.SSPI:
            self._ntlm_client = NativeNTLMClient()

    @property
    def backend(self) -> NativeBackend:
        """Get the native backend."""
        return get_available_backend()

    @property
    def active_protocol(self) -> Optional[Protocol]:
        """Get the protocol used for current session."""
        return self._active_protocol

    def authenticate(
        self,
        username: str,
        password: str,
        prefer_kerberos: bool = True,
    ) -> AuthResult:
        """
        Authenticate using native libraries.

        Args:
            username: User name
            password: Password
            prefer_kerberos: Try Kerberos first (recommended)

        Returns:
            AuthResult
        """
        if prefer_kerberos and self._kerberos_client:
            result = self._kerberos_client.authenticate(
                username, password, self.domain
            )

            if result.success:
                self._active_protocol = Protocol.KERBEROS
                return result

            self._logger.info(
                "kerberos_failed_trying_ntlm",
                error=result.error_message,
            )

        # Try NTLM
        if self._ntlm_client and self._ntlm_client.is_available:
            self._active_protocol = Protocol.NTLM
            # NTLM requires challenge-response, can't just authenticate
            return AuthResult(
                success=False,
                principal=None,
                error_message="NTLM requires challenge-response flow. Use create_negotiate_message().",
            )

        return AuthResult(
            success=False,
            principal=None,
            error_message="No authentication method available",
        )

    def authenticate_from_cache(self) -> AuthResult:
        """
        Authenticate using cached credentials.

        Returns:
            AuthResult
        """
        if self._kerberos_client:
            result = self._kerberos_client.authenticate_from_cache()
            if result.success:
                self._active_protocol = Protocol.KERBEROS
                return result

        return AuthResult(
            success=False,
            principal=None,
            error_message="No cached credentials available",
        )

    def get_token_for_service(
        self,
        service_name: str,
    ) -> Optional[bytes]:
        """
        Get authentication token for a service.

        Args:
            service_name: Service principal name

        Returns:
            Token bytes
        """
        if self._active_protocol == Protocol.KERBEROS and self._kerberos_client:
            return self._kerberos_client.get_service_token(service_name)

        return None


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_native_client(
    domain: str,
    kdc_host: Optional[str] = None,
) -> NativeAuthClient:
    """
    Create a native authentication client.

    Args:
        domain: AD domain name
        kdc_host: Optional KDC hostname

    Returns:
        Configured NativeAuthClient
    """
    return NativeAuthClient(
        domain=domain,
        kdc_host=kdc_host,
    )


def validate_credentials_native(
    username: str,
    password: str,
    domain: str,
) -> bool:
    """
    Validate credentials using native libraries.

    This is a quick way to check if credentials are valid
    without establishing a full session.

    Args:
        username: User name
        password: Password
        domain: Domain name

    Returns:
        True if credentials are valid
    """
    backend = get_available_backend()

    if backend == NativeBackend.SSPI:
        from authmodeler.transport.sspi_wrapper import logon_user
        return logon_user(username, domain, password)

    elif backend == NativeBackend.GSSAPI:
        try:
            creds = GSSAPICredentials.acquire_with_password(
                username, password, domain
            )
            return creds.is_valid
        except Exception:
            return False

    return False
