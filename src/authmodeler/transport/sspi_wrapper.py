"""
AuthModeler SSPI Wrapper

Integration with Windows SSPI (Security Support Provider Interface)
for native Kerberos and NTLM authentication on Windows systems.

SPEC: specs/alloy/kerberos/protocol.als
SPEC: specs/alloy/ntlm/protocol.als

SSPI provides:
- Native Windows credential management
- Kerberos and NTLM support
- Integrated Windows Authentication (IWA)
- Token impersonation

Requirements:
- Windows operating system
- pywin32 package (pip install pywin32)
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from enum import Enum, Flag, auto
from typing import Any, Dict, List, Optional, Tuple, Union

import attrs
import structlog

from authmodeler.core.types import AuthResult, Principal, Realm
from authmodeler.core.exceptions import AuthenticationError

logger = structlog.get_logger()

# Check if SSPI is available (Windows only)
_sspi_available = False
_sspi_error: Optional[str] = None
sspi = None
sspicon = None
win32security = None

if sys.platform == "win32":
    try:
        import sspi as sspi_module
        import sspicon as sspicon_module
        import win32security as win32security_module

        sspi = sspi_module
        sspicon = sspicon_module
        win32security = win32security_module
        _sspi_available = True
    except ImportError as e:
        _sspi_error = str(e)
        logger.warning(
            "sspi_not_available",
            message="Install pywin32 package for native Windows authentication: pip install pywin32"
        )
else:
    _sspi_error = "SSPI is only available on Windows"


def sspi_available() -> bool:
    """Check if SSPI is available."""
    return _sspi_available


# =============================================================================
# SSPI FLAGS AND TYPES
# =============================================================================


class SSPIPackage(Enum):
    """SSPI security packages."""
    NEGOTIATE = "Negotiate"  # SPNEGO - tries Kerberos, falls back to NTLM
    KERBEROS = "Kerberos"    # Kerberos only
    NTLM = "NTLM"            # NTLM only


class SSPIFlags(Flag):
    """SSPI context requirement flags."""
    MUTUAL_AUTH = auto()      # Mutual authentication
    REPLAY_DETECT = auto()    # Replay detection
    SEQUENCE_DETECT = auto()  # Sequence checking
    CONFIDENTIALITY = auto()  # Encryption
    INTEGRITY = auto()        # Signing
    DELEGATE = auto()         # Credential delegation
    CONNECTION = auto()       # Connection-oriented
    USE_SUPPLIED_CREDS = auto()  # Use supplied credentials


# =============================================================================
# SSPI CONTEXT
# =============================================================================


@attrs.define
class SSPIContext:
    """
    SSPI security context for Windows authentication.

    SPEC: specs/alloy/kerberos/protocol.als - APExchange
    SPEC: specs/alloy/ntlm/protocol.als - NTLMAuthentication

    This class wraps the Windows SSPI API to provide native
    Kerberos and NTLM authentication.

    Example (client-side):
        ctx = SSPIContext.create_client(
            target_name="HTTP/server.example.com",
            package=SSPIPackage.NEGOTIATE,
        )

        # Initial token to send to server
        token = ctx.step(None)

        # Process server response
        while ctx.requires_more:
            # Send token to server, receive response
            server_response = send_to_server(token)
            token = ctx.step(server_response)

        if ctx.is_complete:
            # Wrap data for server
            encrypted = ctx.wrap(plaintext_data)

    Example (server-side):
        ctx = SSPIContext.create_server(
            package=SSPIPackage.NEGOTIATE,
        )

        # Process client token
        response = ctx.step(client_token)

        if ctx.is_complete:
            print(f"Client: {ctx.client_name}")
    """

    _target_name: str = ""
    _package: SSPIPackage = SSPIPackage.NEGOTIATE
    _is_initiator: bool = True
    _sspi_auth: Any = None
    _complete: bool = False
    _flags: int = 0
    _username: Optional[str] = None
    _domain: Optional[str] = None
    _password: Optional[str] = attrs.field(default=None, repr=False)

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @classmethod
    def create_client(
        cls,
        target_name: str,
        package: SSPIPackage = SSPIPackage.NEGOTIATE,
        flags: Optional[SSPIFlags] = None,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        password: Optional[str] = None,
    ) -> "SSPIContext":
        """
        Create a client-side SSPI context.

        SPEC: specs/alloy/kerberos/protocol.als - APRequest

        Args:
            target_name: Service principal name (e.g., "HTTP/server.example.com")
            package: SSPI package to use
            flags: Context flags
            username: Username for explicit credentials (None for current user)
            domain: Domain for explicit credentials
            password: Password for explicit credentials

        Returns:
            SSPIContext configured for client authentication
        """
        if not _sspi_available:
            raise ImportError(
                "SSPI not available. This requires Windows and pywin32: pip install pywin32"
            )

        ctx = cls(
            _target_name=target_name,
            _package=package,
            _is_initiator=True,
            _username=username,
            _domain=domain,
            _password=password,
        )

        # Set default flags
        if flags is None:
            ctx._flags = (
                sspicon.ISC_REQ_MUTUAL_AUTH
                | sspicon.ISC_REQ_REPLAY_DETECT
                | sspicon.ISC_REQ_SEQUENCE_DETECT
                | sspicon.ISC_REQ_CONFIDENTIALITY
                | sspicon.ISC_REQ_INTEGRITY
                | sspicon.ISC_REQ_CONNECTION
            )
        else:
            ctx._flags = cls._convert_flags(flags, is_client=True)

        ctx._logger.debug(
            "sspi_client_context_created",
            target=target_name,
            package=package.value,
        )

        return ctx

    @classmethod
    def create_server(
        cls,
        package: SSPIPackage = SSPIPackage.NEGOTIATE,
        flags: Optional[SSPIFlags] = None,
    ) -> "SSPIContext":
        """
        Create a server-side SSPI context.

        SPEC: specs/alloy/kerberos/protocol.als - APReply

        Args:
            package: SSPI package to use
            flags: Context flags

        Returns:
            SSPIContext configured for server authentication
        """
        if not _sspi_available:
            raise ImportError(
                "SSPI not available. This requires Windows and pywin32: pip install pywin32"
            )

        ctx = cls(
            _package=package,
            _is_initiator=False,
        )

        # Set default flags for server
        if flags is None:
            ctx._flags = (
                sspicon.ASC_REQ_MUTUAL_AUTH
                | sspicon.ASC_REQ_REPLAY_DETECT
                | sspicon.ASC_REQ_SEQUENCE_DETECT
                | sspicon.ASC_REQ_CONFIDENTIALITY
                | sspicon.ASC_REQ_INTEGRITY
                | sspicon.ASC_REQ_CONNECTION
            )
        else:
            ctx._flags = cls._convert_flags(flags, is_client=False)

        ctx._logger.debug(
            "sspi_server_context_created",
            package=package.value,
        )

        return ctx

    def step(self, in_token: Optional[bytes] = None) -> Optional[bytes]:
        """
        Perform one step of the SSPI handshake.

        For clients:
        - First call with in_token=None generates initial token
        - Subsequent calls process server responses

        For servers:
        - Each call processes client token and generates response

        Args:
            in_token: Token received from peer (None for initial client call)

        Returns:
            Token to send to peer, or None if complete
        """
        if not _sspi_available:
            raise ImportError("SSPI not available")

        try:
            if self._is_initiator:
                return self._client_step(in_token)
            else:
                return self._server_step(in_token)
        except Exception as e:
            self._logger.error(
                "sspi_step_failed",
                error=str(e),
            )
            raise AuthenticationError(f"SSPI error: {e}") from e

    def _client_step(self, in_token: Optional[bytes]) -> Optional[bytes]:
        """Client-side step implementation."""
        if self._sspi_auth is None:
            # Initialize client auth
            if self._username and self._password:
                # Use explicit credentials
                self._sspi_auth = sspi.ClientAuth(
                    self._package.value,
                    targetspn=self._target_name,
                    auth_info=(self._username, self._domain, self._password),
                    scflags=self._flags,
                )
            else:
                # Use current user credentials
                self._sspi_auth = sspi.ClientAuth(
                    self._package.value,
                    targetspn=self._target_name,
                    scflags=self._flags,
                )

        # Perform authorization step
        err, out_buf = self._sspi_auth.authorize(in_token)

        # Check completion
        if err == 0:  # SEC_E_OK
            self._complete = True

        # Extract output token
        out_token = None
        if out_buf and len(out_buf) > 0:
            out_token = out_buf[0].Buffer

        self._logger.debug(
            "sspi_client_step",
            complete=self._complete,
            has_output=out_token is not None,
            err=err,
        )

        return out_token

    def _server_step(self, in_token: Optional[bytes]) -> Optional[bytes]:
        """Server-side step implementation."""
        if in_token is None:
            raise ValueError("Server requires input token")

        if self._sspi_auth is None:
            # Initialize server auth
            self._sspi_auth = sspi.ServerAuth(
                self._package.value,
                scflags=self._flags,
            )

        # Perform authorization step
        err, out_buf = self._sspi_auth.authorize(in_token)

        # Check completion
        if err == 0:  # SEC_E_OK
            self._complete = True

        # Extract output token
        out_token = None
        if out_buf and len(out_buf) > 0:
            out_token = out_buf[0].Buffer

        self._logger.debug(
            "sspi_server_step",
            complete=self._complete,
            has_output=out_token is not None,
            err=err,
        )

        return out_token

    @property
    def is_complete(self) -> bool:
        """Check if context establishment is complete."""
        return self._complete

    @property
    def requires_more(self) -> bool:
        """Check if more steps are required."""
        return not self._complete

    @property
    def client_name(self) -> Optional[str]:
        """Get client principal name (server-side only)."""
        if not self._complete or self._is_initiator:
            return None

        try:
            if self._sspi_auth and hasattr(self._sspi_auth, 'ctxt'):
                names = win32security.QueryContextAttributes(
                    self._sspi_auth.ctxt,
                    sspicon.SECPKG_ATTR_NAMES,
                )
                return names
        except Exception:
            pass

        return None

    @property
    def package_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the negotiated package."""
        if not self._complete:
            return None

        try:
            if self._sspi_auth and hasattr(self._sspi_auth, 'ctxt'):
                info = win32security.QueryContextAttributes(
                    self._sspi_auth.ctxt,
                    sspicon.SECPKG_ATTR_NEGOTIATION_INFO,
                )
                return {
                    "package": info[0].Name if info else None,
                }
        except Exception:
            pass

        return {"package": self._package.value}

    def wrap(self, data: bytes, encrypt: bool = True) -> bytes:
        """
        Wrap (sign and optionally encrypt) a message.

        Args:
            data: Plaintext data to wrap
            encrypt: Whether to encrypt (True) or just sign (False)

        Returns:
            Wrapped message bytes
        """
        if not self._complete:
            raise RuntimeError("Context not established")

        if not self._sspi_auth:
            raise RuntimeError("No SSPI context")

        try:
            # Encrypt the message
            err, buffers = self._sspi_auth.encrypt(data)
            if err != 0:
                raise AuthenticationError(f"SSPI encrypt failed: {err}")

            # Combine signature and data
            result = b""
            for buf in buffers:
                if buf.Buffer:
                    result += buf.Buffer

            return result

        except Exception as e:
            raise AuthenticationError(f"SSPI wrap failed: {e}") from e

    def unwrap(self, data: bytes) -> Tuple[bytes, bool, bool]:
        """
        Unwrap (verify and optionally decrypt) a message.

        Args:
            data: Wrapped message bytes

        Returns:
            Tuple of (plaintext, was_encrypted, was_signed)
        """
        if not self._complete:
            raise RuntimeError("Context not established")

        if not self._sspi_auth:
            raise RuntimeError("No SSPI context")

        try:
            # Decrypt the message
            err, plaintext = self._sspi_auth.decrypt(data)
            if err != 0:
                raise AuthenticationError(f"SSPI decrypt failed: {err}")

            return (plaintext, True, True)

        except Exception as e:
            raise AuthenticationError(f"SSPI unwrap failed: {e}") from e

    def sign(self, data: bytes) -> bytes:
        """
        Sign a message (generate signature).

        Args:
            data: Data to sign

        Returns:
            Signature bytes
        """
        if not self._complete:
            raise RuntimeError("Context not established")

        if not self._sspi_auth:
            raise RuntimeError("No SSPI context")

        try:
            err, buffers = self._sspi_auth.sign(data)
            if err != 0:
                raise AuthenticationError(f"SSPI sign failed: {err}")

            # Extract signature
            for buf in buffers:
                if buf.BufferType == sspicon.SECBUFFER_TOKEN:
                    return buf.Buffer

            return b""

        except Exception as e:
            raise AuthenticationError(f"SSPI sign failed: {e}") from e

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verify a message signature.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            True if valid
        """
        if not self._complete:
            raise RuntimeError("Context not established")

        if not self._sspi_auth:
            raise RuntimeError("No SSPI context")

        try:
            err = self._sspi_auth.verify(data, signature)
            return err == 0

        except Exception:
            return False

    def impersonate(self) -> None:
        """
        Impersonate the client (server-side only).

        After calling this, the current thread runs in the
        security context of the authenticated client.
        """
        if not self._complete or self._is_initiator:
            raise RuntimeError("Can only impersonate on server after auth")

        if self._sspi_auth and hasattr(self._sspi_auth, 'ctxt'):
            win32security.ImpersonateSecurityContext(self._sspi_auth.ctxt)
            self._logger.info("sspi_impersonating_client")

    def revert_impersonation(self) -> None:
        """Revert to original security context."""
        if self._sspi_auth and hasattr(self._sspi_auth, 'ctxt'):
            win32security.RevertSecurityContext(self._sspi_auth.ctxt)
            self._logger.info("sspi_reverted_impersonation")

    @staticmethod
    def _convert_flags(flags: SSPIFlags, is_client: bool) -> int:
        """Convert SSPIFlags to SSPI flag values."""
        result = 0

        if is_client:
            if SSPIFlags.MUTUAL_AUTH in flags:
                result |= sspicon.ISC_REQ_MUTUAL_AUTH
            if SSPIFlags.REPLAY_DETECT in flags:
                result |= sspicon.ISC_REQ_REPLAY_DETECT
            if SSPIFlags.SEQUENCE_DETECT in flags:
                result |= sspicon.ISC_REQ_SEQUENCE_DETECT
            if SSPIFlags.CONFIDENTIALITY in flags:
                result |= sspicon.ISC_REQ_CONFIDENTIALITY
            if SSPIFlags.INTEGRITY in flags:
                result |= sspicon.ISC_REQ_INTEGRITY
            if SSPIFlags.DELEGATE in flags:
                result |= sspicon.ISC_REQ_DELEGATE
            if SSPIFlags.CONNECTION in flags:
                result |= sspicon.ISC_REQ_CONNECTION
            if SSPIFlags.USE_SUPPLIED_CREDS in flags:
                result |= sspicon.ISC_REQ_USE_SUPPLIED_CREDS
        else:
            if SSPIFlags.MUTUAL_AUTH in flags:
                result |= sspicon.ASC_REQ_MUTUAL_AUTH
            if SSPIFlags.REPLAY_DETECT in flags:
                result |= sspicon.ASC_REQ_REPLAY_DETECT
            if SSPIFlags.SEQUENCE_DETECT in flags:
                result |= sspicon.ASC_REQ_SEQUENCE_DETECT
            if SSPIFlags.CONFIDENTIALITY in flags:
                result |= sspicon.ASC_REQ_CONFIDENTIALITY
            if SSPIFlags.INTEGRITY in flags:
                result |= sspicon.ASC_REQ_INTEGRITY
            if SSPIFlags.DELEGATE in flags:
                result |= sspicon.ASC_REQ_DELEGATE
            if SSPIFlags.CONNECTION in flags:
                result |= sspicon.ASC_REQ_CONNECTION

        return result


# =============================================================================
# CREDENTIAL MANAGEMENT
# =============================================================================


@attrs.define
class SSPICredentials:
    """
    SSPI credential handle management.

    Handles acquiring and managing Windows credentials for
    Kerberos and NTLM authentication.
    """

    _handle: Any = None
    _package: SSPIPackage = SSPIPackage.NEGOTIATE
    _username: Optional[str] = None
    _domain: Optional[str] = None
    _expiry: Optional[datetime] = None
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @classmethod
    def acquire_current_user(
        cls,
        package: SSPIPackage = SSPIPackage.NEGOTIATE,
    ) -> "SSPICredentials":
        """
        Acquire credentials for the current logged-in user.

        Args:
            package: SSPI package to use

        Returns:
            SSPICredentials for current user
        """
        if not _sspi_available:
            raise ImportError("SSPI not available")

        handle, expiry = win32security.AcquireCredentialsHandle(
            None,  # Principal (None = current user)
            package.value,
            sspicon.SECPKG_CRED_OUTBOUND,
            None,  # LogonID
            None,  # AuthData
        )

        result = cls(
            _handle=handle,
            _package=package,
            _expiry=datetime.fromtimestamp(expiry, tz=timezone.utc) if expiry else None,
        )

        result._logger.info(
            "sspi_creds_acquired_current_user",
            package=package.value,
        )

        return result

    @classmethod
    def acquire_with_password(
        cls,
        username: str,
        password: str,
        domain: Optional[str] = None,
        package: SSPIPackage = SSPIPackage.NEGOTIATE,
    ) -> "SSPICredentials":
        """
        Acquire credentials using username/password.

        Args:
            username: User name
            password: User password
            domain: Domain name (optional)
            package: SSPI package to use

        Returns:
            SSPICredentials with specified credentials
        """
        if not _sspi_available:
            raise ImportError("SSPI not available")

        # Build auth identity
        auth_info = (username, domain or "", password)

        handle, expiry = win32security.AcquireCredentialsHandle(
            None,  # Principal
            package.value,
            sspicon.SECPKG_CRED_OUTBOUND,
            None,  # LogonID
            auth_info,
        )

        result = cls(
            _handle=handle,
            _package=package,
            _username=username,
            _domain=domain,
            _expiry=datetime.fromtimestamp(expiry, tz=timezone.utc) if expiry else None,
        )

        result._logger.info(
            "sspi_creds_acquired_password",
            username=username,
            domain=domain,
            package=package.value,
        )

        return result

    @property
    def handle(self) -> Any:
        """Get underlying credential handle."""
        return self._handle

    @property
    def package(self) -> SSPIPackage:
        """Get SSPI package."""
        return self._package

    @property
    def username(self) -> Optional[str]:
        """Get username."""
        return self._username

    @property
    def domain(self) -> Optional[str]:
        """Get domain."""
        return self._domain

    @property
    def expiry(self) -> Optional[datetime]:
        """Get credential expiry time."""
        return self._expiry

    @property
    def is_valid(self) -> bool:
        """Check if credentials are still valid."""
        if self._expiry is None:
            return True
        return datetime.now(timezone.utc) < self._expiry


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_current_username() -> Optional[str]:
    """
    Get the current Windows username.

    Returns:
        Username in DOMAIN\\user format
    """
    if not _sspi_available:
        return None

    try:
        import win32api
        return win32api.GetUserNameEx(win32api.NameSamCompatible)
    except Exception:
        pass

    return None


def get_current_domain() -> Optional[str]:
    """
    Get the current Windows domain.

    Returns:
        Domain name
    """
    if not _sspi_available:
        return None

    try:
        import win32api
        full_name = win32api.GetUserNameEx(win32api.NameSamCompatible)
        if "\\" in full_name:
            return full_name.split("\\")[0]
    except Exception:
        pass

    return None


def list_security_packages() -> List[Dict[str, Any]]:
    """
    List available SSPI security packages.

    Returns:
        List of package information dicts
    """
    if not _sspi_available:
        return []

    results = []

    try:
        packages = win32security.EnumerateSecurityPackages()
        for pkg in packages:
            results.append({
                "name": pkg["Name"],
                "comment": pkg.get("Comment", ""),
                "capabilities": pkg.get("fCapabilities", 0),
                "max_token": pkg.get("cbMaxToken", 0),
            })
    except Exception:
        pass

    return results


def logon_user(
    username: str,
    domain: str,
    password: str,
    logon_type: int = 3,  # LOGON32_LOGON_NETWORK
) -> bool:
    """
    Validate credentials by attempting a logon.

    Args:
        username: User name
        domain: Domain name
        password: Password
        logon_type: Logon type (default: network logon)

    Returns:
        True if credentials are valid
    """
    if not _sspi_available:
        return False

    try:
        handle = win32security.LogonUser(
            username,
            domain,
            password,
            logon_type,
            0,  # LOGON32_PROVIDER_DEFAULT
        )
        # Close handle
        handle.Close()
        return True
    except Exception:
        return False
