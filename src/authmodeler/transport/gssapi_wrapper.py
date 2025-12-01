"""
AuthModeler GSSAPI Wrapper

Integration with the GSSAPI library for native Kerberos authentication
on Unix/Linux/macOS systems.

SPEC: specs/alloy/kerberos/protocol.als
SPEC: specs/tla/Kerberos.tla

GSSAPI provides:
- Native Kerberos credential management
- Ticket cache integration (ccache)
- Keytab support for services
- Mutual authentication
- Message protection (signing/encryption)

Requirements:
- gssapi Python package (pip install gssapi)
- MIT Kerberos or Heimdal libraries installed
- Valid krb5.conf configuration
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from enum import Enum, Flag, auto
from typing import Any, Dict, List, Optional, Tuple, Union

import attrs
import structlog

from authmodeler.core.types import AuthResult, Principal, Realm, SessionKey, EncryptionType
from authmodeler.core.exceptions import AuthenticationError, KerberosError

logger = structlog.get_logger()

# Check if GSSAPI is available
try:
    import gssapi
    from gssapi import raw as gssapi_raw
    from gssapi.raw import misc as gssapi_misc
    _gssapi_available = True
    _gssapi_error = None
except ImportError as e:
    gssapi = None  # type: ignore
    gssapi_raw = None  # type: ignore
    gssapi_misc = None  # type: ignore
    _gssapi_available = False
    _gssapi_error = str(e)
    logger.warning("gssapi_not_available", message="Install gssapi package for native Kerberos support")
except OSError as e:
    # GSSAPI installed but underlying library not available (e.g., MIT Kerberos on Windows)
    gssapi = None  # type: ignore
    gssapi_raw = None  # type: ignore
    gssapi_misc = None  # type: ignore
    _gssapi_available = False
    _gssapi_error = str(e)
    logger.warning("gssapi_library_error", message=str(e))


def gssapi_available() -> bool:
    """Check if GSSAPI is available."""
    return _gssapi_available


# =============================================================================
# GSSAPI FLAGS AND TYPES
# =============================================================================


class GSSAPIFlags(Flag):
    """GSSAPI context flags."""
    DELEG = auto()       # Credential delegation
    MUTUAL = auto()      # Mutual authentication
    REPLAY = auto()      # Replay detection
    SEQUENCE = auto()    # Sequence checking
    CONF = auto()        # Confidentiality (encryption)
    INTEG = auto()       # Integrity (signing)
    ANON = auto()        # Anonymous authentication


class CredentialUsage(Enum):
    """GSSAPI credential usage."""
    INITIATE = "initiate"  # Client credentials
    ACCEPT = "accept"      # Server credentials
    BOTH = "both"          # Both client and server


# =============================================================================
# GSSAPI CONTEXT
# =============================================================================


@attrs.define
class GSSAPIContext:
    """
    GSSAPI security context for Kerberos authentication.

    SPEC: specs/alloy/kerberos/protocol.als - APExchange
    SPEC: specs/tla/Kerberos.tla - AP_Request, AP_Reply

    This class wraps the GSSAPI library to provide native Kerberos
    authentication with proper credential and ticket management.

    Example (client-side):
        ctx = GSSAPIContext.create_client(
            target_name="HTTP/server.example.com",
            credentials=None,  # Use default ccache
        )

        # Initial token to send to server
        token = ctx.step(None)

        # Process server response (if mutual auth)
        if ctx.requires_more:
            ctx.step(server_response)

        if ctx.is_complete:
            # Wrap data for server
            encrypted = ctx.wrap(plaintext_data)

    Example (server-side):
        ctx = GSSAPIContext.create_server(
            credentials=server_creds,  # From keytab
        )

        # Process client token
        response = ctx.step(client_token)

        if ctx.is_complete:
            print(f"Client: {ctx.initiator_name}")
    """

    _name: str = ""
    _is_initiator: bool = True
    _gss_ctx: Any = None
    _gss_cred: Any = None
    _gss_name: Any = None
    _complete: bool = False
    _flags: int = 0
    _lifetime: Optional[int] = None
    _mech_type: Optional[bytes] = None

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @classmethod
    def create_client(
        cls,
        target_name: str,
        credentials: Optional[Any] = None,
        flags: Optional[GSSAPIFlags] = None,
        lifetime: Optional[int] = None,
        mech: Optional[str] = None,
    ) -> "GSSAPIContext":
        """
        Create a client-side GSSAPI context.

        SPEC: specs/alloy/kerberos/protocol.als - APRequest

        Args:
            target_name: Service principal name (e.g., "HTTP/server.example.com")
            credentials: GSSAPI credentials (None for default ccache)
            flags: Context flags (default: MUTUAL | REPLAY | SEQUENCE | CONF | INTEG)
            lifetime: Requested context lifetime in seconds
            mech: Mechanism OID (default: Kerberos)

        Returns:
            GSSAPIContext configured for client authentication
        """
        if not _gssapi_available:
            raise ImportError("GSSAPI library not available. Install with: pip install gssapi")

        ctx = cls(
            _name=target_name,
            _is_initiator=True,
        )

        # Parse target name
        ctx._gss_name = gssapi.Name(
            target_name,
            name_type=gssapi.NameType.hostbased_service,
        )

        # Set default flags
        if flags is None:
            ctx._flags = (
                gssapi.RequirementFlag.mutual_authentication
                | gssapi.RequirementFlag.replay_detection
                | gssapi.RequirementFlag.out_of_sequence_detection
                | gssapi.RequirementFlag.confidentiality
                | gssapi.RequirementFlag.integrity
            )
        else:
            ctx._flags = cls._convert_flags(flags)

        ctx._gss_cred = credentials
        ctx._lifetime = lifetime

        # Determine mechanism
        if mech:
            ctx._mech_type = gssapi.OID.from_int_seq([1, 2, 840, 113554, 1, 2, 2])  # Kerberos
        else:
            ctx._mech_type = None  # Default to Kerberos

        ctx._logger.debug(
            "gssapi_client_context_created",
            target=target_name,
            flags=ctx._flags,
        )

        return ctx

    @classmethod
    def create_server(
        cls,
        credentials: Optional[Any] = None,
        service_name: Optional[str] = None,
    ) -> "GSSAPIContext":
        """
        Create a server-side GSSAPI context.

        SPEC: specs/alloy/kerberos/protocol.als - APReply

        Args:
            credentials: Server credentials (from keytab)
            service_name: Service principal name (if credentials not provided)

        Returns:
            GSSAPIContext configured for server authentication
        """
        if not _gssapi_available:
            raise ImportError("GSSAPI library not available. Install with: pip install gssapi")

        ctx = cls(
            _name=service_name or "",
            _is_initiator=False,
        )

        # Get or acquire server credentials
        if credentials:
            ctx._gss_cred = credentials
        elif service_name:
            name = gssapi.Name(
                service_name,
                name_type=gssapi.NameType.hostbased_service,
            )
            ctx._gss_cred = gssapi.Credentials(
                name=name,
                usage="accept",
            )
        else:
            # Use default from keytab
            ctx._gss_cred = None

        ctx._logger.debug(
            "gssapi_server_context_created",
            service=service_name,
        )

        return ctx

    def step(self, in_token: Optional[bytes] = None) -> Optional[bytes]:
        """
        Perform one step of the GSSAPI handshake.

        SPEC: specs/tla/Kerberos.tla - AP_Request, AP_Reply

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
        if not _gssapi_available:
            raise ImportError("GSSAPI library not available")

        try:
            if self._is_initiator:
                return self._client_step(in_token)
            else:
                return self._server_step(in_token)
        except gssapi.exceptions.GSSError as e:
            self._logger.error(
                "gssapi_step_failed",
                error=str(e),
                major=e.maj_status if hasattr(e, 'maj_status') else None,
                minor=e.min_status if hasattr(e, 'min_status') else None,
            )
            raise AuthenticationError(f"GSSAPI error: {e}") from e

    def _client_step(self, in_token: Optional[bytes]) -> Optional[bytes]:
        """Client-side step implementation."""
        if self._gss_ctx is None:
            # Initialize security context
            self._gss_ctx = gssapi.SecurityContext(
                name=self._gss_name,
                creds=self._gss_cred,
                flags=self._flags,
                lifetime=self._lifetime,
                mech=self._mech_type,
                usage="initiate",
            )

        # Perform step
        out_token = self._gss_ctx.step(in_token)

        # Check if complete
        self._complete = self._gss_ctx.complete

        self._logger.debug(
            "gssapi_client_step",
            complete=self._complete,
            has_output=out_token is not None,
        )

        return out_token

    def _server_step(self, in_token: Optional[bytes]) -> Optional[bytes]:
        """Server-side step implementation."""
        if in_token is None:
            raise ValueError("Server requires input token")

        if self._gss_ctx is None:
            # Initialize security context for accept
            self._gss_ctx = gssapi.SecurityContext(
                creds=self._gss_cred,
                usage="accept",
            )

        # Perform step
        out_token = self._gss_ctx.step(in_token)

        # Check if complete
        self._complete = self._gss_ctx.complete

        self._logger.debug(
            "gssapi_server_step",
            complete=self._complete,
            has_output=out_token is not None,
            initiator=str(self._gss_ctx.initiator_name) if self._complete else None,
        )

        return out_token

    @property
    def is_complete(self) -> bool:
        """Check if context establishment is complete."""
        return self._complete

    @property
    def requires_more(self) -> bool:
        """Check if more steps are required."""
        if self._gss_ctx is None:
            return True
        return not self._complete

    @property
    def initiator_name(self) -> Optional[str]:
        """Get initiator (client) principal name."""
        if self._gss_ctx and self._complete:
            return str(self._gss_ctx.initiator_name)
        return None

    @property
    def target_name(self) -> Optional[str]:
        """Get target (service) principal name."""
        if self._gss_ctx and self._complete:
            return str(self._gss_ctx.target_name)
        return self._name

    @property
    def lifetime(self) -> Optional[int]:
        """Get context lifetime in seconds."""
        if self._gss_ctx and self._complete:
            return self._gss_ctx.lifetime
        return None

    @property
    def mech_type(self) -> Optional[str]:
        """Get mechanism OID."""
        if self._gss_ctx and self._complete:
            return str(self._gss_ctx.mech_type)
        return None

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

        wrapped = self._gss_ctx.wrap(data, encrypt)
        return wrapped.message

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

        unwrapped = self._gss_ctx.unwrap(data)
        return (
            unwrapped.message,
            unwrapped.encrypted,
            True,  # GSSAPI always verifies signature
        )

    def get_mic(self, data: bytes) -> bytes:
        """
        Generate a MIC (Message Integrity Code) for data.

        Args:
            data: Data to sign

        Returns:
            MIC bytes
        """
        if not self._complete:
            raise RuntimeError("Context not established")

        return self._gss_ctx.get_signature(data)

    def verify_mic(self, data: bytes, mic: bytes) -> bool:
        """
        Verify a MIC for data.

        Args:
            data: Original data
            mic: MIC to verify

        Returns:
            True if valid
        """
        if not self._complete:
            raise RuntimeError("Context not established")

        try:
            self._gss_ctx.verify_signature(data, mic)
            return True
        except gssapi.exceptions.GSSError:
            return False

    @staticmethod
    def _convert_flags(flags: GSSAPIFlags) -> int:
        """Convert GSSAPIFlags to gssapi.RequirementFlag."""
        result = 0
        if GSSAPIFlags.DELEG in flags:
            result |= gssapi.RequirementFlag.delegate_to_peer
        if GSSAPIFlags.MUTUAL in flags:
            result |= gssapi.RequirementFlag.mutual_authentication
        if GSSAPIFlags.REPLAY in flags:
            result |= gssapi.RequirementFlag.replay_detection
        if GSSAPIFlags.SEQUENCE in flags:
            result |= gssapi.RequirementFlag.out_of_sequence_detection
        if GSSAPIFlags.CONF in flags:
            result |= gssapi.RequirementFlag.confidentiality
        if GSSAPIFlags.INTEG in flags:
            result |= gssapi.RequirementFlag.integrity
        if GSSAPIFlags.ANON in flags:
            result |= gssapi.RequirementFlag.anonymity
        return result


# =============================================================================
# CREDENTIAL MANAGEMENT
# =============================================================================


@attrs.define
class GSSAPICredentials:
    """
    GSSAPI credential management.

    Handles acquiring and caching Kerberos credentials.
    """

    _creds: Any = None
    _name: Optional[str] = None
    _usage: str = "initiate"
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @classmethod
    def acquire_with_password(
        cls,
        username: str,
        password: str,
        realm: Optional[str] = None,
    ) -> "GSSAPICredentials":
        """
        Acquire credentials using username/password.

        Note: This requires the gssapi 'password' extension.

        Args:
            username: User name
            password: User password
            realm: Kerberos realm (optional)

        Returns:
            GSSAPICredentials with acquired TGT
        """
        if not _gssapi_available:
            raise ImportError("GSSAPI library not available")

        # Build principal name
        if realm:
            principal = f"{username}@{realm}"
        else:
            principal = username

        name = gssapi.Name(principal, name_type=gssapi.NameType.user)

        try:
            # Try to use password acquisition
            # This requires the gssapi.raw.acquire_cred_with_password extension
            creds = gssapi.raw.acquire_cred_with_password(
                name,
                password.encode('utf-8'),
                usage="initiate",
            ).creds

            result = cls(
                _creds=creds,
                _name=principal,
                _usage="initiate",
            )

            result._logger.info(
                "gssapi_creds_acquired_password",
                principal=principal,
            )

            return result

        except AttributeError:
            # Password acquisition not available
            raise AuthenticationError(
                "GSSAPI password acquisition not available. "
                "Use kinit to obtain credentials first."
            )

    @classmethod
    def from_ccache(
        cls,
        ccache_path: Optional[str] = None,
    ) -> "GSSAPICredentials":
        """
        Load credentials from credential cache.

        Args:
            ccache_path: Path to ccache file (None for default)

        Returns:
            GSSAPICredentials from cache
        """
        if not _gssapi_available:
            raise ImportError("GSSAPI library not available")

        # Set ccache environment if specified
        if ccache_path:
            os.environ["KRB5CCNAME"] = ccache_path

        # Acquire default credentials
        creds = gssapi.Credentials(usage="initiate")

        result = cls(
            _creds=creds,
            _name=str(creds.name) if creds.name else None,
            _usage="initiate",
        )

        result._logger.info(
            "gssapi_creds_from_ccache",
            principal=result._name,
            ccache=ccache_path or "default",
        )

        return result

    @classmethod
    def from_keytab(
        cls,
        keytab_path: str,
        service_name: Optional[str] = None,
    ) -> "GSSAPICredentials":
        """
        Load server credentials from keytab.

        Args:
            keytab_path: Path to keytab file
            service_name: Service principal name (optional)

        Returns:
            GSSAPICredentials for server
        """
        if not _gssapi_available:
            raise ImportError("GSSAPI library not available")

        # Set keytab environment
        os.environ["KRB5_KTNAME"] = keytab_path

        # Build name if specified
        name = None
        if service_name:
            name = gssapi.Name(
                service_name,
                name_type=gssapi.NameType.hostbased_service,
            )

        # Acquire credentials
        creds = gssapi.Credentials(
            name=name,
            usage="accept",
        )

        result = cls(
            _creds=creds,
            _name=service_name,
            _usage="accept",
        )

        result._logger.info(
            "gssapi_creds_from_keytab",
            keytab=keytab_path,
            service=service_name,
        )

        return result

    @property
    def credentials(self) -> Any:
        """Get underlying GSSAPI credentials."""
        return self._creds

    @property
    def name(self) -> Optional[str]:
        """Get credential principal name."""
        return self._name

    @property
    def lifetime(self) -> Optional[int]:
        """Get remaining credential lifetime in seconds."""
        if self._creds:
            return self._creds.lifetime
        return None

    @property
    def is_valid(self) -> bool:
        """Check if credentials are still valid."""
        lifetime = self.lifetime
        return lifetime is not None and lifetime > 0


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_default_realm() -> Optional[str]:
    """
    Get the default Kerberos realm from system configuration.

    Returns:
        Default realm name or None
    """
    if not _gssapi_available:
        return None

    try:
        # Try to get from default credentials
        creds = gssapi.Credentials(usage="initiate")
        if creds.name:
            name_str = str(creds.name)
            if "@" in name_str:
                return name_str.split("@")[1]
    except gssapi.exceptions.GSSError:
        pass

    # Try krb5 config file
    krb5_conf_paths = [
        "/etc/krb5.conf",
        "/usr/local/etc/krb5.conf",
        os.path.expanduser("~/.krb5.conf"),
    ]

    for path in krb5_conf_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("default_realm"):
                            parts = line.split("=")
                            if len(parts) >= 2:
                                return parts[1].strip()
            except Exception:
                continue

    return None


def list_cached_credentials() -> List[Dict[str, Any]]:
    """
    List credentials in the default cache.

    Returns:
        List of credential information dicts
    """
    if not _gssapi_available:
        return []

    results = []

    try:
        creds = gssapi.Credentials(usage="initiate")

        results.append({
            "principal": str(creds.name) if creds.name else None,
            "lifetime": creds.lifetime,
            "is_valid": creds.lifetime > 0 if creds.lifetime else False,
        })
    except gssapi.exceptions.GSSError:
        pass

    return results


def kinit(
    principal: str,
    password: str,
    ccache: Optional[str] = None,
) -> bool:
    """
    Acquire TGT using password (similar to kinit command).

    Args:
        principal: User principal (e.g., "user@REALM")
        password: User password
        ccache: Credential cache path (optional)

    Returns:
        True if successful
    """
    try:
        creds = GSSAPICredentials.acquire_with_password(
            principal.split("@")[0],
            password,
            principal.split("@")[1] if "@" in principal else None,
        )
        return creds.is_valid
    except Exception as e:
        logger.error("kinit_failed", error=str(e))
        return False
