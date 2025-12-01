"""
AuthModeler Exception Types

Custom exceptions for authentication protocol errors.
"""

from typing import Optional


class AuthModelerError(Exception):
    """Base exception for all AuthModeler errors."""

    def __init__(self, message: str, code: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class AuthenticationError(AuthModelerError):
    """
    Authentication failed.

    This indicates the authentication process completed but credentials
    were rejected or invalid.
    """

    pass


class ProtocolError(AuthModelerError):
    """
    Protocol-level error.

    This indicates an error in the protocol exchange itself,
    such as malformed messages or unexpected responses.
    """

    pass


class CryptoError(AuthModelerError):
    """
    Cryptographic operation failed.

    This indicates an error in encryption, decryption, or
    integrity verification.
    """

    pass


class StateError(AuthModelerError):
    """
    Invalid state transition.

    This indicates an attempt to perform an operation that is
    not valid in the current protocol state.
    """

    pass


class InvariantViolation(AuthModelerError):
    """
    Security invariant was violated.

    This is a serious error indicating the protocol implementation
    has entered an invalid state that violates formal verification
    guarantees.
    """

    pass


class ReplayDetected(AuthenticationError):
    """
    Replay attack detected.

    An authenticator or message was reused, indicating a potential
    replay attack.
    """

    def __init__(self, message: str = "Replay attack detected") -> None:
        super().__init__(message, code=34)  # KRB_AP_ERR_REPEAT


class TicketExpired(AuthenticationError):
    """
    Ticket has expired.

    The presented ticket's validity period has passed.
    """

    def __init__(self, message: str = "Ticket has expired") -> None:
        super().__init__(message, code=32)  # KRB_AP_ERR_TKT_EXPIRED


class ClockSkew(AuthenticationError):
    """
    Clock skew too great.

    The timestamp in the message is too far from the server's time.
    """

    def __init__(self, message: str = "Clock skew too great") -> None:
        super().__init__(message, code=37)  # KRB_AP_ERR_SKEW


class PreAuthRequired(AuthenticationError):
    """
    Pre-authentication required.

    The KDC requires pre-authentication for this principal.
    """

    def __init__(self, message: str = "Pre-authentication required") -> None:
        super().__init__(message, code=25)  # KDC_ERR_PREAUTH_REQUIRED


class KerberosError(ProtocolError):
    """
    Kerberos protocol error with standard error code.

    Maps to KRB-ERROR message types from RFC 4120.
    """

    # Standard Kerberos error codes
    KDC_ERR_NONE = 0
    KDC_ERR_NAME_EXP = 1
    KDC_ERR_SERVICE_EXP = 2
    KDC_ERR_BAD_PVNO = 3
    KDC_ERR_C_OLD_MAST_KVNO = 4
    KDC_ERR_S_OLD_MAST_KVNO = 5
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8
    KDC_ERR_NULL_KEY = 9
    KDC_ERR_CANNOT_POSTDATE = 10
    KDC_ERR_NEVER_VALID = 11
    KDC_ERR_POLICY = 12
    KDC_ERR_BADOPTION = 13
    KDC_ERR_ETYPE_NOSUPP = 14
    KDC_ERR_SUMTYPE_NOSUPP = 15
    KDC_ERR_PADATA_TYPE_NOSUPP = 16
    KDC_ERR_TRTYPE_NOSUPP = 17
    KDC_ERR_CLIENT_REVOKED = 18
    KDC_ERR_SERVICE_REVOKED = 19
    KDC_ERR_TGT_REVOKED = 20
    KDC_ERR_CLIENT_NOTYET = 21
    KDC_ERR_SERVICE_NOTYET = 22
    KDC_ERR_KEY_EXPIRED = 23
    KDC_ERR_PREAUTH_FAILED = 24
    KDC_ERR_PREAUTH_REQUIRED = 25
    KRB_AP_ERR_BAD_INTEGRITY = 31
    KRB_AP_ERR_TKT_EXPIRED = 32
    KRB_AP_ERR_TKT_NYV = 33
    KRB_AP_ERR_REPEAT = 34
    KRB_AP_ERR_NOT_US = 35
    KRB_AP_ERR_BADMATCH = 36
    KRB_AP_ERR_SKEW = 37
    KRB_AP_ERR_BADADDR = 38
    KRB_AP_ERR_BADVERSION = 39
    KRB_AP_ERR_MSG_TYPE = 40
    KRB_AP_ERR_MODIFIED = 41

    ERROR_MESSAGES = {
        KDC_ERR_C_PRINCIPAL_UNKNOWN: "Client not found in Kerberos database",
        KDC_ERR_S_PRINCIPAL_UNKNOWN: "Server not found in Kerberos database",
        KDC_ERR_PREAUTH_REQUIRED: "Pre-authentication required",
        KDC_ERR_PREAUTH_FAILED: "Pre-authentication failed",
        KRB_AP_ERR_BAD_INTEGRITY: "Integrity check failed",
        KRB_AP_ERR_TKT_EXPIRED: "Ticket has expired",
        KRB_AP_ERR_REPEAT: "Replay detected",
        KRB_AP_ERR_SKEW: "Clock skew too great",
    }

    def __init__(self, code: int, message: Optional[str] = None) -> None:
        if message is None:
            message = self.ERROR_MESSAGES.get(code, f"Kerberos error {code}")
        super().__init__(message, code)


class NTLMError(ProtocolError):
    """
    NTLM protocol error.

    Maps to NTLM error status codes from MS-NLMP.
    """

    STATUS_SUCCESS = 0x00000000
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_ACCOUNT_DISABLED = 0xC0000072
    STATUS_ACCOUNT_EXPIRED = 0xC0000193
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_WRONG_PASSWORD = 0xC000006A
    STATUS_NO_SUCH_USER = 0xC0000064
    STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xC0000199

    def __init__(self, code: int, message: Optional[str] = None) -> None:
        if message is None:
            message = f"NTLM error 0x{code:08X}"
        super().__init__(message, code)
