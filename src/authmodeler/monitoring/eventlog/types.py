"""
Windows Security Event Log Types

Data structures for Windows Security events related to authentication.

Supports:
- Logon events (4624, 4625)
- Kerberos events (4768, 4769, 4771)
- NTLM events (4776)
- Account lockout (4740)

Requirements:
- Windows operating system
- pywin32 package (pip install pywin32)
"""

from __future__ import annotations

import sys
from datetime import datetime
from enum import IntEnum, auto
from typing import Any, Dict, Optional

import attrs
import structlog

logger = structlog.get_logger()

# =============================================================================
# PLATFORM DETECTION
# =============================================================================

_eventlog_available = False
_eventlog_error: Optional[str] = None
win32evtlog = None
win32evtlogutil = None
win32con = None

if sys.platform == "win32":
    try:
        import win32evtlog as win32evtlog_module
        import win32evtlogutil as win32evtlogutil_module
        import win32con as win32con_module

        win32evtlog = win32evtlog_module
        win32evtlogutil = win32evtlogutil_module
        win32con = win32con_module
        _eventlog_available = True
    except ImportError as e:
        _eventlog_error = str(e)
        logger.warning(
            "eventlog_not_available",
            message="Install pywin32 for Event Log access: pip install pywin32",
        )
else:
    _eventlog_error = "Windows Event Log is only available on Windows"


def eventlog_available() -> bool:
    """Check if Windows Event Log API is available."""
    return _eventlog_available


def get_eventlog_error() -> Optional[str]:
    """Get the error message if Event Log is not available."""
    return _eventlog_error


# =============================================================================
# SECURITY EVENT IDS
# =============================================================================


class SecurityEventID(IntEnum):
    """
    Windows Security Event IDs for authentication events.

    These events are logged by Windows Security subsystem and
    are typically found on Domain Controllers for domain accounts.
    """

    # Logon events
    LOGON_SUCCESS = 4624
    LOGON_FAILED = 4625
    LOGOFF = 4634
    LOGON_TYPE_CHANGE = 4648  # Explicit credential logon

    # Kerberos events
    KERBEROS_TGT_REQUEST = 4768  # Kerberos authentication ticket (TGT) requested
    KERBEROS_SERVICE_TICKET = 4769  # Kerberos service ticket requested
    KERBEROS_PREAUTH_FAILED = 4771  # Kerberos pre-authentication failed
    KERBEROS_TICKET_RENEWED = 4770  # Kerberos ticket was renewed

    # NTLM events
    NTLM_CREDENTIAL_VALIDATION = 4776  # NTLM credential validation

    # Account events
    ACCOUNT_LOCKED = 4740  # Account was locked out
    ACCOUNT_UNLOCKED = 4767  # Account was unlocked

    @classmethod
    def logon_events(cls) -> list["SecurityEventID"]:
        """Get all logon-related event IDs."""
        return [cls.LOGON_SUCCESS, cls.LOGON_FAILED]

    @classmethod
    def kerberos_events(cls) -> list["SecurityEventID"]:
        """Get all Kerberos-related event IDs."""
        return [
            cls.KERBEROS_TGT_REQUEST,
            cls.KERBEROS_SERVICE_TICKET,
            cls.KERBEROS_PREAUTH_FAILED,
            cls.KERBEROS_TICKET_RENEWED,
        ]

    @classmethod
    def ntlm_events(cls) -> list["SecurityEventID"]:
        """Get all NTLM-related event IDs."""
        return [cls.NTLM_CREDENTIAL_VALIDATION]

    @classmethod
    def all_auth_events(cls) -> list["SecurityEventID"]:
        """Get all authentication-related event IDs."""
        return cls.logon_events() + cls.kerberos_events() + cls.ntlm_events()


class LogonType(IntEnum):
    """
    Windows logon types from events 4624/4625.

    Indicates how the user logged on.
    """

    INTERACTIVE = 2  # Local keyboard/screen logon
    NETWORK = 3  # Network logon (e.g., accessing shares)
    BATCH = 4  # Batch/scheduled task
    SERVICE = 5  # Service started
    UNLOCK = 7  # Workstation unlock
    NETWORK_CLEARTEXT = 8  # Network logon with cleartext credentials
    NEW_CREDENTIALS = 9  # RunAs with /netonly
    REMOTE_INTERACTIVE = 10  # RDP/Terminal Services
    CACHED_INTERACTIVE = 11  # Cached credentials (offline logon)

    @classmethod
    def from_value(cls, value: int) -> Optional["LogonType"]:
        """Convert integer value to LogonType, returns None if invalid."""
        try:
            return cls(value)
        except ValueError:
            return None


class KerberosErrorCode(IntEnum):
    """
    Kerberos error codes from event 4771 (pre-auth failed).

    These indicate why Kerberos authentication failed.
    """

    SUCCESS = 0x0
    CLIENT_REVOKED = 0x12  # Account disabled/locked
    KEY_EXPIRED = 0x17  # Password expired
    PREAUTH_FAILED = 0x18  # Wrong password
    CLOCK_SKEW = 0x25  # Clock skew too great
    CERTIFICATE_MISMATCH = 0x4B  # Smart card certificate issue


# =============================================================================
# WINDOWS SECURITY EVENT
# =============================================================================


@attrs.define(frozen=True, slots=True)
class WindowsSecurityEvent:
    """
    Immutable record of a Windows Security Event.

    Captures authentication-related events from the Windows Security log.
    Parsed from raw event log entries with relevant fields extracted.

    Attributes:
        event_id: The Windows Security Event ID (e.g., 4624, 4625)
        timestamp: When the event occurred (UTC)
        record_id: Unique record number in the event log
        computer_name: Name of the computer that generated the event
        target_username: Username being authenticated
        target_domain: Domain of the target account
        logon_type: Type of logon (for 4624/4625 events)
        source_ip: IP address of the client (if available)
        source_workstation: Name of the client workstation
        service_name: Service principal name (for Kerberos service tickets)
        status_code: Status/error code (for failed events)
        sub_status_code: Additional status code
        failure_reason: Human-readable failure reason
        logon_id: Unique logon session identifier
        event_data: Raw event data dictionary
        raw_xml: Raw XML of the event (if preserved)
    """

    event_id: SecurityEventID
    timestamp: datetime
    record_id: int
    computer_name: str

    # Authentication details
    target_username: str = ""
    target_domain: str = ""
    logon_type: Optional[LogonType] = None
    source_ip: str = ""
    source_workstation: str = ""

    # Kerberos-specific
    service_name: str = ""
    ticket_encryption_type: str = ""
    pre_auth_type: str = ""

    # Status/error information
    status_code: int = 0
    sub_status_code: int = 0
    failure_reason: str = ""

    # Session identifier
    logon_id: str = ""

    # Raw data
    event_data: Dict[str, Any] = attrs.Factory(dict)
    raw_xml: str = ""

    @property
    def is_success(self) -> bool:
        """Check if this is a successful authentication event."""
        return self.event_id in (
            SecurityEventID.LOGON_SUCCESS,
            SecurityEventID.KERBEROS_TGT_REQUEST,
            SecurityEventID.KERBEROS_SERVICE_TICKET,
        ) and self.status_code == 0

    @property
    def is_failure(self) -> bool:
        """Check if this is a failed authentication event."""
        return self.event_id in (
            SecurityEventID.LOGON_FAILED,
            SecurityEventID.KERBEROS_PREAUTH_FAILED,
        ) or self.status_code != 0

    @property
    def is_kerberos(self) -> bool:
        """Check if this is a Kerberos-related event."""
        return self.event_id in SecurityEventID.kerberos_events()

    @property
    def is_ntlm(self) -> bool:
        """Check if this is an NTLM-related event."""
        return self.event_id in SecurityEventID.ntlm_events()

    @property
    def full_username(self) -> str:
        """Get the full username in DOMAIN\\username format."""
        if self.target_domain:
            return f"{self.target_domain}\\{self.target_username}"
        return self.target_username

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id.value,
            "event_name": self.event_id.name,
            "timestamp": self.timestamp.isoformat(),
            "record_id": self.record_id,
            "computer_name": self.computer_name,
            "target_username": self.target_username,
            "target_domain": self.target_domain,
            "full_username": self.full_username,
            "logon_type": self.logon_type.value if self.logon_type else None,
            "logon_type_name": self.logon_type.name if self.logon_type else None,
            "source_ip": self.source_ip,
            "source_workstation": self.source_workstation,
            "service_name": self.service_name,
            "status_code": self.status_code,
            "sub_status_code": self.sub_status_code,
            "failure_reason": self.failure_reason,
            "logon_id": self.logon_id,
            "is_success": self.is_success,
            "is_failure": self.is_failure,
        }

    def __str__(self) -> str:
        """Human-readable string representation."""
        status = "SUCCESS" if self.is_success else "FAILED"
        return (
            f"{self.event_id.name}({self.event_id.value}) - "
            f"{self.full_username} - {status} - "
            f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
