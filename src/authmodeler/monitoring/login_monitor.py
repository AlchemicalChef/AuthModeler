"""
AuthModeler Login Flow Monitor

Comprehensive monitoring of user authentication flows.
Captures detailed information for security analysis, debugging, and audit logging.

Features:
- Event capture for all authentication steps
- Timing metrics for performance analysis
- Security event detection (failures, unusual patterns)
- Protocol-specific data capture (Kerberos TGT, NTLM challenges)
- Export to JSON, CSV, and structured reports

Usage:
    monitor = create_login_monitor("EXAMPLE.COM")

    # Monitor a login attempt
    with monitor.track_login("jdoe", client_ip="192.168.1.100") as login:
        result = monitor.authenticate("jdoe", "password")

    # Get the login report
    report = monitor.get_report()
    print(f"Login successful: {report.success}")
    print(f"Protocol used: {report.protocol_used}")
    print(f"Duration: {report.duration_ms}ms")

    # Export all data
    monitor.export_json("login_data.json")
"""

from __future__ import annotations

import csv
import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, Generator, List, Optional, Tuple

import attrs
import structlog

from authmodeler.core.types import AuthResult, Principal, Protocol, Realm
from authmodeler.ad.authenticator import ADAuthenticator, ADConfig, create_ad_authenticator

logger = structlog.get_logger()


# =============================================================================
# EVENT TYPES AND DATA STRUCTURES
# =============================================================================


class LoginEventType(Enum):
    """Types of events captured during login flow."""

    # Flow lifecycle
    LOGIN_STARTED = auto()
    LOGIN_COMPLETED = auto()
    LOGIN_FAILED = auto()

    # Protocol events
    KERBEROS_AS_REQ_SENT = auto()
    KERBEROS_AS_REP_RECEIVED = auto()
    KERBEROS_TGT_OBTAINED = auto()
    KERBEROS_PREAUTH_REQUIRED = auto()
    KERBEROS_ERROR = auto()

    NTLM_NEGOTIATE_SENT = auto()
    NTLM_CHALLENGE_RECEIVED = auto()
    NTLM_AUTHENTICATE_SENT = auto()
    NTLM_ERROR = auto()

    # Protocol selection
    PROTOCOL_SELECTED = auto()
    PROTOCOL_FALLBACK = auto()

    # Security events
    INVALID_CREDENTIALS = auto()
    ACCOUNT_LOCKED = auto()
    ACCOUNT_EXPIRED = auto()
    PASSWORD_EXPIRED = auto()
    CLOCK_SKEW_DETECTED = auto()
    ENCRYPTION_NEGOTIATED = auto()

    # Session events
    SESSION_KEY_GENERATED = auto()
    TICKET_ISSUED = auto()
    TICKET_EXPIRES = auto()


@attrs.define(frozen=True, slots=True)
class LoginEvent:
    """
    Immutable record of a login flow event.

    Captures all relevant information about a specific moment
    in the authentication process.
    """

    event_id: str
    event_type: LoginEventType
    timestamp: datetime

    # Context
    username: str = ""
    domain: str = ""
    client_ip: str = ""
    client_hostname: str = ""

    # Protocol details
    protocol: Optional[Protocol] = None
    encryption_type: str = ""

    # Event-specific data
    data: Dict[str, Any] = attrs.Factory(dict)

    # Error information
    error_code: Optional[int] = None
    error_message: str = ""

    # Timing
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.name,
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "domain": self.domain,
            "client_ip": self.client_ip,
            "client_hostname": self.client_hostname,
            "protocol": self.protocol.name if self.protocol else None,
            "encryption_type": self.encryption_type,
            "data": self.data,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
        }


@dataclass
class LoginFlowReport:
    """
    Comprehensive report of a login flow.

    Aggregates all events and metrics from an authentication attempt.
    """

    flow_id: str
    username: str
    domain: str

    # Outcome
    success: bool = False
    protocol_used: Optional[Protocol] = None

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: float = 0.0

    # Client info
    client_ip: str = ""
    client_hostname: str = ""

    # Protocol-specific info
    kerberos_info: Dict[str, Any] = field(default_factory=dict)
    ntlm_info: Dict[str, Any] = field(default_factory=dict)

    # Session info
    session_key_available: bool = False
    ticket_expiration: Optional[datetime] = None
    encryption_type: str = ""

    # Security metrics
    failed_attempts: int = 0
    protocol_fallback_used: bool = False
    warnings: List[str] = field(default_factory=list)

    # Events
    events: List[LoginEvent] = field(default_factory=list)

    # Error info
    error_code: Optional[int] = None
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "flow_id": self.flow_id,
            "username": self.username,
            "domain": self.domain,
            "success": self.success,
            "protocol_used": self.protocol_used.name if self.protocol_used else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "client_ip": self.client_ip,
            "client_hostname": self.client_hostname,
            "kerberos_info": self.kerberos_info,
            "ntlm_info": self.ntlm_info,
            "session_key_available": self.session_key_available,
            "ticket_expiration": self.ticket_expiration.isoformat() if self.ticket_expiration else None,
            "encryption_type": self.encryption_type,
            "failed_attempts": self.failed_attempts,
            "protocol_fallback_used": self.protocol_fallback_used,
            "warnings": self.warnings,
            "events": [e.to_dict() for e in self.events],
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


# =============================================================================
# LOGIN CONTEXT (for tracking active login)
# =============================================================================


@dataclass
class LoginContext:
    """Active login context for tracking an in-progress authentication."""

    flow_id: str
    username: str
    domain: str
    client_ip: str = ""
    client_hostname: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    events: List[LoginEvent] = field(default_factory=list)

    _start_time: float = field(default_factory=time.perf_counter)


# =============================================================================
# LOGIN FLOW MONITOR
# =============================================================================


@attrs.define
class LoginFlowMonitor:
    """
    Monitors and records user login flows.

    Wraps the AD authenticator to capture detailed information
    about authentication attempts for security analysis, debugging,
    and audit logging.

    Features:
    - Automatic event capture for all authentication steps
    - Timing metrics for performance analysis
    - Security event detection
    - Protocol-specific data capture
    - Export to JSON, CSV, and structured reports

    Example:
        monitor = LoginFlowMonitor(domain="EXAMPLE.COM")

        # Simple authentication with monitoring
        result = monitor.authenticate("jdoe", "password", client_ip="192.168.1.100")

        # Get detailed report
        report = monitor.get_last_report()
        print(f"Success: {report.success}")
        print(f"Duration: {report.duration_ms}ms")

        # Export all login data
        monitor.export_json("login_history.json")
    """

    domain: str
    authenticator: ADAuthenticator = attrs.field(init=False)

    # Configuration
    capture_sensitive_data: bool = False  # Don't log passwords, keys by default
    max_history_size: int = 1000

    # State
    _current_context: Optional[LoginContext] = None
    _reports: List[LoginFlowReport] = attrs.Factory(list)
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    # Windows Event Log integration (optional)
    _dc_monitor: Any = None
    _event_correlator: Any = None
    _event_subscriber: Any = None
    _dc_monitoring_enabled: bool = False

    def __attrs_post_init__(self) -> None:
        """Initialize the authenticator."""
        self.authenticator = create_ad_authenticator(
            domain=self.domain,
            prefer_kerberos=True,
            allow_ntlm=True,
        )

    @contextmanager
    def track_login(
        self,
        username: str,
        client_ip: str = "",
        client_hostname: str = "",
    ) -> Generator[LoginContext, None, None]:
        """
        Context manager for tracking a login flow.

        Usage:
            with monitor.track_login("jdoe", client_ip="192.168.1.100") as ctx:
                result = monitor.authenticate("jdoe", "password")

        Args:
            username: Username being authenticated
            client_ip: Client IP address
            client_hostname: Client hostname

        Yields:
            LoginContext for the active login
        """
        flow_id = str(uuid.uuid4())
        context = LoginContext(
            flow_id=flow_id,
            username=username,
            domain=self.domain,
            client_ip=client_ip,
            client_hostname=client_hostname,
        )

        self._current_context = context
        self._record_event(LoginEventType.LOGIN_STARTED)

        try:
            yield context
        finally:
            self._current_context = None

    def authenticate(
        self,
        username: str,
        password: str,
        domain: Optional[str] = None,
        client_ip: str = "",
        client_hostname: str = "",
        protocol: Optional[Protocol] = None,
    ) -> AuthResult:
        """
        Authenticate a user with full monitoring.

        Captures all authentication events, timing, and protocol details.

        Args:
            username: Username to authenticate
            password: User's password
            domain: Optional domain override
            client_ip: Client IP address for logging
            client_hostname: Client hostname for logging
            protocol: Force specific protocol (Kerberos, NTLM, or Negotiate)

        Returns:
            AuthResult with success/failure and session info
        """
        domain = domain or self.domain

        # Create context if not in track_login block
        auto_context = self._current_context is None
        if auto_context:
            self._current_context = LoginContext(
                flow_id=str(uuid.uuid4()),
                username=username,
                domain=domain,
                client_ip=client_ip,
                client_hostname=client_hostname,
            )
            self._record_event(LoginEventType.LOGIN_STARTED)
        else:
            # Update context with any new info
            self._current_context.client_ip = client_ip or self._current_context.client_ip
            self._current_context.client_hostname = client_hostname or self._current_context.client_hostname

        try:
            # Record protocol selection
            selected_protocol = protocol or Protocol.KERBEROS
            self._record_event(
                LoginEventType.PROTOCOL_SELECTED,
                data={"protocol": selected_protocol.name},
            )

            # Perform authentication
            start_time = time.perf_counter()
            result = self.authenticator.authenticate(
                username=username,
                password=password,
                domain=domain,
                protocol=protocol,
            )
            auth_duration = (time.perf_counter() - start_time) * 1000

            # Capture protocol-specific events from authenticator traces
            self._capture_authenticator_traces()

            # Record outcome
            if result.success:
                self._record_event(
                    LoginEventType.LOGIN_COMPLETED,
                    data={
                        "session_key_available": result.session_key is not None,
                        "expiration": result.expiration.isoformat() if result.expiration else None,
                    },
                    duration_ms=auth_duration,
                )

                if result.session_key:
                    self._record_event(LoginEventType.SESSION_KEY_GENERATED)

                if result.expiration:
                    self._record_event(
                        LoginEventType.TICKET_EXPIRES,
                        data={"expiration": result.expiration.isoformat()},
                    )
            else:
                self._record_event(
                    LoginEventType.LOGIN_FAILED,
                    error_code=result.error_code,
                    error_message=result.error_message or "Authentication failed",
                    duration_ms=auth_duration,
                )

                # Detect specific failure types
                self._detect_failure_type(result)

            # Generate and store report
            report = self._generate_report(result)
            self._store_report(report)

            return result

        finally:
            if auto_context:
                self._current_context = None

    def get_last_report(self) -> Optional[LoginFlowReport]:
        """Get the most recent login report."""
        return self._reports[-1] if self._reports else None

    def get_reports(
        self,
        username: Optional[str] = None,
        success_only: bool = False,
        failure_only: bool = False,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[LoginFlowReport]:
        """
        Query login reports with filters.

        Args:
            username: Filter by username
            success_only: Only return successful logins
            failure_only: Only return failed logins
            since: Only return logins after this time
            limit: Maximum number of reports to return

        Returns:
            List of matching LoginFlowReport objects
        """
        reports = self._reports

        if username:
            reports = [r for r in reports if r.username == username]

        if success_only:
            reports = [r for r in reports if r.success]
        elif failure_only:
            reports = [r for r in reports if not r.success]

        if since:
            reports = [r for r in reports if r.started_at and r.started_at >= since]

        return reports[-limit:]

    def get_failed_login_count(
        self,
        username: str,
        window_minutes: int = 15,
    ) -> int:
        """
        Get count of failed logins for a user in a time window.

        Useful for detecting brute force attacks.

        Args:
            username: Username to check
            window_minutes: Time window in minutes

        Returns:
            Count of failed login attempts
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        return sum(
            1 for r in self._reports
            if r.username == username
            and not r.success
            and r.started_at
            and r.started_at >= cutoff
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get aggregate statistics for all monitored logins.

        Returns:
            Dictionary with statistics including:
            - total_logins: Total login attempts
            - successful_logins: Successful login count
            - failed_logins: Failed login count
            - success_rate: Percentage of successful logins
            - avg_duration_ms: Average login duration
            - protocols_used: Count by protocol
            - unique_users: Number of unique users
        """
        if not self._reports:
            return {
                "total_logins": 0,
                "successful_logins": 0,
                "failed_logins": 0,
                "success_rate": 0.0,
                "avg_duration_ms": 0.0,
                "protocols_used": {},
                "unique_users": 0,
            }

        successful = sum(1 for r in self._reports if r.success)
        failed = len(self._reports) - successful

        protocols: Dict[str, int] = {}
        for r in self._reports:
            if r.protocol_used:
                proto_name = r.protocol_used.name
                protocols[proto_name] = protocols.get(proto_name, 0) + 1

        durations = [r.duration_ms for r in self._reports if r.duration_ms > 0]
        avg_duration = sum(durations) / len(durations) if durations else 0.0

        unique_users = len(set(r.username for r in self._reports))

        return {
            "total_logins": len(self._reports),
            "successful_logins": successful,
            "failed_logins": failed,
            "success_rate": (successful / len(self._reports)) * 100 if self._reports else 0.0,
            "avg_duration_ms": avg_duration,
            "protocols_used": protocols,
            "unique_users": unique_users,
        }

    def export_json(self, filepath: str) -> None:
        """
        Export all login data to JSON file.

        Args:
            filepath: Path to output JSON file
        """
        data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": self.domain,
            "statistics": self.get_statistics(),
            "reports": [r.to_dict() for r in self._reports],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

        self._logger.info("exported_login_data", filepath=filepath, count=len(self._reports))

    def export_csv(self, filepath: str) -> None:
        """
        Export login summary to CSV file.

        Args:
            filepath: Path to output CSV file
        """
        fieldnames = [
            "flow_id", "username", "domain", "success", "protocol_used",
            "started_at", "duration_ms", "client_ip", "error_message",
        ]

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for report in self._reports:
                writer.writerow({
                    "flow_id": report.flow_id,
                    "username": report.username,
                    "domain": report.domain,
                    "success": report.success,
                    "protocol_used": report.protocol_used.name if report.protocol_used else "",
                    "started_at": report.started_at.isoformat() if report.started_at else "",
                    "duration_ms": report.duration_ms,
                    "client_ip": report.client_ip,
                    "error_message": report.error_message,
                })

        self._logger.info("exported_csv", filepath=filepath, count=len(self._reports))

    def export_events_json(self, filepath: str) -> None:
        """
        Export all events to JSON file.

        Args:
            filepath: Path to output JSON file
        """
        all_events = []
        for report in self._reports:
            all_events.extend([e.to_dict() for e in report.events])

        data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": self.domain,
            "total_events": len(all_events),
            "events": all_events,
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

        self._logger.info("exported_events", filepath=filepath, count=len(all_events))

    def clear_history(self) -> None:
        """Clear all stored login history."""
        self._reports.clear()
        self._logger.info("history_cleared")

    # =========================================================================
    # INTERNAL METHODS
    # =========================================================================

    def _record_event(
        self,
        event_type: LoginEventType,
        data: Optional[Dict[str, Any]] = None,
        error_code: Optional[int] = None,
        error_message: str = "",
        duration_ms: float = 0.0,
    ) -> None:
        """Record an event in the current login context."""
        if self._current_context is None:
            return

        event = LoginEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            username=self._current_context.username,
            domain=self._current_context.domain,
            client_ip=self._current_context.client_ip,
            client_hostname=self._current_context.client_hostname,
            data=data or {},
            error_code=error_code,
            error_message=error_message,
            duration_ms=duration_ms,
        )

        self._current_context.events.append(event)

        self._logger.debug(
            "login_event",
            event_type=event_type.name,
            username=self._current_context.username,
        )

    def _capture_authenticator_traces(self) -> None:
        """Capture events from authenticator protocol traces."""
        traces = self.authenticator.get_traces()

        for trace in traces:
            event_type_str = trace.get("event_type", "")

            # Map trace events to LoginEventTypes
            event_map = {
                "InitiateAuth": LoginEventType.KERBEROS_AS_REQ_SENT,
                "ASReplyReceived": LoginEventType.KERBEROS_AS_REP_RECEIVED,
                "InitiateNTLM": LoginEventType.NTLM_NEGOTIATE_SENT,
                "ChallengeReceived": LoginEventType.NTLM_CHALLENGE_RECEIVED,
                "AuthenticateComplete": LoginEventType.NTLM_AUTHENTICATE_SENT,
            }

            if event_type_str in event_map:
                self._record_event(
                    event_map[event_type_str],
                    data=trace,
                )

    def _detect_failure_type(self, result: AuthResult) -> None:
        """Detect specific failure types from error codes/messages."""
        error_msg = (result.error_message or "").lower()
        error_code = result.error_code

        # Kerberos error codes
        if error_code:
            if error_code == 6:  # KDC_ERR_C_PRINCIPAL_UNKNOWN
                self._record_event(
                    LoginEventType.INVALID_CREDENTIALS,
                    error_message="Principal not found",
                )
            elif error_code == 18:  # KDC_ERR_CLIENT_REVOKED
                self._record_event(
                    LoginEventType.ACCOUNT_LOCKED,
                    error_message="Account revoked/locked",
                )
            elif error_code == 23:  # KDC_ERR_KEY_EXPIRED
                self._record_event(
                    LoginEventType.PASSWORD_EXPIRED,
                    error_message="Password has expired",
                )
            elif error_code == 37:  # KRB_AP_ERR_SKEW
                self._record_event(
                    LoginEventType.CLOCK_SKEW_DETECTED,
                    error_message="Clock skew too great",
                )

        # String-based detection
        if "invalid" in error_msg or "wrong password" in error_msg:
            self._record_event(
                LoginEventType.INVALID_CREDENTIALS,
                error_message="Invalid credentials",
            )
        elif "locked" in error_msg:
            self._record_event(
                LoginEventType.ACCOUNT_LOCKED,
                error_message="Account locked",
            )
        elif "expired" in error_msg:
            if "password" in error_msg:
                self._record_event(
                    LoginEventType.PASSWORD_EXPIRED,
                    error_message="Password expired",
                )
            else:
                self._record_event(
                    LoginEventType.ACCOUNT_EXPIRED,
                    error_message="Account expired",
                )

    def _generate_report(self, result: AuthResult) -> LoginFlowReport:
        """Generate a comprehensive report for the current login flow."""
        ctx = self._current_context
        if ctx is None:
            raise RuntimeError("No active login context")

        now = datetime.now(timezone.utc)
        duration = (time.perf_counter() - ctx._start_time) * 1000

        # Determine protocol used
        protocol_used = None
        if result.success:
            # Check authenticator state
            if hasattr(self.authenticator, '_last_protocol'):
                protocol_used = self.authenticator._last_protocol

        # Build Kerberos info
        kerberos_info = {}
        if self.authenticator._kerberos_client:
            kc = self.authenticator._kerberos_client
            kerberos_info = {
                "state": kc.state.name,
                "has_tgt": kc.has_valid_tgt,
            }
            if kc.has_valid_tgt and hasattr(kc, 'context'):
                ctx_data = kc.context
                if hasattr(ctx_data, 'tgt_info') and ctx_data.tgt_info:
                    kerberos_info["tgt_flags"] = [f.name for f in ctx_data.tgt_info.flags]

        # Build NTLM info
        ntlm_info = {}
        if self.authenticator._ntlm_client:
            nc = self.authenticator._ntlm_client
            ntlm_info = {
                "state": nc.state.name,
            }

        # Check for protocol fallback
        protocol_fallback_used = any(
            e.event_type == LoginEventType.PROTOCOL_FALLBACK
            for e in ctx.events
        )

        # Count failed attempts in this flow
        failed_attempts = sum(
            1 for e in ctx.events
            if e.event_type in (LoginEventType.LOGIN_FAILED, LoginEventType.INVALID_CREDENTIALS)
        )

        report = LoginFlowReport(
            flow_id=ctx.flow_id,
            username=ctx.username,
            domain=ctx.domain,
            success=result.success,
            protocol_used=protocol_used,
            started_at=ctx.started_at,
            completed_at=now,
            duration_ms=duration,
            client_ip=ctx.client_ip,
            client_hostname=ctx.client_hostname,
            kerberos_info=kerberos_info,
            ntlm_info=ntlm_info,
            session_key_available=result.session_key is not None,
            ticket_expiration=result.expiration,
            failed_attempts=failed_attempts,
            protocol_fallback_used=protocol_fallback_used,
            events=list(ctx.events),
            error_code=result.error_code,
            error_message=result.error_message or "",
        )

        return report

    def _store_report(self, report: LoginFlowReport) -> None:
        """Store report and manage history size."""
        self._reports.append(report)

        # Trim history if needed
        if len(self._reports) > self.max_history_size:
            self._reports = self._reports[-self.max_history_size:]

        self._logger.info(
            "login_report_stored",
            flow_id=report.flow_id,
            username=report.username,
            success=report.success,
            duration_ms=report.duration_ms,
        )

    # =========================================================================
    # WINDOWS EVENT LOG INTEGRATION
    # =========================================================================

    def enable_dc_monitoring(
        self,
        dc_servers: Optional[List[str]] = None,
        auto_discover: bool = True,
    ) -> bool:
        """
        Enable domain-wide Windows Security Event Log monitoring.

        Connects to Domain Controllers to monitor authentication events
        across the entire AD domain.

        Args:
            dc_servers: List of DC hostnames (auto-discovered if not provided)
            auto_discover: Whether to auto-discover DCs if not provided

        Returns:
            True if enabled successfully, False otherwise

        Requires:
            - Windows operating system
            - pywin32 package
            - Appropriate permissions to read Security Event Log from DCs
        """
        try:
            from authmodeler.monitoring.eventlog import (
                DomainControllerMonitor,
                SecurityEventLogReader,
                EventCorrelator,
                eventlog_available,
            )

            if not eventlog_available():
                self._logger.warning("dc_monitoring_not_available")
                return False

            # Create DC monitor
            self._dc_monitor = DomainControllerMonitor(
                domain=self.domain,
                dc_servers=dc_servers or [],
            )

            # Auto-discover DCs if requested
            if auto_discover and not dc_servers:
                discovered = self._dc_monitor.discover_domain_controllers()
                self._logger.info("dc_discovered", count=len(discovered))

            # Create correlator with local reader
            reader = SecurityEventLogReader()
            self._event_correlator = EventCorrelator(reader=reader)

            self._dc_monitoring_enabled = True
            self._logger.info(
                "dc_monitoring_enabled",
                domain=self.domain,
                dcs=len(self._dc_monitor.dc_servers),
            )
            return True

        except ImportError:
            self._logger.warning("eventlog_module_not_available")
            return False
        except Exception as e:
            self._logger.error("dc_monitoring_enable_failed", error=str(e))
            return False

    def disable_dc_monitoring(self) -> None:
        """Disable domain controller monitoring."""
        if self._event_subscriber:
            self._event_subscriber.stop_all()
            self._event_subscriber = None

        self._dc_monitor = None
        self._event_correlator = None
        self._dc_monitoring_enabled = False
        self._logger.info("dc_monitoring_disabled")

    def get_domain_logins(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[Any]:
        """
        Get domain-wide login events from Domain Controllers.

        Requires DC monitoring to be enabled via enable_dc_monitoring().

        Args:
            username: Filter by username
            since: Only events after this time
            max_events: Maximum events to return

        Returns:
            List of WindowsSecurityEvent objects
        """
        if not self._dc_monitoring_enabled or not self._dc_monitor:
            self._logger.warning("dc_monitoring_not_enabled")
            return []

        return self._dc_monitor.get_domain_logons(
            username=username,
            since=since,
            max_events=max_events,
        )

    def get_user_login_history(
        self,
        username: str,
        since: Optional[datetime] = None,
        max_events: int = 100,
    ) -> List[Any]:
        """
        Get complete login history for a user from Domain Controllers.

        Args:
            username: Username to query
            since: Only events after this time
            max_events: Maximum events to return

        Returns:
            List of WindowsSecurityEvent objects
        """
        if not self._dc_monitoring_enabled or not self._dc_monitor:
            self._logger.warning("dc_monitoring_not_enabled")
            return []

        return self._dc_monitor.get_user_login_history(
            username=username,
            since=since,
            max_events=max_events,
        )

    def correlate_with_windows_events(
        self,
        report: Optional[LoginFlowReport] = None,
    ) -> Optional[Any]:
        """
        Correlate a login report with Windows Security events.

        Args:
            report: LoginFlowReport to correlate (default: last report)

        Returns:
            CorrelatedEvent with matched Windows events, or None
        """
        if not self._dc_monitoring_enabled or not self._event_correlator:
            self._logger.warning("dc_monitoring_not_enabled")
            return None

        if report is None:
            report = self.get_last_report()

        if report is None:
            return None

        return self._event_correlator.correlate_login_report(report)

    def start_realtime_monitoring(
        self,
        callback: Optional[Any] = None,
    ) -> bool:
        """
        Start real-time monitoring of domain login events.

        Args:
            callback: Optional callback function for events.
                      Signature: callback(event: WindowsSecurityEvent) -> None

        Returns:
            True if started successfully
        """
        if not self._dc_monitoring_enabled or not self._dc_monitor:
            self._logger.warning("dc_monitoring_not_enabled")
            return False

        try:
            from authmodeler.monitoring.eventlog import (
                DomainEventSubscriber,
                SecurityEventID,
            )

            self._event_subscriber = DomainEventSubscriber(
                dc_servers=self._dc_monitor.dc_servers,
                event_ids=[
                    SecurityEventID.LOGON_SUCCESS,
                    SecurityEventID.LOGON_FAILED,
                ],
                callback=callback,
            )

            results = self._event_subscriber.start_all()
            active = sum(1 for v in results.values() if v)

            self._logger.info(
                "realtime_monitoring_started",
                active_subscriptions=active,
                total_dcs=len(self._dc_monitor.dc_servers),
            )

            return active > 0

        except Exception as e:
            self._logger.error("realtime_monitoring_failed", error=str(e))
            return False

    def stop_realtime_monitoring(self) -> None:
        """Stop real-time monitoring of domain events."""
        if self._event_subscriber:
            self._event_subscriber.stop_all()
            self._event_subscriber = None
            self._logger.info("realtime_monitoring_stopped")

    def get_dc_statistics(self) -> Dict[str, Any]:
        """
        Get domain-wide authentication statistics.

        Returns:
            Dictionary with statistics from Domain Controllers
        """
        if not self._dc_monitoring_enabled or not self._dc_monitor:
            return {"error": "DC monitoring not enabled"}

        return self._dc_monitor.get_statistics()


# =============================================================================
# FACTORY FUNCTION
# =============================================================================


def create_login_monitor(
    domain: str,
    capture_sensitive_data: bool = False,
    max_history_size: int = 1000,
) -> LoginFlowMonitor:
    """
    Create a login flow monitor.

    Args:
        domain: AD domain name (e.g., "EXAMPLE.COM")
        capture_sensitive_data: Whether to capture sensitive data (default: False)
        max_history_size: Maximum number of reports to keep in history

    Returns:
        Configured LoginFlowMonitor

    Example:
        monitor = create_login_monitor("EXAMPLE.COM")
        result = monitor.authenticate("jdoe", "password")
        report = monitor.get_last_report()
    """
    return LoginFlowMonitor(
        domain=domain,
        capture_sensitive_data=capture_sensitive_data,
        max_history_size=max_history_size,
    )
