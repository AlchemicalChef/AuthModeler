"""
Event Correlator

Correlate AuthModeler login events with Windows Security events.
Links internal authentication tracking with Windows audit logs.

Requirements:
- Windows operating system
- pywin32 package
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import attrs
import structlog

from authmodeler.monitoring.eventlog.types import (
    SecurityEventID,
    WindowsSecurityEvent,
)
from authmodeler.monitoring.eventlog.reader import SecurityEventLogReader

logger = structlog.get_logger()


# =============================================================================
# CORRELATED EVENT
# =============================================================================


@dataclass
class CorrelatedEvent:
    """
    An AuthModeler login event correlated with Windows Security events.

    Links internal tracking with Windows audit logs for comprehensive
    security analysis.
    """

    # AuthModeler login event (from LoginFlowMonitor)
    login_flow_id: str
    login_username: str
    login_domain: str
    login_timestamp: datetime
    login_success: bool
    login_client_ip: str = ""

    # Correlated Windows events
    windows_events: List[WindowsSecurityEvent] = field(default_factory=list)

    # Correlation metadata
    correlation_confidence: float = 0.0  # 0.0 - 1.0
    correlation_method: str = ""  # e.g., "time_username", "time_only"
    time_delta_ms: float = 0.0  # Time difference between login and Windows event

    # Analysis
    windows_success: bool = False
    windows_failure: bool = False
    event_mismatch: bool = False  # True if AuthModeler/Windows results differ

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "login_flow_id": self.login_flow_id,
            "login_username": self.login_username,
            "login_domain": self.login_domain,
            "login_timestamp": self.login_timestamp.isoformat(),
            "login_success": self.login_success,
            "login_client_ip": self.login_client_ip,
            "windows_events": [e.to_dict() for e in self.windows_events],
            "windows_event_count": len(self.windows_events),
            "correlation_confidence": self.correlation_confidence,
            "correlation_method": self.correlation_method,
            "time_delta_ms": self.time_delta_ms,
            "windows_success": self.windows_success,
            "windows_failure": self.windows_failure,
            "event_mismatch": self.event_mismatch,
        }


# =============================================================================
# CORRELATION CONFIG
# =============================================================================


@attrs.define
class CorrelationConfig:
    """Configuration for event correlation."""

    # Time window for correlation (milliseconds)
    time_window_ms: int = 5000  # 5 seconds default

    # Match requirements
    require_username_match: bool = True
    require_domain_match: bool = False  # Domain may be formatted differently
    require_ip_match: bool = False  # IP may not always be available

    # Confidence thresholds
    min_confidence: float = 0.5

    # Event mapping
    map_success_to_4624: bool = True
    map_failure_to_4625: bool = True
    include_kerberos_events: bool = True
    include_ntlm_events: bool = True


# =============================================================================
# EVENT CORRELATOR
# =============================================================================


@attrs.define
class EventCorrelator:
    """
    Correlate AuthModeler events with Windows Security events.

    Uses time-window and attribute matching to find related events
    in the Windows Security Event Log.

    Example:
        from authmodeler.monitoring import LoginFlowMonitor
        from authmodeler.monitoring.eventlog import EventCorrelator, SecurityEventLogReader

        monitor = LoginFlowMonitor(domain="EXAMPLE.COM")
        reader = SecurityEventLogReader()
        correlator = EventCorrelator(reader=reader)

        # Authenticate and get report
        result = monitor.authenticate("jdoe", "password")
        report = monitor.get_last_report()

        # Correlate with Windows events
        correlated = correlator.correlate_login_report(report)
        for ce in correlated:
            print(f"Found {len(ce.windows_events)} Windows events")
            print(f"Confidence: {ce.correlation_confidence:.1%}")
    """

    reader: SecurityEventLogReader
    config: CorrelationConfig = attrs.Factory(CorrelationConfig)

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def correlate_login_report(
        self,
        report: Any,  # LoginFlowReport from login_monitor
    ) -> CorrelatedEvent:
        """
        Correlate a LoginFlowReport with Windows Security events.

        Args:
            report: LoginFlowReport from LoginFlowMonitor

        Returns:
            CorrelatedEvent with matched Windows events
        """
        # Extract login details from report
        login_timestamp = report.started_at or datetime.now(timezone.utc)
        login_username = report.username
        login_domain = report.domain
        login_success = report.success
        login_client_ip = report.client_ip

        return self._correlate(
            flow_id=report.flow_id,
            timestamp=login_timestamp,
            username=login_username,
            domain=login_domain,
            success=login_success,
            client_ip=login_client_ip,
        )

    def correlate_login_event(
        self,
        event: Any,  # LoginEvent from login_monitor
        flow_id: str = "",
    ) -> CorrelatedEvent:
        """
        Correlate a single LoginEvent with Windows Security events.

        Args:
            event: LoginEvent from LoginFlowMonitor
            flow_id: Flow ID for tracking

        Returns:
            CorrelatedEvent with matched Windows events
        """
        return self._correlate(
            flow_id=flow_id or event.event_id,
            timestamp=event.timestamp,
            username=event.username,
            domain=event.domain,
            success=event.event_type.name == "LOGIN_COMPLETED",
            client_ip=event.client_ip,
        )

    def find_matching_events(
        self,
        timestamp: datetime,
        username: str,
        domain: str = "",
        success: Optional[bool] = None,
    ) -> List[WindowsSecurityEvent]:
        """
        Find Windows events matching given criteria.

        Args:
            timestamp: Time of authentication
            username: Username to match
            domain: Domain to match (optional)
            success: Filter by success/failure (optional)

        Returns:
            List of matching Windows events
        """
        # Calculate time window
        window = timedelta(milliseconds=self.config.time_window_ms)
        since = timestamp - window
        until = timestamp + window

        # Determine which event IDs to search
        event_ids = []
        if success is True or success is None:
            if self.config.map_success_to_4624:
                event_ids.append(SecurityEventID.LOGON_SUCCESS)
        if success is False or success is None:
            if self.config.map_failure_to_4625:
                event_ids.append(SecurityEventID.LOGON_FAILED)
        if self.config.include_kerberos_events:
            event_ids.extend(SecurityEventID.kerberos_events())
        if self.config.include_ntlm_events:
            event_ids.extend(SecurityEventID.ntlm_events())

        # Query events
        events = self.reader.query_events(
            event_ids=event_ids,
            since=since,
            until=until,
            username=username if self.config.require_username_match else None,
            max_events=100,
        )

        # Filter by additional criteria
        matched = []
        for event in events:
            if self._matches_criteria(event, username, domain):
                matched.append(event)

        return matched

    def calculate_confidence(
        self,
        login_timestamp: datetime,
        login_username: str,
        login_domain: str,
        login_success: bool,
        windows_event: WindowsSecurityEvent,
    ) -> float:
        """
        Calculate confidence score for a correlation.

        Factors:
        - Time proximity (closer = higher)
        - Username match
        - Domain match
        - Success/failure alignment
        - Event type alignment

        Returns:
            Confidence score from 0.0 to 1.0
        """
        score = 0.0
        max_score = 0.0

        # Time proximity (0-0.3)
        time_diff = abs((windows_event.timestamp - login_timestamp).total_seconds() * 1000)
        max_time = self.config.time_window_ms
        time_score = max(0, 1 - (time_diff / max_time)) * 0.3
        score += time_score
        max_score += 0.3

        # Username match (0-0.3)
        if login_username.lower() == windows_event.target_username.lower():
            score += 0.3
        max_score += 0.3

        # Domain match (0-0.15)
        if login_domain and windows_event.target_domain:
            if login_domain.lower() == windows_event.target_domain.lower():
                score += 0.15
            elif login_domain.lower() in windows_event.target_domain.lower():
                score += 0.1
        max_score += 0.15

        # Success/failure alignment (0-0.15)
        windows_success = windows_event.is_success
        if login_success == windows_success:
            score += 0.15
        max_score += 0.15

        # Event type alignment (0-0.1)
        if login_success and windows_event.event_id == SecurityEventID.LOGON_SUCCESS:
            score += 0.1
        elif not login_success and windows_event.event_id == SecurityEventID.LOGON_FAILED:
            score += 0.1
        max_score += 0.1

        return score / max_score if max_score > 0 else 0.0

    def _correlate(
        self,
        flow_id: str,
        timestamp: datetime,
        username: str,
        domain: str,
        success: bool,
        client_ip: str,
    ) -> CorrelatedEvent:
        """Internal correlation implementation."""
        # Find matching Windows events
        windows_events = self.find_matching_events(
            timestamp=timestamp,
            username=username,
            domain=domain,
            success=None,  # Get both success and failure
        )

        # Calculate confidence for each match
        best_confidence = 0.0
        best_time_delta = float("inf")

        for event in windows_events:
            conf = self.calculate_confidence(
                login_timestamp=timestamp,
                login_username=username,
                login_domain=domain,
                login_success=success,
                windows_event=event,
            )
            if conf > best_confidence:
                best_confidence = conf

            time_delta = abs((event.timestamp - timestamp).total_seconds() * 1000)
            if time_delta < best_time_delta:
                best_time_delta = time_delta

        # Determine correlation method
        method = "time_window"
        if self.config.require_username_match:
            method = "time_username"
        if self.config.require_domain_match:
            method = "time_username_domain"

        # Check for success/failure alignment
        windows_success = any(e.is_success for e in windows_events)
        windows_failure = any(e.is_failure for e in windows_events)
        event_mismatch = (success and windows_failure and not windows_success) or (
            not success and windows_success and not windows_failure
        )

        correlated = CorrelatedEvent(
            login_flow_id=flow_id,
            login_username=username,
            login_domain=domain,
            login_timestamp=timestamp,
            login_success=success,
            login_client_ip=client_ip,
            windows_events=windows_events,
            correlation_confidence=best_confidence,
            correlation_method=method,
            time_delta_ms=best_time_delta if best_time_delta != float("inf") else 0.0,
            windows_success=windows_success,
            windows_failure=windows_failure,
            event_mismatch=event_mismatch,
        )

        self._logger.debug(
            "correlation_complete",
            flow_id=flow_id,
            windows_events=len(windows_events),
            confidence=best_confidence,
            mismatch=event_mismatch,
        )

        return correlated

    def _matches_criteria(
        self,
        event: WindowsSecurityEvent,
        username: str,
        domain: str,
    ) -> bool:
        """Check if event matches correlation criteria."""
        # Username match
        if self.config.require_username_match:
            if event.target_username.lower() != username.lower():
                return False

        # Domain match
        if self.config.require_domain_match and domain:
            event_domain = event.target_domain.lower()
            login_domain = domain.lower()
            if event_domain != login_domain and login_domain not in event_domain:
                return False

        return True


# =============================================================================
# BATCH CORRELATION
# =============================================================================


def correlate_reports_batch(
    reports: List[Any],  # List of LoginFlowReport
    reader: SecurityEventLogReader,
    config: Optional[CorrelationConfig] = None,
) -> List[CorrelatedEvent]:
    """
    Correlate multiple login reports with Windows events.

    More efficient than individual correlation for batch processing.

    Args:
        reports: List of LoginFlowReport objects
        reader: Event log reader to use
        config: Correlation configuration

    Returns:
        List of CorrelatedEvent objects
    """
    correlator = EventCorrelator(
        reader=reader,
        config=config or CorrelationConfig(),
    )

    results = []
    for report in reports:
        try:
            correlated = correlator.correlate_login_report(report)
            results.append(correlated)
        except Exception as e:
            logger.warning("correlation_failed", flow_id=report.flow_id, error=str(e))

    return results
