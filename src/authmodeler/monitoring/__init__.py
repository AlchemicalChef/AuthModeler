"""
AuthModeler Login Flow Monitoring

Provides comprehensive monitoring and data collection for user login flows.
Captures authentication events, timing, security metrics, and protocol details.

Includes Windows Security Event Log integration for domain-wide authentication
monitoring from Domain Controllers.
"""

from authmodeler.monitoring.login_monitor import (
    LoginFlowMonitor,
    LoginEvent,
    LoginFlowReport,
    LoginEventType,
    create_login_monitor,
)

# Windows Event Log integration (Windows only)
# These imports will gracefully fail on non-Windows systems
try:
    from authmodeler.monitoring.eventlog import (
        # Types
        SecurityEventID,
        LogonType,
        WindowsSecurityEvent,
        eventlog_available,
        # Reader
        SecurityEventLogReader,
        # DC Monitor
        DomainControllerMonitor,
        # Subscriptions
        EventLogSubscription,
        DomainEventSubscriber,
        # Correlation
        EventCorrelator,
        CorrelatedEvent,
    )

    _eventlog_exports = [
        "SecurityEventID",
        "LogonType",
        "WindowsSecurityEvent",
        "eventlog_available",
        "SecurityEventLogReader",
        "DomainControllerMonitor",
        "EventLogSubscription",
        "DomainEventSubscriber",
        "EventCorrelator",
        "CorrelatedEvent",
    ]
except ImportError:
    # Event log not available (non-Windows or missing dependencies)
    _eventlog_exports = []

    def eventlog_available() -> bool:
        """Check if Windows Event Log integration is available."""
        return False


__all__ = [
    # Core monitoring
    "LoginFlowMonitor",
    "LoginEvent",
    "LoginFlowReport",
    "LoginEventType",
    "create_login_monitor",
    # Event log (conditionally available)
    "eventlog_available",
] + _eventlog_exports
