"""
AuthModeler Windows Security Event Log Integration

Provides domain-wide monitoring of Windows Security events for authentication tracking.
Supports reading from Domain Controllers, real-time subscriptions, and correlation
with AuthModeler authentication flows.

Features:
- Query authentication events (4624, 4625, 4768, 4769, 4771, 4776)
- Domain Controller auto-discovery
- Real-time event subscriptions
- Correlation with AuthModeler login flows

Requirements:
- Windows operating system
- pywin32 package (pip install pywin32)
- Appropriate permissions to read Security Event Log
"""

from authmodeler.monitoring.eventlog.types import (
    SecurityEventID,
    LogonType,
    WindowsSecurityEvent,
    eventlog_available,
)
from authmodeler.monitoring.eventlog.reader import (
    SecurityEventLogReader,
)
from authmodeler.monitoring.eventlog.dc_monitor import (
    DomainControllerMonitor,
)
from authmodeler.monitoring.eventlog.subscription import (
    EventLogSubscription,
    DomainEventSubscriber,
)
from authmodeler.monitoring.eventlog.correlator import (
    EventCorrelator,
    CorrelatedEvent,
)

__all__ = [
    # Types
    "SecurityEventID",
    "LogonType",
    "WindowsSecurityEvent",
    "eventlog_available",
    # Reader
    "SecurityEventLogReader",
    # DC Monitor
    "DomainControllerMonitor",
    # Subscriptions
    "EventLogSubscription",
    "DomainEventSubscriber",
    # Correlation
    "EventCorrelator",
    "CorrelatedEvent",
]
