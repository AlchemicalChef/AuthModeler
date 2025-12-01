"""
Windows Security Event Log Subscriptions

Real-time event monitoring via Windows Event Log subscriptions.
Supports single server and multi-DC subscription patterns.

Requirements:
- Windows operating system
- pywin32 package
- Appropriate permissions to read Security Event Log
"""

from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timezone
from queue import Queue, Empty
from typing import Any, Callable, Dict, List, Optional, Set

import attrs
import structlog

from authmodeler.monitoring.eventlog.types import (
    SecurityEventID,
    WindowsSecurityEvent,
    eventlog_available,
    win32evtlog,
)
from authmodeler.monitoring.eventlog.reader import (
    _parse_event_xml,
    _create_event_from_data,
)

logger = structlog.get_logger()


# =============================================================================
# EVENT LOG SUBSCRIPTION
# =============================================================================


@attrs.define
class EventLogSubscription:
    """
    Subscribe to real-time Windows Security events.

    Uses Windows Event Log subscription API to receive events
    as they are generated.

    Example:
        def on_event(event: WindowsSecurityEvent):
            print(f"New event: {event.event_id.name} - {event.full_username}")

        subscription = EventLogSubscription(
            event_ids=[SecurityEventID.LOGON_SUCCESS, SecurityEventID.LOGON_FAILED],
            callback=on_event,
        )
        subscription.start()

        # ... events are delivered asynchronously ...

        subscription.stop()
    """

    event_ids: List[SecurityEventID] = attrs.Factory(lambda: SecurityEventID.all_auth_events())
    callback: Optional[Callable[[WindowsSecurityEvent], None]] = None
    server: str = ""  # Empty = local machine
    log_name: str = "Security"

    # Event queue for pull mode
    _event_queue: Queue = attrs.Factory(Queue)

    # Internal state
    _running: bool = False
    _thread: Optional[threading.Thread] = None
    _stop_event: threading.Event = attrs.Factory(threading.Event)
    _subscription_handle: Any = None
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @property
    def is_running(self) -> bool:
        """Check if subscription is active."""
        return self._running

    def start(self) -> bool:
        """
        Start the event subscription.

        Returns:
            True if started successfully, False otherwise
        """
        if self._running:
            self._logger.warning("subscription_already_running")
            return False

        if not eventlog_available():
            self._logger.error("eventlog_not_available")
            return False

        self._stop_event.clear()
        self._running = True

        # Start subscription in background thread
        self._thread = threading.Thread(
            target=self._subscription_loop,
            name=f"EventLogSubscription-{self.server or 'local'}",
            daemon=True,
        )
        self._thread.start()

        self._logger.info(
            "subscription_started",
            server=self.server or "local",
            event_ids=[e.name for e in self.event_ids],
        )
        return True

    def stop(self) -> None:
        """Stop the event subscription."""
        if not self._running:
            return

        self._stop_event.set()
        self._running = False

        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

        self._logger.info("subscription_stopped", server=self.server or "local")

    def get_events(self, timeout: float = 1.0, max_events: int = 100) -> List[WindowsSecurityEvent]:
        """
        Get queued events (for pull mode without callback).

        Args:
            timeout: How long to wait for events
            max_events: Maximum events to return

        Returns:
            List of events from the queue
        """
        events = []
        deadline = time.time() + timeout

        while len(events) < max_events and time.time() < deadline:
            try:
                remaining = deadline - time.time()
                event = self._event_queue.get(timeout=max(0.1, remaining))
                events.append(event)
            except Empty:
                break

        return events

    def clear_queue(self) -> int:
        """Clear queued events and return count cleared."""
        count = 0
        while True:
            try:
                self._event_queue.get_nowait()
                count += 1
            except Empty:
                break
        return count

    def _subscription_loop(self) -> None:
        """Background thread for event subscription."""
        try:
            # Build XPath query for subscription
            xpath_query = self._build_subscription_query()

            # Create subscription
            self._subscription_handle = win32evtlog.EvtSubscribe(
                self.server or None,
                win32evtlog.EvtSubscribeStartAtOldestRecord
                if not self.server
                else win32evtlog.EvtSubscribeToFutureEvents,
                self.log_name,
                xpath_query,
                None,  # Bookmark
                None,  # Context
                self._event_callback_wrapper,
                win32evtlog.EvtSubscribeToFutureEvents,
            )

            # Wait for stop signal
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=0.5)

        except AttributeError:
            # EvtSubscribe not available, fall back to polling
            self._logger.info("using_polling_fallback")
            self._polling_loop()

        except Exception as e:
            self._logger.error("subscription_error", error=str(e))
            self._running = False

        finally:
            if self._subscription_handle:
                try:
                    win32evtlog.EvtClose(self._subscription_handle)
                except Exception:
                    pass
                self._subscription_handle = None

    def _polling_loop(self) -> None:
        """Fallback polling loop if subscription API not available."""
        from authmodeler.monitoring.eventlog.reader import SecurityEventLogReader

        reader = SecurityEventLogReader(server=self.server)
        last_record_id = 0

        while not self._stop_event.is_set():
            try:
                # Query for new events
                events = reader.query_events(
                    event_ids=self.event_ids,
                    max_events=100,
                )

                # Filter to new events only
                new_events = [e for e in events if e.record_id > last_record_id]

                if new_events:
                    # Update last seen record
                    last_record_id = max(e.record_id for e in new_events)

                    # Deliver events
                    for event in sorted(new_events, key=lambda e: e.timestamp):
                        self._deliver_event(event)

            except Exception as e:
                self._logger.warning("polling_error", error=str(e))

            # Poll interval
            self._stop_event.wait(timeout=2.0)

    def _event_callback_wrapper(
        self,
        action: int,
        context: Any,
        event_handle: Any,
    ) -> int:
        """Callback wrapper for Windows subscription API."""
        try:
            if action == win32evtlog.EvtSubscribeActionDeliver:
                # Get event XML
                xml = win32evtlog.EvtRender(
                    event_handle,
                    win32evtlog.EvtRenderEventXml,
                )

                # Parse event
                event_data = _parse_event_xml(xml)
                event = _create_event_from_data(event_data, xml)

                if event and event.event_id in self.event_ids:
                    self._deliver_event(event)

        except Exception as e:
            self._logger.warning("callback_error", error=str(e))

        return 0  # Continue subscription

    def _deliver_event(self, event: WindowsSecurityEvent) -> None:
        """Deliver event to callback or queue."""
        # Add to queue
        try:
            self._event_queue.put_nowait(event)
        except Exception:
            pass  # Queue full, drop event

        # Call callback if provided
        if self.callback:
            try:
                self.callback(event)
            except Exception as e:
                self._logger.warning("callback_exception", error=str(e))

    def _build_subscription_query(self) -> str:
        """Build XPath query for subscription."""
        event_id_conditions = " or ".join(
            f"EventID={eid.value}" for eid in self.event_ids
        )
        return f"*[System[({event_id_conditions})]]"


# =============================================================================
# DOMAIN EVENT SUBSCRIBER
# =============================================================================


@attrs.define
class DomainEventSubscriber:
    """
    Subscribe to events from multiple Domain Controllers.

    Manages subscriptions to multiple DCs and delivers events
    through a unified callback.

    Example:
        from authmodeler.monitoring.eventlog import (
            DomainControllerMonitor,
            DomainEventSubscriber,
            SecurityEventID,
        )

        # Discover DCs
        monitor = DomainControllerMonitor(domain="EXAMPLE.COM")
        dc_servers = monitor.discover_domain_controllers()

        # Subscribe to events from all DCs
        def on_event(event):
            print(f"[{event.computer_name}] {event.full_username}: {event.event_id.name}")

        subscriber = DomainEventSubscriber(
            dc_servers=dc_servers,
            event_ids=[SecurityEventID.LOGON_SUCCESS, SecurityEventID.LOGON_FAILED],
            callback=on_event,
        )

        subscriber.start_all()
        # ... events from all DCs delivered to callback ...
        subscriber.stop_all()
    """

    dc_servers: List[str]
    event_ids: List[SecurityEventID] = attrs.Factory(lambda: SecurityEventID.all_auth_events())
    callback: Optional[Callable[[WindowsSecurityEvent], None]] = None

    # Deduplication
    deduplicate: bool = True
    _seen_events: Set[tuple] = attrs.Factory(set)
    _seen_lock: threading.Lock = attrs.Factory(threading.Lock)

    # Subscriptions
    _subscriptions: Dict[str, EventLogSubscription] = attrs.Factory(dict)
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @property
    def is_running(self) -> bool:
        """Check if any subscriptions are active."""
        return any(sub.is_running for sub in self._subscriptions.values())

    @property
    def active_servers(self) -> List[str]:
        """Get list of servers with active subscriptions."""
        return [
            server
            for server, sub in self._subscriptions.items()
            if sub.is_running
        ]

    def start_all(self) -> Dict[str, bool]:
        """
        Start subscriptions to all DCs.

        Returns:
            Dictionary of {server: success} results
        """
        results = {}

        for server in self.dc_servers:
            success = self.start_server(server)
            results[server] = success

        active = sum(1 for s in results.values() if s)
        self._logger.info(
            "domain_subscription_started",
            total_servers=len(self.dc_servers),
            active_subscriptions=active,
        )

        return results

    def stop_all(self) -> None:
        """Stop all subscriptions."""
        for server in list(self._subscriptions.keys()):
            self.stop_server(server)

        self._subscriptions.clear()
        self._seen_events.clear()

        self._logger.info("domain_subscription_stopped")

    def start_server(self, server: str) -> bool:
        """
        Start subscription to a specific server.

        Args:
            server: Server hostname

        Returns:
            True if started successfully
        """
        if server in self._subscriptions and self._subscriptions[server].is_running:
            return True

        subscription = EventLogSubscription(
            server=server,
            event_ids=self.event_ids,
            callback=self._on_event,
        )

        success = subscription.start()
        if success:
            self._subscriptions[server] = subscription

        return success

    def stop_server(self, server: str) -> None:
        """Stop subscription to a specific server."""
        if server in self._subscriptions:
            self._subscriptions[server].stop()
            del self._subscriptions[server]

    def get_events(self, timeout: float = 1.0, max_events: int = 100) -> List[WindowsSecurityEvent]:
        """
        Get queued events from all subscriptions.

        Args:
            timeout: How long to wait
            max_events: Maximum events to return

        Returns:
            Combined events from all subscriptions
        """
        events = []
        deadline = time.time() + timeout

        for subscription in self._subscriptions.values():
            remaining = deadline - time.time()
            if remaining <= 0:
                break

            sub_events = subscription.get_events(
                timeout=min(0.5, remaining),
                max_events=max_events - len(events),
            )
            events.extend(sub_events)

            if len(events) >= max_events:
                break

        # Deduplicate
        if self.deduplicate:
            events = self._deduplicate_events(events)

        return events

    def _on_event(self, event: WindowsSecurityEvent) -> None:
        """Internal callback that handles deduplication."""
        # Check for duplicate
        if self.deduplicate:
            event_key = (event.record_id, event.computer_name)
            with self._seen_lock:
                if event_key in self._seen_events:
                    return
                self._seen_events.add(event_key)

                # Limit seen set size
                if len(self._seen_events) > 10000:
                    # Remove oldest entries (approximate by clearing half)
                    self._seen_events = set(list(self._seen_events)[-5000:])

        # Deliver to user callback
        if self.callback:
            try:
                self.callback(event)
            except Exception as e:
                self._logger.warning("user_callback_error", error=str(e))

    def _deduplicate_events(
        self,
        events: List[WindowsSecurityEvent],
    ) -> List[WindowsSecurityEvent]:
        """Remove duplicate events from list."""
        seen: Set[tuple] = set()
        unique = []

        for event in events:
            key = (event.record_id, event.computer_name)
            if key not in seen:
                seen.add(key)
                unique.append(event)

        return unique
