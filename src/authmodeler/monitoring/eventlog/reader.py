"""
Windows Security Event Log Reader

Query and read events from Windows Security Event Log.
Supports local machine and remote server access.

Requirements:
- Windows operating system
- pywin32 package (pip install pywin32)
- SeSecurityPrivilege or "Event Log Readers" group membership
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import attrs
import structlog

from authmodeler.monitoring.eventlog.types import (
    SecurityEventID,
    LogonType,
    WindowsSecurityEvent,
    eventlog_available,
    win32evtlog,
)

logger = structlog.get_logger()


# =============================================================================
# EVENT PARSING UTILITIES
# =============================================================================


def _parse_event_xml(xml_string: str) -> Dict[str, Any]:
    """
    Parse Windows Event XML to extract event data.

    Args:
        xml_string: Raw XML string from the event

    Returns:
        Dictionary with parsed event fields
    """
    try:
        # Handle XML namespaces
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        root = ET.fromstring(xml_string)

        data = {}

        # System section
        system = root.find("e:System", ns)
        if system is not None:
            event_id_elem = system.find("e:EventID", ns)
            if event_id_elem is not None:
                data["EventID"] = int(event_id_elem.text or "0")

            time_elem = system.find("e:TimeCreated", ns)
            if time_elem is not None:
                data["TimeCreated"] = time_elem.get("SystemTime", "")

            computer_elem = system.find("e:Computer", ns)
            if computer_elem is not None:
                data["Computer"] = computer_elem.text or ""

            record_elem = system.find("e:EventRecordID", ns)
            if record_elem is not None:
                data["EventRecordID"] = int(record_elem.text or "0")

        # EventData section
        event_data = root.find("e:EventData", ns)
        if event_data is not None:
            for elem in event_data.findall("e:Data", ns):
                name = elem.get("Name", "")
                value = elem.text or ""
                if name:
                    data[name] = value

        return data

    except ET.ParseError as e:
        logger.warning("xml_parse_error", error=str(e))
        return {}


def _parse_timestamp(time_str: str) -> datetime:
    """Parse Windows event timestamp to datetime."""
    try:
        # Windows event timestamps are in ISO 8601 format
        # Example: 2024-01-15T10:30:45.123456789Z
        if time_str.endswith("Z"):
            time_str = time_str[:-1] + "+00:00"
        # Handle nanoseconds by truncating to microseconds
        if "." in time_str:
            base, frac = time_str.rsplit(".", 1)
            # Split off timezone if present
            if "+" in frac:
                frac_part, tz = frac.split("+")
                frac = frac_part[:6] + "+" + tz
            elif "-" in frac and len(frac) > 6:
                # Handle negative timezone
                frac_part, tz = frac.rsplit("-", 1)
                frac = frac_part[:6] + "-" + tz
            else:
                frac = frac[:6]
            time_str = f"{base}.{frac}"
        return datetime.fromisoformat(time_str)
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _create_event_from_data(
    event_data: Dict[str, Any], raw_xml: str = ""
) -> Optional[WindowsSecurityEvent]:
    """
    Create a WindowsSecurityEvent from parsed event data.

    Args:
        event_data: Parsed event data dictionary
        raw_xml: Original XML string

    Returns:
        WindowsSecurityEvent or None if parsing fails
    """
    try:
        event_id_value = event_data.get("EventID", 0)
        try:
            event_id = SecurityEventID(event_id_value)
        except ValueError:
            # Unknown event ID, skip
            return None

        timestamp = _parse_timestamp(event_data.get("TimeCreated", ""))

        # Extract logon type if present
        logon_type_value = event_data.get("LogonType", "")
        logon_type = None
        if logon_type_value:
            try:
                logon_type = LogonType(int(logon_type_value))
            except (ValueError, TypeError):
                pass

        # Extract IP address - can be in different fields
        source_ip = (
            event_data.get("IpAddress", "")
            or event_data.get("ClientAddress", "")
            or ""
        )
        # Clean up IP (remove IPv6 prefix if present)
        if source_ip.startswith("::ffff:"):
            source_ip = source_ip[7:]
        if source_ip == "-" or source_ip == "::1":
            source_ip = "127.0.0.1" if source_ip == "::1" else ""

        return WindowsSecurityEvent(
            event_id=event_id,
            timestamp=timestamp,
            record_id=event_data.get("EventRecordID", 0),
            computer_name=event_data.get("Computer", ""),
            target_username=event_data.get("TargetUserName", "")
            or event_data.get("TargetUser", ""),
            target_domain=event_data.get("TargetDomainName", "")
            or event_data.get("TargetDomain", ""),
            logon_type=logon_type,
            source_ip=source_ip,
            source_workstation=event_data.get("WorkstationName", "")
            or event_data.get("Workstation", ""),
            service_name=event_data.get("ServiceName", ""),
            ticket_encryption_type=event_data.get("TicketEncryptionType", ""),
            pre_auth_type=event_data.get("PreAuthType", ""),
            status_code=int(event_data.get("Status", "0x0"), 16)
            if isinstance(event_data.get("Status"), str)
            and event_data.get("Status", "").startswith("0x")
            else int(event_data.get("Status", 0) or 0),
            sub_status_code=int(event_data.get("SubStatus", "0x0"), 16)
            if isinstance(event_data.get("SubStatus"), str)
            and event_data.get("SubStatus", "").startswith("0x")
            else int(event_data.get("SubStatus", 0) or 0),
            failure_reason=event_data.get("FailureReason", ""),
            logon_id=event_data.get("TargetLogonId", "")
            or event_data.get("LogonGuid", ""),
            event_data=event_data,
            raw_xml=raw_xml,
        )

    except Exception as e:
        logger.warning("event_parse_error", error=str(e), event_data=event_data)
        return None


# =============================================================================
# SECURITY EVENT LOG READER
# =============================================================================


@attrs.define
class SecurityEventLogReader:
    """
    Read and query Windows Security Event Log.

    Provides methods to query authentication events from the Security log
    on local or remote Windows machines.

    Requires appropriate permissions:
    - Local: SeSecurityPrivilege or "Event Log Readers" group
    - Remote: Domain Admin or delegated permissions

    Example:
        reader = SecurityEventLogReader()
        events = reader.get_logon_events(
            username="jdoe",
            since=datetime.now() - timedelta(hours=1),
        )
        for event in events:
            print(f"{event.timestamp}: {event.full_username} - {event.event_id.name}")
    """

    server: str = ""  # Empty = local machine
    log_name: str = "Security"

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    @classmethod
    def is_available(cls) -> Tuple[bool, str]:
        """
        Check if Security Event Log reading is available.

        Returns:
            Tuple of (available, message)
        """
        if not eventlog_available():
            return False, "pywin32 not available or not on Windows"
        return True, "Security Event Log API available"

    def query_events(
        self,
        event_ids: Optional[List[SecurityEventID]] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        username: Optional[str] = None,
        max_events: int = 1000,
    ) -> List[WindowsSecurityEvent]:
        """
        Query events from the Security Event Log.

        Args:
            event_ids: List of event IDs to filter (None = all auth events)
            since: Only events after this time
            until: Only events before this time
            username: Filter by target username (case-insensitive)
            max_events: Maximum number of events to return

        Returns:
            List of WindowsSecurityEvent objects, newest first
        """
        if not eventlog_available():
            self._logger.warning("eventlog_not_available")
            return []

        if event_ids is None:
            event_ids = SecurityEventID.all_auth_events()

        # Build XPath query
        xpath_query = self._build_xpath_query(event_ids, since, until)

        try:
            return self._execute_query(xpath_query, username, max_events)
        except Exception as e:
            self._logger.error("query_failed", error=str(e), server=self.server)
            return []

    def get_logon_events(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """
        Get logon events (4624 success, 4625 failed).

        Args:
            username: Filter by username
            since: Only events after this time
            max_events: Maximum events to return

        Returns:
            List of logon events
        """
        return self.query_events(
            event_ids=SecurityEventID.logon_events(),
            since=since,
            username=username,
            max_events=max_events,
        )

    def get_successful_logons(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """Get only successful logon events (4624)."""
        return self.query_events(
            event_ids=[SecurityEventID.LOGON_SUCCESS],
            since=since,
            username=username,
            max_events=max_events,
        )

    def get_failed_logons(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        window_minutes: int = 15,
        max_events: int = 100,
    ) -> List[WindowsSecurityEvent]:
        """
        Get failed logon events (4625).

        Useful for brute force detection.

        Args:
            username: Filter by username
            since: Only events after this time (default: last window_minutes)
            window_minutes: Time window in minutes (used if since not provided)
            max_events: Maximum events to return
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        return self.query_events(
            event_ids=[SecurityEventID.LOGON_FAILED],
            since=since,
            username=username,
            max_events=max_events,
        )

    def get_kerberos_events(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """Get Kerberos-related events (4768, 4769, 4771)."""
        return self.query_events(
            event_ids=SecurityEventID.kerberos_events(),
            since=since,
            username=username,
            max_events=max_events,
        )

    def get_ntlm_events(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """Get NTLM credential validation events (4776)."""
        return self.query_events(
            event_ids=SecurityEventID.ntlm_events(),
            since=since,
            username=username,
            max_events=max_events,
        )

    def get_account_lockouts(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 100,
    ) -> List[WindowsSecurityEvent]:
        """Get account lockout events (4740)."""
        return self.query_events(
            event_ids=[SecurityEventID.ACCOUNT_LOCKED],
            since=since,
            username=username,
            max_events=max_events,
        )

    def count_failed_logons(
        self,
        username: str,
        window_minutes: int = 15,
    ) -> int:
        """
        Count failed logon attempts for a user.

        Useful for brute force detection.

        Args:
            username: Username to check
            window_minutes: Time window in minutes

        Returns:
            Number of failed logon attempts
        """
        events = self.get_failed_logons(
            username=username,
            window_minutes=window_minutes,
        )
        return len(events)

    def _build_xpath_query(
        self,
        event_ids: List[SecurityEventID],
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> str:
        """Build XPath query for event filtering."""
        # Start with event ID filter
        event_id_conditions = " or ".join(
            f"EventID={eid.value}" for eid in event_ids
        )
        query = f"*[System[({event_id_conditions})"

        # Add time filters if specified
        if since:
            # Convert to Windows FILETIME ticks
            since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            query += f" and TimeCreated[@SystemTime>='{since_str}']"

        if until:
            until_str = until.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            query += f" and TimeCreated[@SystemTime<='{until_str}']"

        query += "]]"
        return query

    def _execute_query(
        self,
        xpath_query: str,
        username: Optional[str],
        max_events: int,
    ) -> List[WindowsSecurityEvent]:
        """Execute the event log query."""
        events = []
        username_lower = username.lower() if username else None

        try:
            # Use EvtQuery for more efficient querying
            query_handle = win32evtlog.EvtQuery(
                self.server or None,
                win32evtlog.EvtQueryChannelPath,
                self.log_name,
                xpath_query,
                win32evtlog.EvtQueryReverseDirection,  # Newest first
            )

            while len(events) < max_events:
                # Read events in batches
                event_handles = win32evtlog.EvtNext(
                    query_handle, min(100, max_events - len(events))
                )
                if not event_handles:
                    break

                for handle in event_handles:
                    try:
                        xml = win32evtlog.EvtRender(
                            handle, win32evtlog.EvtRenderEventXml
                        )
                        event_data = _parse_event_xml(xml)
                        event = _create_event_from_data(event_data, xml)

                        if event is None:
                            continue

                        # Apply username filter
                        if username_lower:
                            event_username = event.target_username.lower()
                            if event_username != username_lower:
                                continue

                        events.append(event)

                        if len(events) >= max_events:
                            break

                    finally:
                        win32evtlog.EvtClose(handle)

            win32evtlog.EvtClose(query_handle)

        except AttributeError:
            # Fallback to older API if EvtQuery not available
            self._logger.info("using_legacy_api")
            events = self._legacy_read_events(xpath_query, username_lower, max_events)
        except Exception as e:
            self._logger.error("query_error", error=str(e))
            raise

        return events

    def _legacy_read_events(
        self,
        xpath_query: str,
        username_lower: Optional[str],
        max_events: int,
    ) -> List[WindowsSecurityEvent]:
        """Fallback to legacy ReadEventLog API."""
        events = []

        try:
            handle = win32evtlog.OpenEventLog(self.server or None, self.log_name)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            while len(events) < max_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break

                for record in records:
                    event_id_value = record.EventID & 0xFFFF

                    # Check if it's an auth event
                    try:
                        event_id = SecurityEventID(event_id_value)
                    except ValueError:
                        continue

                    # Parse the record
                    event = WindowsSecurityEvent(
                        event_id=event_id,
                        timestamp=record.TimeGenerated.replace(tzinfo=timezone.utc),
                        record_id=record.RecordNumber,
                        computer_name=record.ComputerName,
                        target_username=record.StringInserts[5]
                        if record.StringInserts and len(record.StringInserts) > 5
                        else "",
                        target_domain=record.StringInserts[6]
                        if record.StringInserts and len(record.StringInserts) > 6
                        else "",
                        event_data={},
                        raw_xml="",
                    )

                    # Apply username filter
                    if username_lower:
                        if event.target_username.lower() != username_lower:
                            continue

                    events.append(event)

                    if len(events) >= max_events:
                        break

            win32evtlog.CloseEventLog(handle)

        except Exception as e:
            self._logger.error("legacy_read_error", error=str(e))

        return events
