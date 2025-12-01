"""
Domain Controller Event Log Monitor

Monitor authentication events across multiple Domain Controllers.
Provides domain-wide visibility into login activity.

Requirements:
- Windows operating system
- pywin32 package
- Domain Admin or delegated permissions for remote DC access
"""

from __future__ import annotations

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import attrs
import structlog

from authmodeler.monitoring.eventlog.types import (
    SecurityEventID,
    WindowsSecurityEvent,
    eventlog_available,
)
from authmodeler.monitoring.eventlog.reader import SecurityEventLogReader

logger = structlog.get_logger()


# =============================================================================
# DC DISCOVERY
# =============================================================================


def _discover_dcs_via_dns(domain: str) -> List[str]:
    """
    Discover Domain Controllers via DNS SRV records.

    Args:
        domain: AD domain name (e.g., "EXAMPLE.COM")

    Returns:
        List of DC hostnames
    """
    dcs = []

    try:
        import dns.resolver

        # Query _ldap._tcp.dc._msdcs.<domain> SRV records
        srv_query = f"_ldap._tcp.dc._msdcs.{domain}"
        answers = dns.resolver.resolve(srv_query, "SRV")

        for answer in answers:
            dc_name = str(answer.target).rstrip(".")
            dcs.append(dc_name)

    except ImportError:
        logger.info("dnspython_not_available", message="Install dnspython for DNS-based DC discovery")
    except Exception as e:
        logger.warning("dns_discovery_failed", error=str(e))

    return dcs


def _discover_dcs_via_netlogon(domain: str) -> List[str]:
    """
    Discover Domain Controllers via Windows Netlogon API.

    Args:
        domain: AD domain name

    Returns:
        List of DC hostnames
    """
    dcs = []

    if sys.platform != "win32" or not eventlog_available():
        return dcs

    try:
        import win32net
        import win32netcon

        # Get list of domain controllers
        resume = 0
        while True:
            result, total, resume = win32net.NetServerEnum(
                None,  # Local machine
                100,  # Level 100 - basic info
                win32netcon.SV_TYPE_DOMAIN_CTRL | win32netcon.SV_TYPE_DOMAIN_BAKCTRL,
                domain,
                resume,
            )

            for server in result:
                dc_name = server.get("name", "")
                if dc_name:
                    dcs.append(dc_name)

            if not resume:
                break

    except ImportError:
        logger.info("win32net_not_available")
    except Exception as e:
        logger.warning("netlogon_discovery_failed", error=str(e))

    return dcs


def _discover_dcs_via_ldap(domain: str) -> List[str]:
    """
    Discover Domain Controllers via LDAP query.

    Args:
        domain: AD domain name

    Returns:
        List of DC hostnames
    """
    dcs = []

    try:
        import ldap3
        from ldap3 import Server, Connection, ALL

        # Build DN from domain
        domain_dn = ",".join(f"DC={part}" for part in domain.split("."))

        # Connect to domain (auto-discover)
        server = Server(domain, get_info=ALL)
        conn = Connection(server, auto_bind=True)

        # Search for domain controllers
        search_base = f"OU=Domain Controllers,{domain_dn}"
        search_filter = "(objectClass=computer)"

        conn.search(
            search_base,
            search_filter,
            attributes=["dNSHostName", "cn"],
        )

        for entry in conn.entries:
            hostname = entry.dNSHostName.value if hasattr(entry, "dNSHostName") else None
            if hostname:
                dcs.append(hostname)

        conn.unbind()

    except ImportError:
        logger.info("ldap3_not_available", message="Install ldap3 for LDAP-based DC discovery")
    except Exception as e:
        logger.warning("ldap_discovery_failed", error=str(e))

    return dcs


# =============================================================================
# DOMAIN CONTROLLER MONITOR
# =============================================================================


@attrs.define
class DomainControllerMonitor:
    """
    Monitor authentication events across Domain Controllers.

    Aggregates events from multiple DCs for domain-wide visibility.
    Automatically discovers DCs if none are specified.

    Example:
        monitor = DomainControllerMonitor(domain="EXAMPLE.COM")

        # Discover DCs
        dcs = monitor.discover_domain_controllers()
        print(f"Found {len(dcs)} domain controllers")

        # Query domain-wide logons
        logons = monitor.get_domain_logons(
            username="jdoe",
            since=datetime.now() - timedelta(hours=1),
        )

        for event in logons:
            print(f"{event.timestamp}: {event.full_username} on {event.computer_name}")
    """

    domain: str
    dc_servers: List[str] = attrs.Factory(list)
    max_workers: int = 5  # Parallel queries to DCs
    timeout_seconds: int = 30

    _readers: Dict[str, SecurityEventLogReader] = attrs.Factory(dict)
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def discover_domain_controllers(self, use_cache: bool = True) -> List[str]:
        """
        Discover Domain Controllers for the domain.

        Uses multiple discovery methods:
        1. DNS SRV records (preferred)
        2. Windows Netlogon API (Windows only)
        3. LDAP query (if ldap3 available)

        Args:
            use_cache: If True, return cached DCs if available

        Returns:
            List of DC hostnames
        """
        if use_cache and self.dc_servers:
            return list(self.dc_servers)

        discovered: Set[str] = set()

        # Try DNS discovery first (cross-platform)
        dns_dcs = _discover_dcs_via_dns(self.domain)
        discovered.update(dns_dcs)
        self._logger.info("dns_discovery", found=len(dns_dcs))

        # Try Netlogon on Windows
        if sys.platform == "win32":
            netlogon_dcs = _discover_dcs_via_netlogon(self.domain)
            discovered.update(netlogon_dcs)
            self._logger.info("netlogon_discovery", found=len(netlogon_dcs))

        # Try LDAP as fallback
        if not discovered:
            ldap_dcs = _discover_dcs_via_ldap(self.domain)
            discovered.update(ldap_dcs)
            self._logger.info("ldap_discovery", found=len(ldap_dcs))

        self.dc_servers = sorted(discovered)
        self._logger.info(
            "dc_discovery_complete",
            domain=self.domain,
            total_dcs=len(self.dc_servers),
        )

        return list(self.dc_servers)

    def get_reader(self, server: str) -> SecurityEventLogReader:
        """Get or create a reader for a specific DC."""
        if server not in self._readers:
            self._readers[server] = SecurityEventLogReader(server=server)
        return self._readers[server]

    def query_all_dcs(
        self,
        event_ids: Optional[List[SecurityEventID]] = None,
        since: Optional[datetime] = None,
        username: Optional[str] = None,
        max_events_per_dc: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """
        Query events from all Domain Controllers in parallel.

        Args:
            event_ids: Event IDs to filter (None = all auth events)
            since: Only events after this time
            username: Filter by username
            max_events_per_dc: Maximum events per DC

        Returns:
            Combined list of events from all DCs, sorted by timestamp (newest first)
        """
        if not self.dc_servers:
            self.discover_domain_controllers()

        if not self.dc_servers:
            self._logger.warning("no_dcs_found", domain=self.domain)
            return []

        all_events: List[WindowsSecurityEvent] = []

        def query_dc(dc: str) -> List[WindowsSecurityEvent]:
            try:
                reader = self.get_reader(dc)
                return reader.query_events(
                    event_ids=event_ids,
                    since=since,
                    username=username,
                    max_events=max_events_per_dc,
                )
            except Exception as e:
                self._logger.warning("dc_query_failed", dc=dc, error=str(e))
                return []

        # Query DCs in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(query_dc, dc): dc for dc in self.dc_servers}

            for future in as_completed(futures, timeout=self.timeout_seconds):
                dc = futures[future]
                try:
                    events = future.result()
                    all_events.extend(events)
                    self._logger.debug("dc_query_complete", dc=dc, events=len(events))
                except Exception as e:
                    self._logger.warning("dc_query_error", dc=dc, error=str(e))

        # Deduplicate by record_id + computer_name (same event might be seen via different paths)
        seen: Set[Tuple[int, str]] = set()
        unique_events = []
        for event in all_events:
            key = (event.record_id, event.computer_name)
            if key not in seen:
                seen.add(key)
                unique_events.append(event)

        # Sort by timestamp (newest first)
        unique_events.sort(key=lambda e: e.timestamp, reverse=True)

        self._logger.info(
            "domain_query_complete",
            dcs_queried=len(self.dc_servers),
            total_events=len(unique_events),
        )

        return unique_events

    def get_domain_logons(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 1000,
    ) -> List[WindowsSecurityEvent]:
        """
        Get logon events (success and failed) from all DCs.

        Args:
            username: Filter by username
            since: Only events after this time
            max_events: Maximum total events

        Returns:
            List of logon events from all DCs
        """
        return self.query_all_dcs(
            event_ids=SecurityEventID.logon_events(),
            since=since,
            username=username,
            max_events_per_dc=max_events // max(len(self.dc_servers), 1),
        )[:max_events]

    def get_domain_successful_logons(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """Get successful logon events (4624) from all DCs."""
        return self.query_all_dcs(
            event_ids=[SecurityEventID.LOGON_SUCCESS],
            since=since,
            username=username,
            max_events_per_dc=max_events // max(len(self.dc_servers), 1),
        )[:max_events]

    def get_domain_failed_logons(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        window_minutes: int = 15,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """
        Get failed logon events (4625) from all DCs.

        Useful for detecting brute force attacks across the domain.
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        return self.query_all_dcs(
            event_ids=[SecurityEventID.LOGON_FAILED],
            since=since,
            username=username,
            max_events_per_dc=max_events // max(len(self.dc_servers), 1),
        )[:max_events]

    def get_domain_kerberos_events(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """Get Kerberos events (4768, 4769, 4771) from all DCs."""
        return self.query_all_dcs(
            event_ids=SecurityEventID.kerberos_events(),
            since=since,
            username=username,
            max_events_per_dc=max_events // max(len(self.dc_servers), 1),
        )[:max_events]

    def get_domain_ntlm_events(
        self,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
        max_events: int = 500,
    ) -> List[WindowsSecurityEvent]:
        """Get NTLM credential validation events (4776) from all DCs."""
        return self.query_all_dcs(
            event_ids=SecurityEventID.ntlm_events(),
            since=since,
            username=username,
            max_events_per_dc=max_events // max(len(self.dc_servers), 1),
        )[:max_events]

    def count_domain_failed_logons(
        self,
        username: str,
        window_minutes: int = 15,
    ) -> int:
        """
        Count failed logon attempts for a user across all DCs.

        Useful for detecting distributed brute force attacks.

        Args:
            username: Username to check
            window_minutes: Time window in minutes

        Returns:
            Total failed logon count across domain
        """
        events = self.get_domain_failed_logons(
            username=username,
            window_minutes=window_minutes,
        )
        return len(events)

    def get_user_login_history(
        self,
        username: str,
        since: Optional[datetime] = None,
        max_events: int = 100,
    ) -> List[WindowsSecurityEvent]:
        """
        Get complete login history for a user across the domain.

        Includes all authentication-related events.

        Args:
            username: Username to query
            since: Only events after this time
            max_events: Maximum events to return

        Returns:
            List of authentication events for the user
        """
        return self.query_all_dcs(
            event_ids=SecurityEventID.all_auth_events(),
            since=since,
            username=username,
            max_events_per_dc=max_events,
        )[:max_events]

    def get_statistics(
        self,
        since: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get domain-wide authentication statistics.

        Args:
            since: Start time for statistics

        Returns:
            Dictionary with statistics
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=24)

        events = self.query_all_dcs(since=since, max_events_per_dc=1000)

        successful = sum(1 for e in events if e.is_success)
        failed = sum(1 for e in events if e.is_failure)
        kerberos = sum(1 for e in events if e.is_kerberos)
        ntlm = sum(1 for e in events if e.is_ntlm)
        unique_users = len(set(e.target_username for e in events if e.target_username))

        return {
            "domain": self.domain,
            "dcs_monitored": len(self.dc_servers),
            "since": since.isoformat(),
            "total_events": len(events),
            "successful_logons": successful,
            "failed_logons": failed,
            "success_rate": (successful / len(events) * 100) if events else 0.0,
            "kerberos_events": kerberos,
            "ntlm_events": ntlm,
            "unique_users": unique_users,
        }
