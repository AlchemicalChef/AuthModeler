#!/usr/bin/env python3
"""
Domain Controller Login Monitoring Example

Demonstrates how to use AuthModeler to monitor authentication events
from Active Directory Domain Controllers.

Features:
1. Domain Controller discovery
2. Query domain-wide login events
3. Real-time event subscriptions
4. Brute force attack detection
5. Correlate with AuthModeler logins

Requirements:
- Windows operating system
- pywin32 package installed
- Appropriate permissions to read Security Event Log from DCs
  (Domain Admin or delegated permissions)

Author: Keith Ramphal
"""

import sys
import time
from datetime import datetime, timedelta, timezone

# Check if running on Windows
if sys.platform != "win32":
    print("This example requires Windows with Active Directory access.")
    print("On non-Windows systems, the eventlog module is not available.")
    sys.exit(1)

from authmodeler.monitoring import (
    eventlog_available,
    create_login_monitor,
)

# Check if eventlog module is available
if not eventlog_available():
    print("Windows Event Log integration is not available.")
    print("Make sure pywin32 is installed: pip install pywin32")
    sys.exit(1)

from authmodeler.monitoring.eventlog import (
    DomainControllerMonitor,
    DomainEventSubscriber,
    SecurityEventID,
    SecurityEventLogReader,
    EventCorrelator,
    CorrelatedEvent,
)


def main():
    """Demonstrate domain-wide login monitoring."""

    print("=" * 70)
    print("AuthModeler - Domain Controller Login Monitoring")
    print("=" * 70)
    print()

    # Configuration - change this to your domain
    DOMAIN = "YOURDOMAIN.COM"  # Change to your domain

    # ==========================================================================
    # EXAMPLE 1: Discover Domain Controllers
    # ==========================================================================
    print("1. Discover Domain Controllers")
    print("-" * 40)

    monitor = DomainControllerMonitor(domain=DOMAIN)

    try:
        dc_servers = monitor.discover_domain_controllers()
        print(f"   Found {len(dc_servers)} domain controller(s):")
        for dc in dc_servers:
            print(f"      - {dc}")
    except Exception as e:
        print(f"   Error discovering DCs: {e}")
        print("   Using manual DC list (update with your DCs)")
        dc_servers = ["DC1.yourdomain.com", "DC2.yourdomain.com"]
        monitor.dc_servers = dc_servers
    print()

    # ==========================================================================
    # EXAMPLE 2: Query Recent Domain Logons
    # ==========================================================================
    print("2. Query Recent Domain Logons")
    print("-" * 40)

    try:
        # Get logons from the last hour
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        logons = monitor.get_domain_logons(since=one_hour_ago, max_events=20)

        print(f"   Found {len(logons)} logon events in the last hour:")
        for event in logons[:10]:  # Show first 10
            status = "SUCCESS" if event.is_success else "FAILED"
            print(f"      [{event.timestamp.strftime('%H:%M:%S')}] "
                  f"{event.full_username} - {status} - {event.source_ip}")
    except Exception as e:
        print(f"   Error querying events: {e}")
    print()

    # ==========================================================================
    # EXAMPLE 3: Query Specific User's Login History
    # ==========================================================================
    print("3. Query User Login History")
    print("-" * 40)

    test_user = "administrator"  # Change to a user in your domain
    try:
        user_events = monitor.get_user_login_history(
            username=test_user,
            since=datetime.now(timezone.utc) - timedelta(days=1),
            max_events=20,
        )

        print(f"   Login history for '{test_user}':")
        for event in user_events[:10]:
            print(f"      [{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
                  f"{event.event_id.name} from {event.source_ip or 'local'}")
        if not user_events:
            print(f"      No events found for user '{test_user}'")
    except Exception as e:
        print(f"   Error querying user history: {e}")
    print()

    # ==========================================================================
    # EXAMPLE 4: Detect Failed Logins (Brute Force Detection)
    # ==========================================================================
    print("4. Brute Force Detection")
    print("-" * 40)

    try:
        # Get failed logins in the last 15 minutes
        failed_logons = monitor.get_domain_failed_logons(window_minutes=15)

        # Group by username
        failed_by_user = {}
        for event in failed_logons:
            user = event.target_username
            if user:
                failed_by_user[user] = failed_by_user.get(user, 0) + 1

        print(f"   Failed logins in last 15 minutes: {len(failed_logons)}")
        if failed_by_user:
            print("   Users with failed logins:")
            for user, count in sorted(failed_by_user.items(), key=lambda x: -x[1])[:5]:
                alert = " *** ALERT: Possible brute force!" if count >= 5 else ""
                print(f"      {user}: {count} failed attempts{alert}")
        else:
            print("   No failed logins detected")
    except Exception as e:
        print(f"   Error checking failed logins: {e}")
    print()

    # ==========================================================================
    # EXAMPLE 5: Get Domain Statistics
    # ==========================================================================
    print("5. Domain Authentication Statistics (Last 24 Hours)")
    print("-" * 40)

    try:
        stats = monitor.get_statistics()
        print(f"   Domain: {stats['domain']}")
        print(f"   DCs Monitored: {stats['dcs_monitored']}")
        print(f"   Total Events: {stats['total_events']}")
        print(f"   Successful Logons: {stats['successful_logons']}")
        print(f"   Failed Logons: {stats['failed_logons']}")
        print(f"   Success Rate: {stats['success_rate']:.1f}%")
        print(f"   Kerberos Events: {stats['kerberos_events']}")
        print(f"   NTLM Events: {stats['ntlm_events']}")
        print(f"   Unique Users: {stats['unique_users']}")
    except Exception as e:
        print(f"   Error getting statistics: {e}")
    print()

    # ==========================================================================
    # EXAMPLE 6: Real-time Event Subscription
    # ==========================================================================
    print("6. Real-time Event Subscription (5 seconds)")
    print("-" * 40)

    event_count = [0]  # Use list to allow modification in callback

    def on_login_event(event):
        """Callback for real-time login events."""
        event_count[0] += 1
        status = "SUCCESS" if event.is_success else "FAILED"
        print(f"   >> [{event.computer_name}] {event.full_username}: "
              f"{event.event_id.name} - {status}")

    try:
        subscriber = DomainEventSubscriber(
            dc_servers=dc_servers,
            event_ids=[SecurityEventID.LOGON_SUCCESS, SecurityEventID.LOGON_FAILED],
            callback=on_login_event,
        )

        print("   Starting real-time subscription...")
        results = subscriber.start_all()
        active = sum(1 for v in results.values() if v)
        print(f"   Active subscriptions: {active}/{len(dc_servers)}")
        print("   Waiting for events (5 seconds)...")

        time.sleep(5)

        subscriber.stop_all()
        print(f"   Received {event_count[0]} events during subscription")

    except Exception as e:
        print(f"   Subscription error: {e}")
    print()

    # ==========================================================================
    # EXAMPLE 7: Correlate AuthModeler Login with Windows Events
    # ==========================================================================
    print("7. Correlate AuthModeler Login with Windows Events")
    print("-" * 40)

    try:
        # Create AuthModeler login monitor
        login_monitor = create_login_monitor(domain=DOMAIN)

        # Create reader for local machine (or use specific DC)
        reader = SecurityEventLogReader()
        correlator = EventCorrelator(reader=reader)

        # Perform authentication (this will use simulated mode)
        print("   Performing AuthModeler authentication...")
        result = login_monitor.authenticate(
            username="testuser",
            password="TestPassword123!",
            client_ip="192.168.1.100",
        )
        print(f"   AuthModeler result: {'SUCCESS' if result.success else 'FAILED'}")

        # Get the report
        report = login_monitor.get_last_report()
        if report:
            # Correlate with Windows events
            correlated = correlator.correlate_login_report(report)
            print(f"   Correlation results:")
            print(f"      Windows events found: {len(correlated.windows_events)}")
            print(f"      Confidence: {correlated.correlation_confidence:.1%}")
            print(f"      Method: {correlated.correlation_method}")
            if correlated.event_mismatch:
                print("      WARNING: Mismatch between AuthModeler and Windows results")

    except Exception as e:
        print(f"   Correlation error: {e}")
    print()

    # ==========================================================================
    # SUMMARY
    # ==========================================================================
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print()
    print("This example demonstrated:")
    print("  1. Domain Controller discovery")
    print("  2. Querying domain-wide login events")
    print("  3. User login history retrieval")
    print("  4. Brute force attack detection")
    print("  5. Domain authentication statistics")
    print("  6. Real-time event subscriptions")
    print("  7. Correlation with AuthModeler logins")
    print()
    print("For production use:")
    print("  - Set up appropriate service account permissions")
    print("  - Add user to 'Event Log Readers' group or grant SeSecurityPrivilege")
    print("  - Consider using Windows Event Forwarding for centralized collection")
    print()


if __name__ == "__main__":
    main()
