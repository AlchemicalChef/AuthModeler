#!/usr/bin/env python3
"""
Login Flow Monitoring Example

Demonstrates how to use AuthModeler to collect information on user login flows.
This example shows:
1. Basic authentication monitoring
2. Capturing login events and timing
3. Detecting failed login patterns
4. Exporting login data for analysis

Author: Keith Ramphal
"""

import json
from datetime import datetime, timedelta, timezone

from authmodeler.monitoring import (
    LoginFlowMonitor,
    LoginEventType,
    create_login_monitor,
)


def main():
    """Demonstrate login flow monitoring capabilities."""

    print("=" * 60)
    print("AuthModeler - Login Flow Monitoring Example")
    print("=" * 60)
    print()

    # Create a login monitor for your domain
    monitor = create_login_monitor(
        domain="EXAMPLE.COM",
        capture_sensitive_data=False,  # Don't log sensitive data
        max_history_size=1000,
    )

    # ==========================================================================
    # EXAMPLE 1: Basic Authentication Monitoring
    # ==========================================================================
    print("1. Basic Authentication Monitoring")
    print("-" * 40)

    # Authenticate a user - this captures all login events automatically
    result = monitor.authenticate(
        username="jdoe",
        password="SecurePassword123!",
        client_ip="192.168.1.100",
        client_hostname="workstation01",
    )

    print(f"   Username: jdoe")
    print(f"   Result: {'SUCCESS' if result.success else 'FAILED'}")

    # Get the detailed report
    report = monitor.get_last_report()
    if report:
        print(f"   Duration: {report.duration_ms:.2f}ms")
        print(f"   Protocol: {report.protocol_used.name if report.protocol_used else 'N/A'}")
        print(f"   Events captured: {len(report.events)}")
        print()

    # ==========================================================================
    # EXAMPLE 2: Multiple Login Attempts
    # ==========================================================================
    print("2. Multiple Login Attempts")
    print("-" * 40)

    # Simulate multiple users logging in
    users = [
        ("alice", "192.168.1.101", "laptop-alice"),
        ("bob", "192.168.1.102", "desktop-bob"),
        ("charlie", "192.168.1.103", "mobile-charlie"),
    ]

    for username, ip, hostname in users:
        result = monitor.authenticate(
            username=username,
            password="Password123!",
            client_ip=ip,
            client_hostname=hostname,
        )
        status = "SUCCESS" if result.success else "FAILED"
        print(f"   {username} from {ip}: {status}")

    print()

    # ==========================================================================
    # EXAMPLE 3: Get Login Statistics
    # ==========================================================================
    print("3. Login Statistics")
    print("-" * 40)

    stats = monitor.get_statistics()
    print(f"   Total logins: {stats['total_logins']}")
    print(f"   Successful: {stats['successful_logins']}")
    print(f"   Failed: {stats['failed_logins']}")
    print(f"   Success rate: {stats['success_rate']:.1f}%")
    print(f"   Avg duration: {stats['avg_duration_ms']:.2f}ms")
    print(f"   Unique users: {stats['unique_users']}")
    print(f"   Protocols used: {stats['protocols_used']}")
    print()

    # ==========================================================================
    # EXAMPLE 4: Query Login Reports
    # ==========================================================================
    print("4. Query Login Reports")
    print("-" * 40)

    # Get all reports for a specific user
    alice_reports = monitor.get_reports(username="alice", limit=10)
    print(f"   Reports for 'alice': {len(alice_reports)}")

    # Get only successful logins
    successful_reports = monitor.get_reports(success_only=True)
    print(f"   Successful logins: {len(successful_reports)}")

    # Get logins from the last hour
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_reports = monitor.get_reports(since=one_hour_ago)
    print(f"   Logins in last hour: {len(recent_reports)}")
    print()

    # ==========================================================================
    # EXAMPLE 5: Detect Failed Login Patterns (Brute Force Detection)
    # ==========================================================================
    print("5. Brute Force Detection")
    print("-" * 40)

    # Simulate failed login attempts
    test_user = "hacker_target"
    for i in range(5):
        monitor.authenticate(
            username=test_user,
            password=f"wrong_password_{i}",
            client_ip="10.0.0.1",
        )

    # Check failed login count
    failed_count = monitor.get_failed_login_count(
        username=test_user,
        window_minutes=15,
    )
    print(f"   Failed logins for '{test_user}' in last 15 min: {failed_count}")

    if failed_count >= 5:
        print(f"   WARNING: Possible brute force attack detected!")
    print()

    # ==========================================================================
    # EXAMPLE 6: Examine Login Events
    # ==========================================================================
    print("6. Examine Login Events")
    print("-" * 40)

    # Get the most recent report
    latest_report = monitor.get_last_report()
    if latest_report:
        print(f"   Flow ID: {latest_report.flow_id}")
        print(f"   Events in this login:")

        for event in latest_report.events[:5]:  # Show first 5 events
            print(f"      - {event.event_type.name} at {event.timestamp.strftime('%H:%M:%S.%f')}")
    print()

    # ==========================================================================
    # EXAMPLE 7: Export Login Data
    # ==========================================================================
    print("7. Export Login Data")
    print("-" * 40)

    # Export to JSON
    json_file = "login_history.json"
    monitor.export_json(json_file)
    print(f"   Exported JSON to: {json_file}")

    # Export to CSV
    csv_file = "login_summary.csv"
    monitor.export_csv(csv_file)
    print(f"   Exported CSV to: {csv_file}")

    # Export events only
    events_file = "login_events.json"
    monitor.export_events_json(events_file)
    print(f"   Exported events to: {events_file}")
    print()

    # ==========================================================================
    # EXAMPLE 8: Using Context Manager for Detailed Tracking
    # ==========================================================================
    print("8. Context Manager for Detailed Tracking")
    print("-" * 40)

    with monitor.track_login("admin", client_ip="10.10.10.1") as login_ctx:
        print(f"   Tracking login flow: {login_ctx.flow_id[:8]}...")

        # The authenticate call will automatically add events to this context
        result = monitor.authenticate(
            username="admin",
            password="AdminPassword!",
        )

        print(f"   Result: {'SUCCESS' if result.success else 'FAILED'}")
        print(f"   Events in context: {len(login_ctx.events)}")
    print()

    # ==========================================================================
    # EXAMPLE 9: View Detailed Report as JSON
    # ==========================================================================
    print("9. Detailed Report (JSON)")
    print("-" * 40)

    latest = monitor.get_last_report()
    if latest:
        report_dict = latest.to_dict()
        # Show a subset of the report
        summary = {
            "flow_id": report_dict["flow_id"][:8] + "...",
            "username": report_dict["username"],
            "success": report_dict["success"],
            "duration_ms": report_dict["duration_ms"],
            "events_count": len(report_dict["events"]),
        }
        print(f"   {json.dumps(summary, indent=6)}")
    print()

    # ==========================================================================
    # SUMMARY
    # ==========================================================================
    print("=" * 60)
    print("Summary")
    print("=" * 60)

    final_stats = monitor.get_statistics()
    print(f"Total login attempts monitored: {final_stats['total_logins']}")
    print(f"Unique users: {final_stats['unique_users']}")
    print(f"Success rate: {final_stats['success_rate']:.1f}%")
    print()
    print("Data exported to:")
    print(f"  - {json_file} (full history)")
    print(f"  - {csv_file} (summary)")
    print(f"  - {events_file} (all events)")
    print()


if __name__ == "__main__":
    main()
