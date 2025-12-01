#!/usr/bin/env python3
"""
Service-Side Kerberos Authentication Example

Demonstrates how to use AuthModeler's KerberosService to validate
incoming AP-REQ messages from clients.

Features:
1. Service-side ticket validation
2. Authenticator decryption and verification
3. Replay attack prevention
4. Mutual authentication (AP-REP generation)
5. State machine trace export for verification

SPEC: specs/tla/Kerberos.tla - ServiceProcessAPRequest

Author: Keith Ramphal
"""

from datetime import datetime, timedelta, timezone

from returns.result import Success, Failure

from authmodeler.core.types import (
    EncryptionType,
    Principal,
    Realm,
    SessionKey,
    Timestamp,
)
from authmodeler.core.crypto import encrypt_aes_cts, generate_session_key
from authmodeler.kerberos import (
    KerberosService,
    KerberosClient,
    APRequest,
    Authenticator,
    DecryptedTicket,
    ServiceState,
    create_kerberos_service,
)


def main():
    """Demonstrate service-side Kerberos authentication."""

    print("=" * 70)
    print("AuthModeler - Service-Side Kerberos Authentication")
    print("=" * 70)
    print()

    # Configuration
    SERVICE_NAME = "HTTP/webserver.example.com"
    REALM = "EXAMPLE.COM"
    CLIENT_NAME = "jdoe"

    # ==========================================================================
    # EXAMPLE 1: Create Kerberos Service
    # ==========================================================================
    print("1. Create Kerberos Service")
    print("-" * 40)

    service = create_kerberos_service(
        service_name=SERVICE_NAME,
        realm=REALM,
        simulation_mode=True,  # Use simulation for demo
    )

    print(f"   Service Principal: {service.principal.name}")
    print(f"   Realm: {service.realm.name}")
    print(f"   Initial State: {service.state.name}")
    print()

    # ==========================================================================
    # EXAMPLE 2: Simulate Client AP-REQ
    # ==========================================================================
    print("2. Simulate Client AP-REQ")
    print("-" * 40)

    # Generate a session key (shared between client and service via ticket)
    session_key_material = generate_session_key(
        EncryptionType.AES256_CTS_HMAC_SHA1_96
    )
    session_key = SessionKey(
        enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        material=session_key_material,
    )

    # Create simulated ticket (in real scenario, this comes from KDC)
    client_realm = Realm(name=REALM)
    client_principal = Principal(name=CLIENT_NAME, realm=client_realm)
    end_time = datetime.now(timezone.utc) + timedelta(hours=8)

    # Format ticket for simulation
    ticket_bytes = (
        f"SVC_TKT:{CLIENT_NAME}:{REALM}:{session_key_material.hex()}"
        f":{end_time.isoformat()}"
    ).encode("utf-8")

    print(f"   Client: {CLIENT_NAME}@{REALM}")
    print(f"   Ticket Expiry: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Create authenticator (proves client has session key)
    auth_timestamp = Timestamp()
    authenticator_plaintext = (
        f"{CLIENT_NAME}|{auth_timestamp.time.isoformat()}".encode("utf-8")
    )

    # Encrypt authenticator with session key
    encrypted_auth, iv = encrypt_aes_cts(session_key_material, authenticator_plaintext)

    # Build AP-REQ
    ap_req = APRequest(
        ticket=ticket_bytes,
        authenticator=iv + encrypted_auth,
        mutual_required=True,
    )

    print(f"   Authenticator Time: {auth_timestamp.time.strftime('%H:%M:%S')}")
    print(f"   Mutual Auth Requested: {ap_req.mutual_required}")
    print()

    # ==========================================================================
    # EXAMPLE 3: Validate AP-REQ
    # ==========================================================================
    print("3. Validate AP-REQ")
    print("-" * 40)

    result = service.validate_ap_request(ap_req)

    if isinstance(result, Success):
        auth_result = result.unwrap()
        print(f"   Validation: SUCCESS")
        print(f"   Client Principal: {auth_result.client_principal.name}")
        print(f"   Client Realm: {auth_result.client_realm.name}")
        print(f"   Session Key Established: Yes")
        print(f"   Mutual Auth Required: {auth_result.mutual_auth_required}")
        print(f"   Service State: {service.state.name}")
    else:
        print(f"   Validation: FAILED")
        print(f"   Error: {result.failure()}")
    print()

    # ==========================================================================
    # EXAMPLE 4: Generate AP-REP (Mutual Authentication)
    # ==========================================================================
    print("4. Generate AP-REP (Mutual Authentication)")
    print("-" * 40)

    if isinstance(result, Success):
        auth_result = result.unwrap()

        if auth_result.mutual_auth_required:
            ap_rep_result = service.build_ap_reply(auth_result)

            if isinstance(ap_rep_result, Success):
                ap_rep = ap_rep_result.unwrap()
                print(f"   AP-REP Generated: Yes")
                print(f"   Encryption Type: {ap_rep.enc_type.name}")
                print(f"   Protocol Version: {ap_rep.pvno}")
                print("   (Client can verify service identity with this)")
            else:
                print(f"   AP-REP Error: {ap_rep_result.failure()}")
    print()

    # ==========================================================================
    # EXAMPLE 5: Replay Attack Detection
    # ==========================================================================
    print("5. Replay Attack Detection")
    print("-" * 40)

    print("   Attempting to replay the same AP-REQ...")

    replay_result = service.validate_ap_request(ap_req)

    if isinstance(replay_result, Failure):
        print(f"   Replay Detected: YES")
        print(f"   Error: {replay_result.failure()}")
    else:
        print(f"   WARNING: Replay not detected (unexpected)")

    cache_stats = service.get_replay_cache_stats()
    print(f"   Replay Cache Size: {cache_stats['size']}")
    print()

    # ==========================================================================
    # EXAMPLE 6: Expired Ticket Detection
    # ==========================================================================
    print("6. Expired Ticket Detection")
    print("-" * 40)

    # Create expired ticket
    expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
    expired_ticket = (
        f"SVC_TKT:expireduser:{REALM}:{session_key_material.hex()}"
        f":{expired_time.isoformat()}"
    ).encode("utf-8")

    # Create new authenticator to avoid replay detection
    new_timestamp = Timestamp()
    new_auth_plaintext = f"expireduser|{new_timestamp.time.isoformat()}".encode("utf-8")
    new_encrypted_auth, new_iv = encrypt_aes_cts(session_key_material, new_auth_plaintext)

    expired_ap_req = APRequest(
        ticket=expired_ticket,
        authenticator=new_iv + new_encrypted_auth,
        mutual_required=False,
    )

    expired_result = service.validate_ap_request(expired_ap_req)

    if isinstance(expired_result, Failure):
        print(f"   Expired Ticket Detected: YES")
        print(f"   Error: {expired_result.failure()}")
    else:
        print(f"   WARNING: Expired ticket not detected")
    print()

    # ==========================================================================
    # EXAMPLE 7: State Machine Trace
    # ==========================================================================
    print("7. State Machine Trace (for TLA+ verification)")
    print("-" * 40)

    trace = service.get_trace()
    print(f"   Total Transitions: {len(trace)}")

    for i, transition in enumerate(trace[:5]):  # Show first 5
        print(f"   [{i}] {transition['from_state']} --[{transition['event_type']}]--> "
              f"{transition['to_state']}")

    if len(trace) > 5:
        print(f"   ... and {len(trace) - 5} more transitions")

    print()
    print("   (Full trace can be exported with service.export_trace_json())")
    print()

    # ==========================================================================
    # SUMMARY
    # ==========================================================================
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print()
    print("This example demonstrated:")
    print("  1. Creating a KerberosService for AP-REQ validation")
    print("  2. Simulating client AP-REQ generation")
    print("  3. Service-side ticket and authenticator validation")
    print("  4. AP-REP generation for mutual authentication")
    print("  5. Replay attack prevention via authenticator cache")
    print("  6. Expired ticket detection")
    print("  7. State machine trace export for formal verification")
    print()
    print("For production use:")
    print("  - Configure service key from keytab file")
    print("  - Integrate with actual KDC-issued tickets")
    print("  - Set appropriate clock skew tolerance")
    print("  - Monitor replay cache size and cleanup")
    print()


if __name__ == "__main__":
    main()
