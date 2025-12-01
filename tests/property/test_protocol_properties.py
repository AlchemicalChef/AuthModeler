"""
Property-based tests for protocol invariants.

Tests that Kerberos and NTLM protocol implementations maintain
required security properties across many random inputs.
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from datetime import datetime, timedelta, timezone

from authmodeler.core.types import (
    Principal,
    Realm,
    Timestamp,
    Nonce,
    TicketTimes,
    SessionKey,
    EncryptionType,
)
from authmodeler.kerberos.client import KerberosClient, TransportMode
from authmodeler.ntlm.client import NTLMClient, NTLMTransportMode


# =============================================================================
# STRATEGIES
# =============================================================================

# Strategy for valid realm names (uppercase alphanumeric with dots)
realm_name_strategy = st.from_regex(r"[A-Z][A-Z0-9]{1,10}(\.[A-Z][A-Z0-9]{1,10})?", fullmatch=True)

# Strategy for valid principal names
principal_name_strategy = st.from_regex(r"[a-z][a-z0-9_]{0,19}", fullmatch=True)

# Strategy for service principal names
service_principal_strategy = st.from_regex(r"[a-z]+/[a-z][a-z0-9\-\.]{0,30}", fullmatch=True)

# Strategy for passwords
password_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N', 'P')),
    min_size=8,
    max_size=64,
)


# =============================================================================
# TIMESTAMP AND NONCE PROPERTIES
# =============================================================================


class TestTimestampProperties:
    """Property-based tests for Timestamp."""

    @given(st.integers(min_value=1, max_value=3600))  # Start at 1 to avoid edge case
    def test_timestamp_validity_with_skew(self, skew_seconds: int):
        """Property: Fresh timestamp is valid within skew tolerance."""
        ts = Timestamp()
        reference = datetime.now(timezone.utc)
        skew = timedelta(seconds=skew_seconds)
        assert ts.is_within_skew(reference, skew=skew)

    @given(st.integers(min_value=1, max_value=3600))
    def test_expired_timestamp_invalid(self, age_seconds: int):
        """Property: Old timestamp is invalid with small skew."""
        old_time = datetime.now(timezone.utc) - timedelta(seconds=age_seconds + 10)
        ts = Timestamp(time=old_time)
        reference = datetime.now(timezone.utc)
        skew = timedelta(seconds=5)  # 5 second skew
        assert not ts.is_within_skew(reference, skew=skew)


class TestNonceProperties:
    """Property-based tests for Nonce."""

    @given(st.integers(min_value=0, max_value=2**31))
    def test_nonce_from_int(self, value: int):
        """Property: Nonce.from_int preserves value."""
        nonce = Nonce.from_int(value)
        assert nonce.as_int == value

    @settings(max_examples=100)
    @given(st.just(None))  # Use st.just(None) instead of st.nothing()
    def test_nonces_unique(self, _):
        """Property: Random nonces are unique."""
        nonce1 = Nonce()
        nonce2 = Nonce()
        assert nonce1.as_int != nonce2.as_int


# =============================================================================
# TICKET TIMES PROPERTIES
# =============================================================================


class TestTicketTimesProperties:
    """Property-based tests for TicketTimes."""

    @given(
        validity_hours=st.integers(min_value=1, max_value=24),
        renew_days=st.integers(min_value=1, max_value=7),
    )
    def test_valid_ticket_times(self, validity_hours: int, renew_days: int):
        """Property: Properly constructed ticket times are valid."""
        now = datetime.now(timezone.utc)
        times = TicketTimes(
            auth_time=now,
            start_time=now,
            end_time=now + timedelta(hours=validity_hours),
            renew_till=now + timedelta(hours=validity_hours) + timedelta(days=renew_days),
        )
        assert times.is_valid_at()

    @given(st.integers(min_value=1, max_value=100))
    def test_expired_ticket_times_invalid(self, hours_ago: int):
        """Property: Expired ticket times are invalid."""
        past = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        times = TicketTimes(
            auth_time=past - timedelta(hours=10),
            start_time=past - timedelta(hours=10),
            end_time=past,
            renew_till=past + timedelta(days=6),
        )
        assert not times.is_valid_at()

    @given(
        validity_hours=st.integers(min_value=1, max_value=24),
    )
    def test_valid_at_future_invalid(self, validity_hours: int):
        """Property: Valid ticket is invalid after end_time."""
        now = datetime.now(timezone.utc)
        end_time = now + timedelta(hours=validity_hours)
        times = TicketTimes(
            auth_time=now,
            start_time=now,
            end_time=end_time,
            renew_till=end_time + timedelta(days=7),
        )
        # Should be valid now
        assert times.is_valid_at(now)
        # Should be invalid after end_time
        assert not times.is_valid_at(end_time + timedelta(seconds=1))


# =============================================================================
# PRINCIPAL PROPERTIES
# =============================================================================


class TestPrincipalProperties:
    """Property-based tests for Principal."""

    @given(name=principal_name_strategy, realm_name=realm_name_strategy)
    @settings(max_examples=50)
    def test_principal_full_name_format(self, name: str, realm_name: str):
        """Property: Full name is name@realm."""
        realm = Realm(realm_name)
        principal = Principal(name=name, realm=realm)
        assert str(principal) == f"{name}@{realm_name}"

    @given(
        name1=principal_name_strategy,
        name2=principal_name_strategy,
        realm_name=realm_name_strategy,
    )
    @settings(max_examples=50)
    def test_principals_equal_iff_same_name_realm(
        self, name1: str, name2: str, realm_name: str
    ):
        """Property: Principals equal iff same name and realm."""
        realm = Realm(realm_name)
        p1 = Principal(name=name1, realm=realm)
        p2 = Principal(name=name2, realm=realm)

        if name1 == name2:
            assert p1 == p2
        else:
            assert p1 != p2


# =============================================================================
# KERBEROS CLIENT PROPERTIES
# =============================================================================


class TestKerberosClientProperties:
    """Property-based tests for Kerberos client."""

    @given(
        realm_name=realm_name_strategy,
        username=principal_name_strategy,
        password=password_strategy,
    )
    @settings(max_examples=20)
    def test_authentication_creates_principal(
        self, realm_name: str, username: str, password: str
    ):
        """Property: Successful auth creates correct principal."""
        client = KerberosClient(
            realm=Realm(realm_name),
            transport_mode=TransportMode.SIMULATED,
        )
        result = client.authenticate(username, password)

        assert result.success
        assert result.principal is not None
        assert result.principal.name == username

    @given(
        realm_name=realm_name_strategy,
        username=principal_name_strategy,
        password=password_strategy,
    )
    @settings(max_examples=20)
    def test_authentication_provides_session_key(
        self, realm_name: str, username: str, password: str
    ):
        """Property: Successful auth provides session key."""
        client = KerberosClient(
            realm=Realm(realm_name),
            transport_mode=TransportMode.SIMULATED,
        )
        result = client.authenticate(username, password)

        assert result.success
        assert result.session_key is not None
        assert len(result.session_key) > 0

    @given(
        realm_name=realm_name_strategy,
        username=principal_name_strategy,
        password=password_strategy,
    )
    @settings(max_examples=20)
    def test_authentication_provides_expiration(
        self, realm_name: str, username: str, password: str
    ):
        """Property: Successful auth provides future expiration."""
        client = KerberosClient(
            realm=Realm(realm_name),
            transport_mode=TransportMode.SIMULATED,
        )
        result = client.authenticate(username, password)

        assert result.success
        assert result.expiration is not None
        assert result.expiration > datetime.now(timezone.utc)

    @given(realm_name=realm_name_strategy)
    @settings(max_examples=10)
    def test_service_ticket_requires_tgt(self, realm_name: str):
        """Property: Service ticket requires prior authentication."""
        from returns.result import Failure
        client = KerberosClient(
            realm=Realm(realm_name),
            transport_mode=TransportMode.SIMULATED,
        )

        # Without authentication, service ticket should fail
        result = client.get_service_ticket("http/server.example.com")
        assert isinstance(result, Failure)


# =============================================================================
# NTLM CLIENT PROPERTIES
# =============================================================================


class TestNTLMClientProperties:
    """Property-based tests for NTLM client."""

    @given(domain=realm_name_strategy)
    @settings(max_examples=20)
    def test_negotiate_message_creation(self, domain: str):
        """Property: Negotiate message is always created successfully."""
        client = NTLMClient(transport_mode=NTLMTransportMode.SIMULATED)
        negotiate = client.create_negotiate_message(domain=domain)

        assert negotiate is not None
        assert negotiate.negotiate_flags > 0

    @given(domain=realm_name_strategy)
    @settings(max_examples=10)
    def test_authenticate_requires_challenge(self, domain: str):
        """Property: Authenticate requires prior challenge."""
        from returns.result import Failure
        client = NTLMClient(transport_mode=NTLMTransportMode.SIMULATED)

        # Without challenge, authenticate should fail
        result = client.create_authenticate_message(
            username="user",
            password="pass",
            domain=domain,
        )
        assert isinstance(result, Failure)


# =============================================================================
# SECURITY INVARIANTS
# =============================================================================


class TestSecurityInvariants:
    """Property-based tests for security invariants."""

    @given(
        username=principal_name_strategy,
        password1=password_strategy,
        password2=password_strategy,
    )
    @settings(max_examples=20)
    def test_different_passwords_different_session_keys(
        self, username: str, password1: str, password2: str
    ):
        """Property: Different passwords produce different session keys."""
        assume(password1 != password2)

        client1 = KerberosClient(
            realm=Realm("EXAMPLE.COM"),
            transport_mode=TransportMode.SIMULATED,
        )
        client2 = KerberosClient(
            realm=Realm("EXAMPLE.COM"),
            transport_mode=TransportMode.SIMULATED,
        )

        result1 = client1.authenticate(username, password1)
        result2 = client2.authenticate(username, password2)

        # Session keys should be different (they're randomly generated)
        assert result1.session_key != result2.session_key

    @given(
        username=principal_name_strategy,
        password=password_strategy,
    )
    @settings(max_examples=10)
    def test_trace_records_all_events(self, username: str, password: str):
        """Property: All authentication events are traced."""
        client = KerberosClient(
            realm=Realm("EXAMPLE.COM"),
            transport_mode=TransportMode.SIMULATED,
        )

        # Before auth, trace should be empty
        assert len(client.get_trace()) == 0

        # After auth, trace should have events
        client.authenticate(username, password)
        trace = client.get_trace()

        assert len(trace) > 0
