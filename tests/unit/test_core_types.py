"""
Unit tests for authmodeler.core.types module.

Tests core type definitions, validators, and invariants.
"""

import pytest
from datetime import datetime, timedelta, timezone

from authmodeler.core.types import (
    Realm,
    Principal,
    SessionKey,
    EncryptionType,
    Timestamp,
    Nonce,
    TicketTimes,
    TicketInfo,
    TicketFlag,
    AuthResult,
    Protocol,
)


class TestRealm:
    """Tests for Realm type."""

    def test_realm_creation(self):
        """Test basic realm creation."""
        realm = Realm("EXAMPLE.COM")
        assert realm.name == "EXAMPLE.COM"

    def test_realm_uppercase_conversion(self):
        """Test realm name is auto-uppercased."""
        realm = Realm("example.com")
        assert realm.name == "EXAMPLE.COM"

    def test_realm_equality(self):
        """Test realm equality comparison."""
        r1 = Realm("EXAMPLE.COM")
        r2 = Realm("EXAMPLE.COM")
        r3 = Realm("OTHER.COM")

        assert r1 == r2
        assert r1 != r3

    def test_realm_hashable(self):
        """Test realm can be used in sets/dicts."""
        realm = Realm("EXAMPLE.COM")
        realm_set = {realm}
        assert realm in realm_set

    def test_realm_str(self):
        """Test realm string representation."""
        realm = Realm("EXAMPLE.COM")
        assert str(realm) == "EXAMPLE.COM"


class TestPrincipal:
    """Tests for Principal type."""

    def test_principal_creation(self, test_realm):
        """Test basic principal creation."""
        principal = Principal(name="user", realm=test_realm)
        assert principal.name == "user"
        assert principal.realm == test_realm

    def test_principal_str(self, test_realm):
        """Test principal string representation."""
        principal = Principal(name="user", realm=test_realm)
        assert str(principal) == "user@EXAMPLE.COM"

    def test_principal_equality(self, test_realm):
        """Test principal equality."""
        p1 = Principal(name="user", realm=test_realm)
        p2 = Principal(name="user", realm=test_realm)
        p3 = Principal(name="other", realm=test_realm)

        assert p1 == p2
        assert p1 != p3

    def test_service_principal(self, test_realm):
        """Test service principal with forward slash."""
        principal = Principal(name="http/server.example.com", realm=test_realm)
        assert principal.name == "http/server.example.com"
        assert str(principal) == "http/server.example.com@EXAMPLE.COM"

    def test_principal_from_string(self):
        """Test principal parsing from string."""
        principal = Principal.from_string("user@EXAMPLE.COM")
        assert principal.name == "user"
        assert principal.realm.name == "EXAMPLE.COM"

    def test_principal_from_string_with_slash(self):
        """Test service principal parsing from string."""
        principal = Principal.from_string("krbtgt/EXAMPLE.COM@EXAMPLE.COM")
        assert principal.name == "krbtgt/EXAMPLE.COM"
        assert principal.realm.name == "EXAMPLE.COM"


class TestSessionKey:
    """Tests for SessionKey type."""

    def test_session_key_creation(self):
        """Test session key creation."""
        material = b"\x00" * 32
        now = datetime.now(timezone.utc)
        key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=material,
            valid_from=now,
            valid_until=now + timedelta(hours=10),
        )
        assert key.enctype == EncryptionType.AES256_CTS_HMAC_SHA1_96
        assert key.material == material

    def test_session_key_length(self, test_session_key):
        """Test session key has correct length for AES256."""
        assert len(test_session_key.material) == 32

    def test_session_key_immutable(self, test_session_key):
        """Test session key material is immutable (bytes)."""
        assert isinstance(test_session_key.material, bytes)

    def test_session_key_validity(self):
        """Test session key validity check."""
        now = datetime.now(timezone.utc)
        key = SessionKey(
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            material=b"\x00" * 32,
            valid_from=now,
            valid_until=now + timedelta(hours=10),
        )
        assert key.is_valid_at(now)
        assert not key.is_valid_at(now + timedelta(hours=11))


class TestTimestamp:
    """Tests for Timestamp type."""

    def test_timestamp_creation(self):
        """Test timestamp creation with current time."""
        ts = Timestamp()
        assert ts.time is not None
        assert ts.time.tzinfo is not None  # Must be timezone-aware

    def test_timestamp_with_value(self):
        """Test timestamp with specific time."""
        specific_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        ts = Timestamp(time=specific_time)
        assert ts.time == specific_time

    def test_timestamp_is_within_skew(self):
        """Test timestamp skew check."""
        ts = Timestamp()
        reference = datetime.now(timezone.utc)
        # Fresh timestamp should be within skew
        assert ts.is_within_skew(reference, skew=timedelta(minutes=5))

    def test_timestamp_expired(self):
        """Test expired timestamp detection."""
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)
        ts = Timestamp(time=old_time)
        reference = datetime.now(timezone.utc)
        # Should be outside 5 minute skew
        assert not ts.is_within_skew(reference, skew=timedelta(minutes=5))

    def test_timestamp_usec(self):
        """Test timestamp with microseconds."""
        ts = Timestamp(usec=123456)
        assert ts.usec == 123456


class TestNonce:
    """Tests for Nonce type."""

    def test_nonce_creation(self):
        """Test nonce creation generates random value."""
        n1 = Nonce()
        n2 = Nonce()
        # Two nonces should be different
        assert n1.value != n2.value

    def test_nonce_from_int(self):
        """Test nonce creation from integer."""
        n = Nonce.from_int(12345)
        assert n.as_int == 12345

    def test_nonce_size(self):
        """Test nonce value is 4 bytes."""
        n = Nonce()
        assert len(n.value) == 4

    def test_nonce_as_int(self):
        """Test nonce as_int property."""
        n = Nonce()
        assert isinstance(n.as_int, int)
        assert 0 <= n.as_int < 2**32


class TestTicketTimes:
    """Tests for TicketTimes type."""

    def test_ticket_times_creation(self, current_time):
        """Test ticket times creation."""
        times = TicketTimes(
            auth_time=current_time,
            start_time=current_time,
            end_time=current_time + timedelta(hours=10),
            renew_till=current_time + timedelta(days=7),
        )
        assert times.auth_time == current_time
        assert times.end_time > times.start_time

    def test_ticket_times_is_valid_at(self, ticket_times):
        """Test valid ticket times."""
        assert ticket_times.is_valid_at()

    def test_ticket_times_expired(self, expired_ticket_times):
        """Test expired ticket times."""
        assert not expired_ticket_times.is_valid_at()

    def test_ticket_times_invalid_order(self, current_time):
        """Test ticket times rejects invalid time order."""
        with pytest.raises(ValueError):
            TicketTimes(
                auth_time=current_time,
                start_time=current_time,
                end_time=current_time - timedelta(hours=1),  # End before start
            )


class TestTicketInfo:
    """Tests for TicketInfo type."""

    def test_ticket_info_creation(self, tgt_info):
        """Test ticket info creation."""
        assert tgt_info.client is not None
        assert tgt_info.server is not None
        assert tgt_info.session_key is not None

    def test_ticket_info_flags(self, tgt_info):
        """Test ticket flags."""
        assert TicketFlag.INITIAL in tgt_info.flags
        assert TicketFlag.RENEWABLE in tgt_info.flags

    def test_ticket_info_is_valid(self, tgt_info):
        """Test ticket validity."""
        assert tgt_info.is_valid()

    def test_ticket_info_is_tgt(self, tgt_info):
        """Test TGT detection."""
        assert tgt_info.is_tgt

    def test_ticket_info_is_not_tgt(self, service_ticket_info):
        """Test service ticket is not TGT."""
        assert not service_ticket_info.is_tgt

    def test_ticket_info_is_renewable(self, tgt_info):
        """Test renewable ticket detection."""
        assert tgt_info.is_renewable

    def test_ticket_info_is_forwardable(self, tgt_info):
        """Test forwardable ticket detection."""
        assert tgt_info.is_forwardable


class TestAuthResult:
    """Tests for AuthResult type."""

    def test_auth_result_success(self, test_principal, test_session_key, current_time):
        """Test successful auth result."""
        result = AuthResult(
            success=True,
            principal=test_principal,
            session_key=test_session_key.material,
            expiration=current_time + timedelta(hours=10),
        )
        assert result.success
        assert result.principal == test_principal
        assert result.session_key is not None

    def test_auth_result_failure(self):
        """Test failed auth result."""
        result = AuthResult(
            success=False,
            principal=None,
            error_code=6,
            error_message="Client not found",
        )
        assert not result.success
        assert result.error_code == 6
        assert "not found" in result.error_message

    def test_auth_result_success_factory(self, test_principal):
        """Test success result factory method."""
        result = AuthResult.success_result(principal=test_principal)
        assert result.success
        assert result.principal == test_principal

    def test_auth_result_failure_factory(self):
        """Test failure result factory method."""
        result = AuthResult.failure_result("Authentication failed", error_code=5)
        assert not result.success
        assert result.error_code == 5


class TestProtocol:
    """Tests for Protocol enum."""

    def test_protocol_values(self):
        """Test protocol enum values exist."""
        assert Protocol.KERBEROS is not None
        assert Protocol.NTLM is not None
        assert Protocol.NEGOTIATE is not None

    def test_protocol_names(self):
        """Test protocol names."""
        assert Protocol.KERBEROS.name == "KERBEROS"
        assert Protocol.NTLM.name == "NTLM"


class TestEncryptionType:
    """Tests for EncryptionType enum."""

    def test_encryption_types(self):
        """Test common encryption types exist."""
        assert EncryptionType.AES256_CTS_HMAC_SHA1_96 is not None
        assert EncryptionType.AES128_CTS_HMAC_SHA1_96 is not None
        assert EncryptionType.RC4_HMAC is not None

    def test_encryption_type_values(self):
        """Test encryption type RFC values."""
        assert EncryptionType.AES256_CTS_HMAC_SHA1_96.value == 18
        assert EncryptionType.AES128_CTS_HMAC_SHA1_96.value == 17
        assert EncryptionType.RC4_HMAC.value == 23

    def test_encryption_type_key_size(self):
        """Test key size property."""
        assert EncryptionType.AES256_CTS_HMAC_SHA1_96.key_size == 32
        assert EncryptionType.AES128_CTS_HMAC_SHA1_96.key_size == 16
        assert EncryptionType.RC4_HMAC.key_size == 16

    def test_encryption_type_is_deprecated(self):
        """Test deprecated encryption type detection."""
        assert not EncryptionType.AES256_CTS_HMAC_SHA1_96.is_deprecated
        assert EncryptionType.DES_CBC_MD5.is_deprecated
