"""
Pytest configuration and shared fixtures for AuthModeler tests.
"""

import pytest
from datetime import datetime, timedelta, timezone

from authmodeler.core.types import (
    Principal,
    Realm,
    SessionKey,
    EncryptionType,
    TicketTimes,
    TicketInfo,
    TicketFlag,
    Timestamp,
    Nonce,
    AuthResult,
    Protocol,
)
from authmodeler.kerberos.client import KerberosClient, TransportMode
from authmodeler.ntlm.client import NTLMClient, NTLMTransportMode
from authmodeler.ad.authenticator import ADAuthenticator, ADConfig


# =============================================================================
# REALM AND PRINCIPAL FIXTURES
# =============================================================================


@pytest.fixture
def test_realm() -> Realm:
    """Test Kerberos realm."""
    return Realm("EXAMPLE.COM")


@pytest.fixture
def test_principal(test_realm: Realm) -> Principal:
    """Test user principal."""
    return Principal(name="testuser", realm=test_realm)


@pytest.fixture
def service_principal(test_realm: Realm) -> Principal:
    """Test service principal."""
    return Principal(name="http/server.example.com", realm=test_realm)


@pytest.fixture
def krbtgt_principal(test_realm: Realm) -> Principal:
    """TGT service principal (krbtgt)."""
    return Principal(name=f"krbtgt/{test_realm.name}", realm=test_realm)


# =============================================================================
# CRYPTOGRAPHIC FIXTURES
# =============================================================================


@pytest.fixture
def test_session_key() -> SessionKey:
    """Test session key for AES256."""
    import secrets
    return SessionKey(
        enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        material=secrets.token_bytes(32),
    )


@pytest.fixture
def test_password() -> str:
    """Test password."""
    return "TestP@ssw0rd123!"


# =============================================================================
# TIME-RELATED FIXTURES
# =============================================================================


@pytest.fixture
def current_time() -> datetime:
    """Current UTC time."""
    return datetime.now(timezone.utc)


@pytest.fixture
def ticket_times(current_time: datetime) -> TicketTimes:
    """Standard ticket times (10 hour validity)."""
    return TicketTimes(
        auth_time=current_time,
        start_time=current_time,
        end_time=current_time + timedelta(hours=10),
        renew_till=current_time + timedelta(days=7),
    )


@pytest.fixture
def expired_ticket_times() -> TicketTimes:
    """Expired ticket times for testing expiration."""
    past = datetime.now(timezone.utc) - timedelta(hours=12)
    return TicketTimes(
        auth_time=past - timedelta(hours=10),
        start_time=past - timedelta(hours=10),
        end_time=past,
        renew_till=past + timedelta(days=6),
    )


# =============================================================================
# TICKET FIXTURES
# =============================================================================


@pytest.fixture
def tgt_info(
    test_principal: Principal,
    krbtgt_principal: Principal,
    test_session_key: SessionKey,
    ticket_times: TicketTimes,
    test_realm: Realm,
) -> TicketInfo:
    """Valid TGT ticket info."""
    return TicketInfo(
        client=test_principal,
        server=krbtgt_principal,
        session_key=test_session_key,
        times=ticket_times,
        flags=frozenset({TicketFlag.INITIAL, TicketFlag.RENEWABLE, TicketFlag.FORWARDABLE}),
        realm=test_realm,
    )


@pytest.fixture
def service_ticket_info(
    test_principal: Principal,
    service_principal: Principal,
    test_session_key: SessionKey,
    ticket_times: TicketTimes,
    test_realm: Realm,
) -> TicketInfo:
    """Valid service ticket info."""
    return TicketInfo(
        client=test_principal,
        server=service_principal,
        session_key=test_session_key,
        times=ticket_times,
        flags=frozenset({TicketFlag.FORWARDABLE}),
        realm=test_realm,
    )


# =============================================================================
# CLIENT FIXTURES
# =============================================================================


@pytest.fixture
def kerberos_client(test_realm: Realm) -> KerberosClient:
    """Kerberos client in simulated mode."""
    return KerberosClient(
        realm=test_realm,
        transport_mode=TransportMode.SIMULATED,
    )


@pytest.fixture
def ntlm_client() -> NTLMClient:
    """NTLM client in simulated mode."""
    return NTLMClient(
        transport_mode=NTLMTransportMode.SIMULATED,
    )


@pytest.fixture
def ad_config(test_realm: Realm) -> ADConfig:
    """AD configuration for testing."""
    return ADConfig(
        domain=test_realm.name,
        dc_host="dc.example.com",
        use_native=False,
    )


@pytest.fixture
def ad_authenticator(ad_config: ADConfig) -> ADAuthenticator:
    """AD authenticator in simulated mode."""
    return ADAuthenticator(config=ad_config)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def make_principal(name: str, realm: str = "EXAMPLE.COM") -> Principal:
    """Helper to create a principal."""
    return Principal(name=name, realm=Realm(realm))


def make_session_key(length: int = 32) -> SessionKey:
    """Helper to create a random session key."""
    import secrets
    return SessionKey(
        enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        material=secrets.token_bytes(length),
    )


# =============================================================================
# PYTEST MARKERS
# =============================================================================


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests requiring real AD environment"
    )
    config.addinivalue_line(
        "markers", "native: marks tests requiring native GSSAPI/SSPI"
    )
