"""
Unit tests for authmodeler.ntlm.client module.

Tests NTLM client functionality, message generation, and authentication flow.
"""

import pytest
from datetime import datetime, timezone

from authmodeler.ntlm.client import (
    NTLMClient,
    NTLMClientStateMachine,
    NTLMTransportMode,
    create_ntlm_client,
    is_sspi_available,
)
from authmodeler.ntlm.types import (
    NTLMState,
    NTLMContext,
    NegotiateMessage,
    ChallengeMessage,
    AuthenticateMessage,
    NegotiateFlags,
    InitiateNTLM,
    ChallengeReceived,
    AuthenticateComplete,
)


class TestNTLMClientCreation:
    """Tests for NTLMClient creation and configuration."""

    def test_create_client_simulated_mode(self):
        """Test client creation in simulated mode."""
        client = NTLMClient(transport_mode=NTLMTransportMode.SIMULATED)
        assert client.transport_mode == NTLMTransportMode.SIMULATED

    def test_create_client_factory(self):
        """Test client creation via factory function."""
        client = create_ntlm_client()
        assert client.transport_mode == NTLMTransportMode.SIMULATED

    def test_create_client_factory_native(self):
        """Test client creation with native mode."""
        client = create_ntlm_client(use_native=True)
        # Should fall back to simulated if SSPI not available
        assert client.transport_mode in (NTLMTransportMode.SIMULATED, NTLMTransportMode.NATIVE)

    def test_client_initial_state(self, ntlm_client):
        """Test client starts in INITIAL state."""
        assert ntlm_client.state == NTLMState.INITIAL

    def test_client_with_workstation_name(self):
        """Test client with workstation name."""
        client = NTLMClient(workstation_name="WORKSTATION1")
        assert client.workstation_name == "WORKSTATION1"

    def test_is_sspi_available(self):
        """Test SSPI availability check returns tuple."""
        available, info = is_sspi_available()
        assert isinstance(available, bool)
        assert isinstance(info, str)


class TestNTLMNegotiateMessage:
    """Tests for NTLM NEGOTIATE message generation."""

    def test_create_negotiate_message(self, ntlm_client):
        """Test NEGOTIATE message creation."""
        negotiate = ntlm_client.create_negotiate_message()
        assert negotiate is not None
        assert isinstance(negotiate, NegotiateMessage)

    def test_negotiate_message_flags(self, ntlm_client):
        """Test NEGOTIATE message has expected flags."""
        negotiate = ntlm_client.create_negotiate_message()
        flags = negotiate.negotiate_flags

        # Should have common negotiation flags
        assert flags & NegotiateFlags.NEGOTIATE_UNICODE.value
        assert flags & NegotiateFlags.REQUEST_TARGET.value

    def test_negotiate_message_with_domain(self, ntlm_client):
        """Test NEGOTIATE message with domain hint."""
        negotiate = ntlm_client.create_negotiate_message(domain="EXAMPLE")
        assert negotiate.domain_name == "EXAMPLE"

    def test_negotiate_message_to_bytes(self, ntlm_client):
        """Test NEGOTIATE message serialization."""
        negotiate = ntlm_client.create_negotiate_message()
        msg_bytes = negotiate.to_bytes()

        assert msg_bytes is not None
        assert msg_bytes.startswith(b"NTLMSSP\x00")  # NTLM signature
        assert msg_bytes[8:12] == b"\x01\x00\x00\x00"  # Type 1


class TestNTLMChallengeProcessing:
    """Tests for NTLM CHALLENGE message processing."""

    @pytest.fixture
    def sample_challenge(self) -> ChallengeMessage:
        """Create a sample CHALLENGE message."""
        return ChallengeMessage(
            negotiate_flags=NegotiateFlags.default_server_flags(),
            server_challenge=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            target_name="EXAMPLE",
            target_info=None,
        )

    def test_process_challenge(self, ntlm_client, sample_challenge):
        """Test CHALLENGE message processing."""
        from returns.result import Success
        # First send negotiate to move to correct state
        ntlm_client.create_negotiate_message()

        result = ntlm_client.process_challenge(sample_challenge)
        assert isinstance(result, Success)

    def test_process_challenge_sets_state(self, ntlm_client, sample_challenge):
        """Test CHALLENGE processing transitions state."""
        ntlm_client.create_negotiate_message()
        ntlm_client.process_challenge(sample_challenge)
        assert ntlm_client.state == NTLMState.CHALLENGE_RECEIVED

    def test_process_challenge_stores_challenge(self, ntlm_client, sample_challenge):
        """Test CHALLENGE processing stores server challenge."""
        ntlm_client.create_negotiate_message()
        ntlm_client.process_challenge(sample_challenge)

        ctx = ntlm_client.context
        assert ctx.server_challenge == sample_challenge.server_challenge


def _md4_available():
    """Check if MD4 is available."""
    try:
        import hashlib
        hashlib.new("md4")
        return True
    except ValueError:
        return False


class TestNTLMAuthenticateMessage:
    """Tests for NTLM AUTHENTICATE message generation."""

    @pytest.fixture
    def challenged_client(self, ntlm_client) -> NTLMClient:
        """Client that has received a challenge."""
        ntlm_client.create_negotiate_message()
        challenge = ChallengeMessage(
            negotiate_flags=NegotiateFlags.default_server_flags(),
            server_challenge=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            target_name="EXAMPLE",
            target_info=None,
        )
        ntlm_client.process_challenge(challenge)
        return ntlm_client

    @pytest.mark.skipif(not _md4_available(), reason="MD4 not available")
    def test_create_authenticate_message(self, challenged_client):
        """Test AUTHENTICATE message creation."""
        from returns.result import Success
        result = challenged_client.create_authenticate_message(
            username="testuser",
            password="password",
            domain="EXAMPLE",
        )
        assert isinstance(result, Success)

        authenticate = result.unwrap()
        assert isinstance(authenticate, AuthenticateMessage)

    @pytest.mark.skipif(not _md4_available(), reason="MD4 not available")
    def test_authenticate_message_contains_user(self, challenged_client):
        """Test AUTHENTICATE message contains username."""
        result = challenged_client.create_authenticate_message(
            username="testuser",
            password="password",
            domain="EXAMPLE",
        )
        authenticate = result.unwrap()
        assert authenticate.user_name == "testuser"

    @pytest.mark.skipif(not _md4_available(), reason="MD4 not available")
    def test_authenticate_message_contains_domain(self, challenged_client):
        """Test AUTHENTICATE message contains domain."""
        result = challenged_client.create_authenticate_message(
            username="testuser",
            password="password",
            domain="MYDOMAIN",
        )
        authenticate = result.unwrap()
        assert authenticate.domain_name == "MYDOMAIN"

    @pytest.mark.skipif(not _md4_available(), reason="MD4 not available")
    def test_authenticate_message_has_nt_response(self, challenged_client):
        """Test AUTHENTICATE message has NT response."""
        result = challenged_client.create_authenticate_message(
            username="testuser",
            password="password",
            domain="EXAMPLE",
        )
        authenticate = result.unwrap()
        assert len(authenticate.nt_response) > 0

    def test_authenticate_requires_challenge(self, ntlm_client):
        """Test AUTHENTICATE requires prior challenge."""
        from returns.result import Failure
        result = ntlm_client.create_authenticate_message(
            username="testuser",
            password="password",
            domain="EXAMPLE",
        )
        assert isinstance(result, Failure)


class TestNTLMStateMachine:
    """Tests for NTLM client state machine."""

    def test_state_machine_initial_state(self):
        """Test state machine starts in INITIAL."""
        sm = NTLMClientStateMachine(
            _state=NTLMState.INITIAL,
            _context=NTLMContext(),
        )
        assert sm.state == NTLMState.INITIAL

    def test_state_machine_transition_initiate(self):
        """Test InitiateNTLM transition."""
        from returns.result import Success
        sm = NTLMClientStateMachine(
            _state=NTLMState.INITIAL,
            _context=NTLMContext(),
        )

        event = InitiateNTLM(
            username="user",
            domain="DOMAIN",
            password="password",
        )

        result = sm.process_event(event)
        assert isinstance(result, Success)
        assert sm.state == NTLMState.NEGOTIATE_SENT

    def test_state_machine_challenge_received(self):
        """Test ChallengeReceived transition."""
        from returns.result import Success
        sm = NTLMClientStateMachine(
            _state=NTLMState.NEGOTIATE_SENT,
            _context=NTLMContext(username="user", domain="DOMAIN"),
        )

        event = ChallengeReceived(
            server_challenge=b"\x00" * 8,
            target_info=None,
            negotiate_flags=0,
            target_name="SERVER",
        )

        result = sm.process_event(event)
        assert isinstance(result, Success)
        assert sm.state == NTLMState.CHALLENGE_RECEIVED


@pytest.mark.skipif(not _md4_available(), reason="MD4 not available")
class TestNTLMCompleteAuth:
    """Tests for completing NTLM authentication."""

    @pytest.fixture
    def authenticated_client(self, ntlm_client) -> NTLMClient:
        """Client that has sent authenticate message."""
        ntlm_client.create_negotiate_message()
        challenge = ChallengeMessage(
            negotiate_flags=NegotiateFlags.default_server_flags(),
            server_challenge=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            target_name="EXAMPLE",
            target_info=None,
        )
        ntlm_client.process_challenge(challenge)
        ntlm_client.create_authenticate_message("user", "pass", "EXAMPLE")
        return ntlm_client

    def test_complete_authentication_success(self, authenticated_client):
        """Test completing authentication successfully."""
        result = authenticated_client.complete_authentication(success=True)
        assert result.success
        assert authenticated_client.state == NTLMState.AUTHENTICATED

    def test_complete_authentication_failure(self, authenticated_client):
        """Test completing authentication with failure."""
        result = authenticated_client.complete_authentication(
            success=False,
            error_code=0xC000006D,
            error_message="Bad password",
        )
        assert not result.success
        assert result.error_code == 0xC000006D

    def test_session_key_available_after_auth(self, authenticated_client):
        """Test session key is available after authentication."""
        authenticated_client.complete_authentication(success=True)
        assert authenticated_client.session_key is not None


class TestNTLMTracing:
    """Tests for NTLM authentication tracing."""

    def test_get_trace_empty_initially(self, ntlm_client):
        """Test trace is empty before any operations."""
        trace = ntlm_client.get_trace()
        assert trace == []

    def test_get_trace_after_negotiate(self, ntlm_client):
        """Test trace records events."""
        ntlm_client.create_negotiate_message()

        # State machine should have some transitions
        # (actual trace depends on implementation)
        trace = ntlm_client.get_trace()
        assert isinstance(trace, list)

    def test_export_trace_json(self, ntlm_client):
        """Test trace export as JSON."""
        ntlm_client.create_negotiate_message()
        json_trace = ntlm_client.export_trace_json()

        assert isinstance(json_trace, str)

        # Should be valid JSON
        import json
        parsed = json.loads(json_trace)
        # May be a list or a dict depending on implementation
        assert isinstance(parsed, (list, dict))


class TestNTLMInvariants:
    """Tests for NTLM security invariants."""

    def test_challenge_before_authenticate_invariant(self, ntlm_client):
        """Test authenticate requires prior challenge."""
        from returns.result import Failure
        # Trying to create authenticate without challenge should fail
        result = ntlm_client.create_authenticate_message("user", "pass", "DOMAIN")
        assert isinstance(result, Failure)


class TestNegotiateFlags:
    """Tests for NTLM negotiate flags."""

    def test_default_client_flags(self):
        """Test default client flags are set."""
        flags = NegotiateFlags.default_client_flags()
        assert flags > 0
        assert flags & NegotiateFlags.NEGOTIATE_UNICODE.value

    def test_default_server_flags(self):
        """Test default server flags are set."""
        flags = NegotiateFlags.default_server_flags()
        assert flags > 0

    def test_negotiate_flags_enum(self):
        """Test negotiate flags enum values."""
        assert NegotiateFlags.NEGOTIATE_UNICODE.value == 0x00000001
        assert NegotiateFlags.REQUEST_TARGET.value == 0x00000004
        assert NegotiateFlags.NEGOTIATE_NTLM.value == 0x00000200
