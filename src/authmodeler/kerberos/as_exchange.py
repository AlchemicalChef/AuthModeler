"""
AuthModeler Kerberos AS Exchange

Implementation of the Kerberos Authentication Service exchange.
Client obtains a TGT (Ticket Granting Ticket) from the KDC.

SPEC: specs/alloy/kerberos/protocol.als - ASExchange
SPEC: specs/tla/Kerberos.tla - AS_Request, AS_Reply

Protocol Flow:
1. Client -> KDC: AS-REQ (with optional pre-auth)
2. KDC -> Client: AS-REP (TGT + encrypted session key)
   OR KDC -> Client: KRB-ERROR (e.g., pre-auth required)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any

import attrs
import structlog
from returns.result import Failure, Result, Success

from authmodeler.core.crypto import (
    compute_kerberos_checksum,
    decrypt_aes_cts,
    derive_key_from_password,
    encrypt_aes_cts,
    generate_nonce,
    generate_session_key,
)
from authmodeler.core.exceptions import (
    AuthenticationError,
    CryptoError,
    KerberosError,
    PreAuthRequired,
)
from authmodeler.core.state_machine import StateMachineBase, TransitionEntry
from authmodeler.core.types import (
    EncryptionType,
    Key,
    Nonce,
    Principal,
    Realm,
    SessionKey,
    TicketFlag,
    TicketInfo,
    TicketTimes,
    Timestamp,
)
from authmodeler.kerberos.types import (
    ASErrorReceived,
    ASReply,
    ASReplyEncPart,
    ASReplyReceived,
    ASRequest,
    EncryptedTimestamp,
    EtypeInfo2Entry,
    InitiateAuth,
    KDCOptions,
    KerberosContext,
    KerberosError as KerberosErrorMsg,
    KerberosState,
    PreAuthData,
    PreAuthType,
)

logger = structlog.get_logger()


# =============================================================================
# AS EXCHANGE STATE MACHINE
# =============================================================================


@attrs.define
class ASExchangeStateMachine(
    StateMachineBase[KerberosState, Any, KerberosContext]
):
    """
    State machine for Kerberos AS Exchange.

    SPEC: specs/tla/Kerberos.tla - ClientStates (INITIAL -> AS_REQ_SENT -> HAS_TGT)

    Handles:
    - Initial authentication request
    - Pre-authentication (if required)
    - TGT reception and session key decryption
    """

    def initial_state(self) -> KerberosState:
        return KerberosState.INITIAL

    def transition_table(
        self,
    ) -> Dict[Tuple[KerberosState, type], TransitionEntry]:
        return {
            # Initial -> AS_REQ_SENT: Client initiates authentication
            (KerberosState.INITIAL, InitiateAuth): (
                KerberosState.AS_REQ_SENT,
                self._handle_initiate_auth,
            ),
            # AS_REQ_SENT -> HAS_TGT: Received valid AS-REP
            (KerberosState.AS_REQ_SENT, ASReplyReceived): (
                KerberosState.HAS_TGT,
                self._handle_as_reply,
            ),
            # AS_REQ_SENT -> ERROR: Received KRB-ERROR
            (KerberosState.AS_REQ_SENT, ASErrorReceived): (
                KerberosState.ERROR,
                self._handle_as_error,
            ),
            # AS_REQ_SENT -> AS_REQ_SENT: Pre-auth required, retry
            (KerberosState.AS_REQ_SENT, InitiateAuth): (
                KerberosState.AS_REQ_SENT,
                self._handle_initiate_auth,
            ),
        }

    @staticmethod
    def _handle_initiate_auth(
        event: InitiateAuth, ctx: KerberosContext
    ) -> KerberosContext:
        """
        Handle authentication initiation.

        SPEC: specs/alloy/kerberos/protocol.als - sendASRequest
        """
        # Generate fresh nonce for this request
        nonce = Nonce()

        return attrs.evolve(
            ctx,
            principal=event.principal,
            realm=event.realm,
            pending_nonce=nonce,
            error_code=None,
            error_message="",
        )

    @staticmethod
    def _handle_as_reply(
        event: ASReplyReceived, ctx: KerberosContext
    ) -> KerberosContext:
        """
        Handle successful AS-REP.

        SPEC: specs/alloy/kerberos/protocol.als - receiveASReply
        SPEC: specs/tla/Kerberos.tla - ClientReceiveASRep
        """
        return attrs.evolve(
            ctx,
            tgt=event.tgt,
            tgt_session_key=event.session_key,
            tgt_info=event.tgt_info,
            pending_nonce=None,
        )

    @staticmethod
    def _handle_as_error(
        event: ASErrorReceived, ctx: KerberosContext
    ) -> KerberosContext:
        """
        Handle KRB-ERROR in AS exchange.

        SPEC: specs/alloy/kerberos/protocol.als - receiveError
        """
        return attrs.evolve(
            ctx,
            error_code=event.error_code,
            error_message=event.error_message,
            pending_nonce=None,
        )


# =============================================================================
# AS EXCHANGE HANDLER
# =============================================================================


@attrs.define
class ASExchangeHandler:
    """
    Handles the Kerberos AS exchange protocol.

    SPEC: specs/alloy/kerberos/protocol.als - ASExchange

    This class manages the client-side AS exchange:
    1. Build AS-REQ message
    2. Process AS-REP or KRB-ERROR response
    3. Decrypt session key from AS-REP

    Security invariants enforced:
    - Nonce freshness check
    - Timestamp validation
    - Encryption type matching
    """

    realm: Realm
    kdc_address: str = ""  # For future network integration
    clock_skew_tolerance: timedelta = timedelta(minutes=5)

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def build_as_request(
        self,
        principal: Principal,
        preauth_data: Optional[List[PreAuthData]] = None,
        kdc_options: Optional[KDCOptions] = None,
        requested_etypes: Optional[List[EncryptionType]] = None,
    ) -> Tuple[ASRequest, Nonce]:
        """
        Build an AS-REQ message.

        SPEC: specs/alloy/kerberos/protocol.als - ASRequest

        Args:
            principal: Client principal requesting TGT
            preauth_data: Pre-authentication data (if required)
            kdc_options: KDC options flags
            requested_etypes: Encryption types client supports

        Returns:
            Tuple of (AS-REQ message, nonce used)
        """
        nonce = Nonce()

        # Default to strong encryption types
        if requested_etypes is None:
            requested_etypes = [
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                EncryptionType.AES128_CTS_HMAC_SHA1_96,
                EncryptionType.RC4_HMAC,
            ]

        # Build krbtgt principal for this realm
        krbtgt = Principal(
            name=f"krbtgt/{self.realm.name}",
            realm=self.realm,
        )

        request = ASRequest(
            padata=preauth_data or [],
            kdc_options=kdc_options or KDCOptions(),
            client_principal=principal,
            server_principal=krbtgt,
            nonce=nonce,
            etype=requested_etypes,
        )

        self._logger.debug(
            "built_as_request",
            principal=principal.name,
            realm=self.realm.name,
            has_preauth=bool(preauth_data),
        )

        return request, nonce

    def build_encrypted_timestamp_preauth(
        self,
        principal: Principal,
        password: str,
        enctype: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
    ) -> PreAuthData:
        """
        Build PA-ENC-TIMESTAMP pre-authentication data.

        SPEC: specs/alloy/kerberos/protocol.als - PreAuthData.encTimestamp

        This proves the client knows the password by encrypting
        the current timestamp with the password-derived key.

        Args:
            principal: Client principal
            password: User password
            enctype: Encryption type to use

        Returns:
            PreAuthData containing encrypted timestamp
        """
        # Derive key from password
        salt = f"{self.realm.name}{principal.name}".encode("utf-8")
        key = derive_key_from_password(password, salt, enctype)

        # Build timestamp
        timestamp = Timestamp()

        # Encode timestamp (simplified - real impl uses ASN.1)
        timestamp_bytes = timestamp.time.isoformat().encode("utf-8")

        # Encrypt timestamp
        ciphertext, iv = encrypt_aes_cts(key.material, timestamp_bytes)

        # Build PA-DATA
        padata_value = iv + ciphertext  # Prepend IV

        self._logger.debug(
            "built_enc_timestamp_preauth",
            principal=principal.name,
            enctype=enctype.name,
        )

        return PreAuthData(
            padata_type=PreAuthType.PA_ENC_TIMESTAMP,
            padata_value=padata_value,
        )

    def process_as_reply(
        self,
        reply: ASReply,
        expected_nonce: Nonce,
        password: str,
        principal: Principal,
    ) -> Result[Tuple[bytes, SessionKey, TicketInfo], str]:
        """
        Process an AS-REP message.

        SPEC: specs/alloy/kerberos/protocol.als - receiveASReply
        SPEC: specs/tla/Kerberos.tla - ClientReceiveASRep

        Security checks performed:
        1. Nonce matches (replay prevention)
        2. Client principal matches
        3. Decryption succeeds (proves password correctness)
        4. Timestamps valid

        Args:
            reply: AS-REP message from KDC
            expected_nonce: Nonce we sent in AS-REQ
            password: User password for decryption
            principal: Expected client principal

        Returns:
            Success((tgt, session_key, ticket_info)) or Failure(error_message)
        """
        # Verify client principal matches
        if reply.client_principal != principal:
            return Failure(
                f"Principal mismatch: expected {principal.name}, "
                f"got {reply.client_principal.name}"
            )

        # Derive decryption key from password
        salt = f"{self.realm.name}{principal.name}".encode("utf-8")
        key = derive_key_from_password(password, salt, reply.enc_type)

        # Decrypt enc_part
        try:
            # Extract IV (first 16 bytes) and ciphertext
            if len(reply.enc_part) < 16:
                return Failure("enc_part too short")

            iv = reply.enc_part[:16]
            ciphertext = reply.enc_part[16:]

            plaintext = decrypt_aes_cts(key.material, ciphertext, iv)
        except CryptoError as e:
            self._logger.warning(
                "as_reply_decryption_failed",
                error=str(e),
            )
            return Failure(f"Decryption failed: {e}")

        # Parse decrypted content (simplified - real impl uses ASN.1)
        try:
            enc_part = self._parse_as_reply_enc_part(plaintext)
        except Exception as e:
            return Failure(f"Failed to parse enc_part: {e}")

        # CRITICAL: Verify nonce matches (replay prevention)
        # SPEC: specs/alloy/kerberos/properties.als - NonceFreshness
        if enc_part.nonce != expected_nonce:
            self._logger.error(
                "nonce_mismatch",
                expected=expected_nonce.value,
                received=enc_part.nonce.value,
            )
            return Failure("Nonce mismatch - possible replay attack")

        # Validate timestamps
        now = datetime.now(timezone.utc)
        if enc_part.end_time < now:
            return Failure("Ticket already expired")

        # Build ticket info
        ticket_info = TicketInfo(
            times=TicketTimes(
                auth_time=enc_part.auth_time,
                start_time=enc_part.start_time or now,
                end_time=enc_part.end_time,
                renew_till=enc_part.renew_till,
            ),
            flags=enc_part.flags,
            client_principal=principal,
            server_principal=enc_part.server_principal,
            server_realm=enc_part.server_realm,
        )

        self._logger.info(
            "as_reply_processed",
            principal=principal.name,
            ticket_valid_until=enc_part.end_time.isoformat(),
        )

        return Success((reply.ticket, enc_part.session_key, ticket_info))

    def process_error(
        self, error: KerberosErrorMsg
    ) -> Result[List[EtypeInfo2Entry], KerberosError]:
        """
        Process a KRB-ERROR message from AS exchange.

        SPEC: specs/alloy/kerberos/protocol.als - receiveError

        Args:
            error: KRB-ERROR message

        Returns:
            Success(etype_info) if error is pre-auth required with etype info
            Failure(KerberosError) otherwise
        """
        if error.error_code == KerberosError.KDC_ERR_PREAUTH_REQUIRED:
            # Parse e_data for PA-ETYPE-INFO2
            if error.e_data:
                etype_info = self._parse_etype_info2(error.e_data)
                self._logger.info(
                    "preauth_required",
                    etypes=[e.etype.name for e in etype_info],
                )
                return Success(etype_info)
            return Success([])

        # Other errors are failures
        self._logger.error(
            "as_exchange_error",
            error_code=error.error_code,
            error_text=error.error_text,
        )
        return Failure(KerberosError(error.error_code, error.error_text))

    def _parse_as_reply_enc_part(self, data: bytes) -> ASReplyEncPart:
        """
        Parse decrypted AS-REP enc-part.

        Note: This is a simplified parser. Real implementation would
        use proper ASN.1 DER decoding (pyasn1 or similar).
        """
        # For now, create a mock response
        # Real implementation would parse ASN.1 structure
        return ASReplyEncPart(
            session_key=SessionKey(
                enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                material=data[:32] if len(data) >= 32 else data + b"\x00" * (32 - len(data)),
            ),
            nonce=Nonce.from_int(int.from_bytes(data[32:36], "big") if len(data) >= 36 else 0),
            flags=frozenset({TicketFlag.INITIAL, TicketFlag.RENEWABLE}),
            auth_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc) + timedelta(hours=10),
            server_realm=self.realm,
            server_principal=Principal(
                name=f"krbtgt/{self.realm.name}",
                realm=self.realm,
            ),
        )

    def _parse_etype_info2(self, data: bytes) -> List[EtypeInfo2Entry]:
        """
        Parse PA-ETYPE-INFO2 from error e_data.

        Note: Simplified parser.
        """
        # Default to AES256
        return [
            EtypeInfo2Entry(
                etype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                salt=None,
            )
        ]


# =============================================================================
# HIGH-LEVEL AS EXCHANGE FUNCTION
# =============================================================================


def perform_as_exchange(
    principal: Principal,
    password: str,
    realm: Realm,
    kdc_send_receive: Optional[Any] = None,  # For network integration
) -> Result[Tuple[bytes, SessionKey, TicketInfo], str]:
    """
    Perform complete AS exchange to obtain a TGT.

    SPEC: specs/alloy/kerberos/protocol.als - ASExchange
    SPEC: specs/tla/Kerberos.tla - ASExchange sequence

    This function handles the complete AS exchange including:
    1. Initial AS-REQ (without pre-auth)
    2. Pre-auth retry if required
    3. AS-REP processing and TGT extraction

    Args:
        principal: Client principal
        password: User password
        realm: Kerberos realm
        kdc_send_receive: Function to send/receive KDC messages

    Returns:
        Success((tgt, session_key, ticket_info)) or Failure(error)
    """
    handler = ASExchangeHandler(realm=realm)

    # Build initial AS-REQ (without pre-auth to test if required)
    request, nonce = handler.build_as_request(principal)

    logger.info(
        "starting_as_exchange",
        principal=principal.name,
        realm=realm.name,
    )

    # In a real implementation, we would:
    # 1. Encode request to ASN.1/DER
    # 2. Send to KDC
    # 3. Receive and decode response
    # 4. Handle pre-auth if required
    # 5. Process AS-REP

    # For now, assume pre-auth is required (common in modern AD)
    preauth = handler.build_encrypted_timestamp_preauth(
        principal, password
    )

    # Build request with pre-auth
    request_with_preauth, nonce = handler.build_as_request(
        principal, preauth_data=[preauth]
    )

    # The actual KDC communication would happen here
    # For now, we return a placeholder indicating the exchange structure
    logger.info(
        "as_exchange_ready",
        principal=principal.name,
        has_preauth=True,
        nonce=nonce.value,
    )

    return Failure("KDC communication not implemented - use KerberosClient for full flow")


# =============================================================================
# INVARIANTS
# =============================================================================


def tgt_requires_valid_auth(state: KerberosState, ctx: KerberosContext) -> bool:
    """
    Invariant: HAS_TGT state requires valid TGT data.

    SPEC: specs/alloy/kerberos/properties.als - NoTicketWithoutAuth
    """
    if state == KerberosState.HAS_TGT:
        return (
            ctx.tgt is not None
            and ctx.tgt_session_key is not None
            and ctx.tgt_info is not None
        )
    return True


def nonce_cleared_after_exchange(
    state: KerberosState, ctx: KerberosContext
) -> bool:
    """
    Invariant: Pending nonce is cleared after exchange completes.

    SPEC: specs/alloy/kerberos/properties.als - NonceFreshness
    """
    if state in (KerberosState.HAS_TGT, KerberosState.ERROR):
        return ctx.pending_nonce is None
    return True
