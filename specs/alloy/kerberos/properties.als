/**
 * AuthModeler Kerberos Security Properties
 *
 * Formal specification of security properties that must hold for
 * Kerberos V5 authentication to be secure.
 *
 * Properties are categorized as:
 * - SAFETY: Must always hold (invariants)
 * - LIVENESS: Must eventually hold (progress guarantees)
 * - AUTHENTICATION: Verify claimed identities
 * - CONFIDENTIALITY: Protect sensitive data
 * - INTEGRITY: Prevent tampering
 * - FRESHNESS: Prevent replay attacks
 *
 * Reference: RFC 4120 Section 1.1 (Security Goals)
 */
module kerberos/properties

open core/types
open core/crypto
open core/attacker
open kerberos/protocol

-- =============================================================================
-- AUTHENTICATION PROPERTIES
-- =============================================================================

/**
 * Property AUTH-1: No ticket without proper authentication.
 *
 * A client cannot obtain a valid ticket (TGT or service ticket)
 * without proving knowledge of their long-term key (password).
 *
 * SECURITY GOAL: Prevent unauthorized ticket issuance.
 */
assert NoTicketWithoutAuthentication {
    all t: Ticket |
        t in KDCState.issuedTickets implies
        -- The ticket's plaintext must be a TicketEncPart
        (t.encPart.plaintext in TicketEncPart and
         some pa: PreAuthData, ltk: LongTermKey |
            pa.encTimestamp.encryptionKey = ltk and
            ltk.owner = (t.encPart.plaintext & TicketEncPart).clientPrincipal)
}
check NoTicketWithoutAuthentication for 5

/**
 * Property AUTH-2: Service authentication guarantee.
 *
 * If a service accepts an AP-REQ, the client is genuinely authenticated.
 * The client must possess a valid ticket issued by the KDC.
 *
 * SECURITY GOAL: Service knows client identity is verified by KDC.
 */
assert ServiceAuthenticationGuarantee {
    all ss: ServiceSession, apReq: APRequest |
        (apReq in Network.history and
         apReq.receiver = ss.principal and
         apReq.authenticator.plaintext in ss.authenticatorCache)
        implies
        (apReq.ticket in KDCState.issuedTickets and
         ticketValidAt[apReq.ticket, apReq.timestamp.time])
}
check ServiceAuthenticationGuarantee for 5

/**
 * Property AUTH-3: Mutual authentication.
 *
 * When mutual authentication is requested, the client can verify
 * the service possesses the correct session key.
 *
 * SECURITY GOAL: Client knows it's talking to the intended service.
 */
assert MutualAuthenticationGuarantee {
    all apReq: APRequest, apRep: APReply |
        (apReq.mutualRequired = True and
         apRep in Network.history and
         apRep.sender = apReq.receiver)
        implies
        (canDecrypt[apRep.encPart, apReq.ticket.encPart.plaintext.sessionKey] and
         apRep.encPart.plaintext.ctime = apReq.authenticator.plaintext.ctime)
}
check MutualAuthenticationGuarantee for 4

/**
 * Property AUTH-4: Identity binding.
 *
 * The principal in the ticket matches the principal that requested it
 * via AS-REQ with valid pre-authentication.
 *
 * SECURITY GOAL: No identity confusion or impersonation through KDC.
 */
assert IdentityBinding {
    all t: TGT, asReq: ASRequest, asRep: ASReply |
        -- If AS-REP contains this TGT
        (asRep in Network.history and asRep.ticket = t) implies
        -- The client in the ticket matches the client that authenticated
        (some tep: TicketEncPart |
            t.encPart.plaintext = tep and
            tep.clientPrincipal = asReq.clientPrincipal)
}
check IdentityBinding for 4

-- =============================================================================
-- CONFIDENTIALITY PROPERTIES
-- =============================================================================

/**
 * Property CONF-1: Password never transmitted.
 *
 * Plaintext passwords NEVER appear in network messages.
 * Only password-derived keys (not plaintext passwords) are used.
 *
 * SECURITY GOAL: Protect credential confidentiality.
 */
assert PasswordNeverTransmitted {
    all pdk: PasswordDerivedKey |
        -- Password-derived key material is NOT the same as any key material
        -- transmitted in messages (only derived keys are used, never passwords)
        (no asReq: ASRequest |
            asReq.padata.encTimestamp.plaintext = pdk.password) and
        (no asRep: ASReply |
            asRep.encPart.plaintext = pdk.password) and
        -- Password itself is never in any plaintext field
        (no ed: EncryptedData | ed.plaintext = pdk.password)
}
check PasswordNeverTransmitted for 5

/**
 * Property CONF-2: Session key confidentiality.
 *
 * Session keys are only known to the legitimate parties:
 * - TGT session key: client and KDC
 * - Service session key: client and service
 *
 * SECURITY GOAL: Attacker cannot learn session keys.
 */
assert SessionKeyConfidentiality {
    all sk: SessionKey |
        (sk in TGT.encPart.plaintext.sessionKey or
         sk in ServiceTicket.encPart.plaintext.sessionKey)
        implies
        sessionKeySecrecy[sk]
}
check SessionKeyConfidentiality for 4

/**
 * Property CONF-3: Ticket confidentiality.
 *
 * The encrypted portion of a ticket cannot be read by the attacker.
 * Only the service holding the decryption key can read it.
 *
 * SECURITY GOAL: Protect authorization data in tickets.
 */
assert TicketConfidentiality {
    all t: Ticket |
        t in KDCState.issuedTickets implies
        ticketConfidentiality[t]
}
check TicketConfidentiality for 4

/**
 * Property CONF-4: Authenticator confidentiality.
 *
 * Authenticators encrypted with session keys are not readable by attacker.
 *
 * SECURITY GOAL: Prevent authenticator extraction for relay/replay.
 */
assert AuthenticatorConfidentiality {
    all apReq: APRequest |
        apReq in Network.history implies
        not canDecryptWithKnowledge[apReq.authenticator]
}
check AuthenticatorConfidentiality for 4

-- =============================================================================
-- INTEGRITY PROPERTIES
-- =============================================================================

/**
 * Property INT-1: Ticket integrity.
 *
 * Tickets cannot be forged or modified without detection.
 * Only the KDC (for TGT) or service (for service ticket) can create valid tickets.
 *
 * SECURITY GOAL: Prevent ticket forgery.
 */
assert TicketIntegrity {
    all t: Ticket |
        -- Ensure plaintext is TicketEncPart for proper type access
        (t.encPart.plaintext in TicketEncPart and
         ticketValidAt[t, (t.encPart.plaintext & TicketEncPart).authTime])
        implies
        (t in KDCState.issuedTickets)
}
check TicketIntegrity for 5

/**
 * Property INT-2: Authenticator integrity.
 *
 * Authenticators cannot be modified without detection.
 * Any tampering breaks the checksum/encryption.
 *
 * SECURITY GOAL: Detect message tampering.
 */
assert AuthenticatorIntegrity {
    all apReq: APRequest |
        apReq in Network.history implies
        (let auth = apReq.authenticator.plaintext |
            auth.clientPrincipal = apReq.ticket.encPart.plaintext.clientPrincipal)
}
check AuthenticatorIntegrity for 4

/**
 * Property INT-3: Reply integrity.
 *
 * Kerberos replies (AS-REP, TGS-REP, AP-REP) cannot be forged.
 * They are encrypted with keys known only to legitimate parties.
 *
 * SECURITY GOAL: Prevent fake KDC/service responses.
 */
assert ReplyIntegrity {
    all asRep: ASReply |
        asRep in Network.history implies
        asRep.sender = KDC

    all tgsRep: TGSReply |
        tgsRep in Network.history implies
        tgsRep.sender = KDC
}
check ReplyIntegrity for 4

-- =============================================================================
-- FRESHNESS PROPERTIES (Replay Prevention)
-- =============================================================================

/**
 * Property FRESH-1: Nonce freshness.
 *
 * Each authentication request uses a fresh nonce.
 * Nonces are never reused within a reasonable time window.
 *
 * SECURITY GOAL: Bind request to reply.
 */
assert NonceFreshness {
    all disj req1, req2: ASRequest + TGSRequest |
        req1.reqNonce != req2.reqNonce
}
check NonceFreshness for 4

/**
 * Property FRESH-2: Authenticator freshness.
 *
 * Each authenticator has a unique timestamp.
 * Replay of authenticators is detected.
 *
 * SECURITY GOAL: Prevent replay attacks.
 */
assert AuthenticatorFreshness {
    all disj auth1, auth2: Authenticator |
        (auth1.clientPrincipal = auth2.clientPrincipal)
        implies
        (auth1.ctime != auth2.ctime or auth1.cusec != auth2.cusec)
}
check AuthenticatorFreshness for 4

/**
 * Property FRESH-3: No authenticator replay.
 *
 * Services maintain an authenticator cache.
 * Replayed authenticators are rejected.
 *
 * SECURITY GOAL: Detect and reject replay attacks.
 */
assert NoAuthenticatorReplay {
    all ss: ServiceSession, auth: Authenticator |
        (auth in ss.authenticatorCache)
        implies
        -- Can only be in cache once
        (one apReq: APRequest |
            apReq.authenticator.plaintext = auth and
            apReq in Network.history)
}
check NoAuthenticatorReplay for 4

/**
 * Property FRESH-4: Timestamp verification.
 *
 * Timestamps must be within acceptable clock skew.
 * Prevents use of old/future timestamps.
 *
 * SECURITY GOAL: Bound authentication time window.
 */
pred timestampWithinSkew[ts: Timestamp, ref: Time] {
    -- Within 5 minutes (modeled as adjacent Time atoms)
    ts.time = ref or
    ts.time = prev[ref] or
    ts.time = next[ref]
}

assert TimestampVerification {
    all apReq: APRequest, ss: ServiceSession |
        (apReq in Network.inTransit and
         apReq.receiver = ss.principal)
        implies
        timestampWithinSkew[apReq.authenticator.plaintext.ctime, apReq.timestamp.time]
}
check TimestampVerification for 4

-- =============================================================================
-- ATTACK PREVENTION PROPERTIES
-- =============================================================================

/**
 * Property ATK-1: Replay attack prevention.
 *
 * An attacker cannot successfully authenticate by replaying
 * a captured authentication message.
 *
 * SECURITY GOAL: Detect and reject replays.
 */
assert ReplayAttackPrevention {
    all apReq: APRequest, ss: ServiceSession |
        -- If authenticator already used
        (apReq.authenticator.plaintext in ss.authenticatorCache)
        implies
        -- Replay attempt is rejected
        (ss.state != SS_Authenticated)
}
check ReplayAttackPrevention for 4

/**
 * Property ATK-2: Pass-the-Hash prevention.
 *
 * Having only the NT hash (without password) is insufficient
 * for Kerberos authentication (unlike NTLM).
 *
 * SECURITY GOAL: Require full credential for authentication.
 */
assert PassTheHashPrevention {
    all p: Principal |
        passTheHash[p] implies
        -- Cannot complete Kerberos AS exchange
        (no asRep: ASReply | asRep.clientPrincipal = p and asRep in Network.history)
}
// Note: This should PASS for Kerberos (unlike NTLM)
check PassTheHashPrevention for 4

/**
 * Property ATK-3: Man-in-the-Middle prevention.
 *
 * An attacker cannot modify messages in transit without detection.
 * All sensitive messages are encrypted/authenticated.
 *
 * SECURITY GOAL: Detect message tampering.
 */
assert MITMPrevention {
    all m: Message |
        m in Network.history implies
        -- Message was sent by claimed sender
        (m.sender = KDC implies m in ASReply + TGSReply + KerberosError)
}
check MITMPrevention for 4

/**
 * Property ATK-4: Golden Ticket limitation.
 *
 * IF the KRBTGT key is compromised, attacker can forge any ticket.
 * This documents the known limitation, not a property to verify.
 *
 * SECURITY GOAL: Document catastrophic failure mode.
 */
assert GoldenTicketAttackPossible {
    -- If KRBTGT key is known, attacker can forge tickets
    goldenTicketCapability implies
    (all t: TGT | canDecryptWithKnowledge[t.encPart])
}
check GoldenTicketAttackPossible for 3

/**
 * Property ATK-5: Offline password attack limitation.
 *
 * Pre-authentication (PA-ENC-TIMESTAMP) prevents offline
 * password guessing attacks against AS-REP.
 *
 * SECURITY GOAL: Rate-limit password guessing.
 */
assert PreAuthRequiredForASREQ {
    all asReq: ASRequest |
        asReq in Network.history implies
        some asReq.padata
}
check PreAuthRequiredForASREQ for 4

-- =============================================================================
-- DELEGATION PROPERTIES (Future Enhancement)
-- =============================================================================

/**
 * Property DEL-1: Delegation constraint.
 *
 * Delegated credentials can only be used within authorized scope.
 * (Not implemented in MVP - placeholder for future)
 */
// pred constrainedDelegation[t: Ticket, allowedServices: set Principal] {
//     FORWARDABLE in t.encPart.plaintext.flags implies
//     t.serverPrincipal in allowedServices
// }

-- =============================================================================
-- COMPOUND SECURITY ASSERTIONS
-- =============================================================================

/**
 * Comprehensive security assertion.
 *
 * All critical properties must hold simultaneously.
 */
assert ComprehensiveSecurity {
    -- Authentication
    all t: Ticket | t in KDCState.issuedTickets implies
        (some PreAuthData)

    -- Confidentiality
    all sk: SessionKey | sessionKeySecrecy[sk]

    -- Freshness
    all disj a1, a2: Authenticator |
        a1.ctime != a2.ctime or a1.cusec != a2.cusec

    -- No password leakage (passwords never appear in message timestamps or receiver/sender fields)
    no pdk: PasswordDerivedKey, m: Message |
        pdk.password = m.timestamp
}
check ComprehensiveSecurity for 4

-- =============================================================================
-- RUN COMMANDS FOR COUNTEREXAMPLE EXPLORATION
-- =============================================================================

/**
 * Find scenario where authentication succeeds.
 */
run SuccessfulAuth {
    some cs: ClientSession |
        cs.state = CS_Authenticated
} for 5 but 3 Time

/**
 * Find scenario where replay is attempted.
 */
run ReplayAttempt {
    some auth: Authenticator, ss: ServiceSession |
        auth in ss.authenticatorCache and
        (some apReq: APRequest |
            apReq.authenticator.plaintext = auth and
            apReq in Network.inTransit)
} for 4

/**
 * Find scenario where attacker compromises session key.
 */
run SessionKeyCompromise {
    some sk: SessionKey, kk: KnownKey |
        kk.key = sk and
        kk in Attacker.knowledge and
        kk not in Attacker.initialKnowledge
} for 4

/**
 * Find scenario where ticket is forged.
 */
run TicketForgery {
    some t: Ticket |
        t not in KDCState.issuedTickets and
        (some apReq: APRequest | apReq.ticket = t)
} for 4
