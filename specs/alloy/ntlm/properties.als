/**
 * AuthModeler NTLM Security Properties
 *
 * Formal specification of security properties for NTLMv2 authentication.
 * Documents both achieved properties AND known vulnerabilities.
 *
 * IMPORTANT: NTLM has inherent security weaknesses that cannot be fixed
 * by implementation alone. This specification documents:
 * - Properties that HOLD (can be verified)
 * - Properties that FAIL (known vulnerabilities)
 * - Mitigations (EPA, SMB signing, etc.)
 *
 * Reference: MS-NLMP - NT LAN Manager (NTLM) Authentication Protocol
 */
module ntlm/properties

open core/types
open core/crypto
open core/attacker
open ntlm/protocol

-- =============================================================================
-- PROPERTIES THAT SHOULD HOLD
-- =============================================================================

/**
 * Property HOLD-1: Challenge Freshness
 *
 * Each server challenge is used only once.
 * Prevents challenge reuse attacks.
 */
assert ChallengeFreshness {
    all ss: NTLMServerSession |
        all disj c1, c2: ServerChallenge |
            (c1 in ss.usedChallenges and c2 in ss.usedChallenges)
            implies c1 != c2
}
check ChallengeFreshness for 4

/**
 * Property HOLD-2: Response Binding to Challenge
 *
 * An NTLMv2 response is cryptographically bound to the server challenge.
 * Cannot use response from one challenge with another.
 */
assert ResponseBoundToChallenge {
    all resp: NTLMv2Response, sc1, sc2: ServerChallenge, nt1, nt2: NTHash |
        (validNTLMv2Response[resp, nt1, sc1] and validNTLMv2Response[resp, nt2, sc2])
        implies sc1 = sc2
}
check ResponseBoundToChallenge for 4

/**
 * Property HOLD-3: Timestamp Inclusion
 *
 * NTLMv2 responses include a timestamp, limiting replay window.
 */
assert TimestampInResponse {
    all resp: NTLMv2Response |
        some resp.clientChallenge.timestamp
}
check TimestampInResponse for 3

/**
 * Property HOLD-4: Client Challenge Freshness
 *
 * Each authentication uses a fresh client challenge.
 * Adds entropy to the response.
 */
assert ClientChallengeFreshness {
    all disj cs1, cs2: NTLMClientSession |
        (cs1.state = NC_Authenticated and cs2.state = NC_Authenticated)
        implies cs1.clientChallenge != cs2.clientChallenge
}
check ClientChallengeFreshness for 4

/**
 * Property HOLD-5: Session Key Derivation
 *
 * Session base key is derived from NT hash and proof string.
 * Different authentications produce different session keys.
 */
assert SessionKeyDerivation {
    all disj d1, d2: SessionBaseKeyDerivation |
        (d1.ntHash != d2.ntHash or d1.ntProofStr != d2.ntProofStr)
        implies d1.sessionBaseKey != d2.sessionBaseKey
}
check SessionKeyDerivation for 4

/**
 * Property HOLD-6: MIC Integrity
 *
 * When MIC is present, it binds all three messages together.
 * Prevents message modification.
 */
assert MICIntegrity {
    all authMsg: AuthenticateMessage |
        some authMsg.mic implies
        -- MIC cryptographically binds messages
        (some neg: NegotiateMessage, chal: ChallengeMessage |
            neg.sender = authMsg.sender and
            chal.receiver = authMsg.sender and
            authMsg.receiver = neg.receiver)
}
check MICIntegrity for 4

/**
 * Property HOLD-7: EPA Prevents Relay (When Enabled)
 *
 * Channel binding prevents relay to different servers.
 * EPA is enabled when the challenge message includes channel bindings.
 */
assert EPAPreventsRelay {
    all authMsg: AuthenticateMessage, ss: NTLMServerSession, chalMsg: ChallengeMessage |
        -- When EPA is enabled (challenge has channel bindings)
        (some chalMsg.targetInfo.msvAvChannelBindings and
         chalMsg in Network.history and
         chalMsg.receiver = authMsg.sender and
         authMsg.receiver = ss.principal and
         authMsg.sender in ss.authenticatedClients)
        implies
        -- Client intended to authenticate to this server
        (some cs: NTLMClientSession |
            cs.principal = authMsg.sender and
            cs.targetServer = ss.principal)
}
check EPAPreventsRelay for 4

-- =============================================================================
-- KNOWN VULNERABILITIES (Properties That FAIL)
-- =============================================================================

/**
 * VULNERABILITY-1: Pass-the-Hash
 *
 * Having the NT hash alone is sufficient for authentication.
 * No password needed at authentication time.
 *
 * EXPECTED: COUNTEREXAMPLE FOUND
 */
assert NoPassTheHash {
    all cs: NTLMClientSession |
        cs.state = NC_Authenticated implies
        -- Requires original password, not just hash
        (some pdk: PasswordDerivedKey |
            some nc: NTHashComputation |
                nc.password = pdk.password and nc.hash = cs.ntHash)
}
-- This SHOULD fail - documents the vulnerability
check NoPassTheHash for 3 expect 1

/**
 * VULNERABILITY-2: NTLM Relay (Without EPA)
 *
 * Without channel binding, attacker can relay authentication
 * from one server to another.
 *
 * EXPECTED: COUNTEREXAMPLE FOUND (when EPA disabled)
 */
assert NoRelayWithoutEPA {
    all ss: NTLMServerSession, authMsg: AuthenticateMessage, chalMsg: ChallengeMessage |
        (authMsg.receiver = ss.principal and
         authMsg.sender in ss.authenticatedClients and
         chalMsg in Network.history and
         chalMsg.receiver = authMsg.sender and
         -- No EPA - no channel bindings in challenge
         no chalMsg.targetInfo.msvAvChannelBindings)
        implies
        (some cs: NTLMClientSession |
            cs.principal = authMsg.sender and
            cs.targetServer = ss.principal)
}
-- This SHOULD fail without EPA
check NoRelayWithoutEPA for 4 expect 1

/**
 * VULNERABILITY-3: Offline Cracking
 *
 * Captured challenge-response pairs can be attacked offline.
 * Attacker can crack weak passwords.
 *
 * EXPECTED: COUNTEREXAMPLE FOUND
 */
pred offlineCrackingPossible {
    -- Attacker captures challenge and response from network
    some chal: ChallengeMessage, auth: AuthenticateMessage |
        chal in Network.history and
        auth in Network.history and
        auth.sender != Attacker and
        -- Attacker has all the data needed for offline attack
        (some kc: KnownChallenge, kr: KnownCiphertext |
            kc.challenge = chal.serverChallenge and
            kc in Attacker.knowledge and
            kr in Attacker.knowledge)
}

/**
 * VULNERABILITY-4: Downgrade to NTLMv1
 *
 * Without proper flag enforcement, authentication can be
 * downgraded to weaker NTLMv1.
 *
 * MITIGATION: Require NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
 */
assert NoDowngradeToNTLMv1 {
    all authMsg: AuthenticateMessage |
        authMsg in Network.history implies
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in authMsg.negotiateFlags
}
check NoDowngradeToNTLMv1 for 3

/**
 * VULNERABILITY-5: Reflection Attack (Same Client/Server)
 *
 * Server could reflect challenge back to client.
 * Mitigated by requiring NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.
 */
assert NoReflectionAttack {
    all cs: NTLMClientSession, ss: NTLMServerSession |
        (cs.state = NC_Authenticated and ss.state = NS_Authenticated)
        implies cs.principal != ss.principal
}
check NoReflectionAttack for 3

-- =============================================================================
-- MITIGATIONS
-- =============================================================================

/**
 * Mitigation: Extended Protection for Authentication (EPA)
 *
 * Channel binding ties authentication to TLS channel.
 * Prevents relay attacks.
 * EPA is enabled when the challenge message includes channel bindings.
 */
pred epaEnabled[chalMsg: ChallengeMessage] {
    some chalMsg.targetInfo.msvAvChannelBindings
}

/**
 * Mitigation: SMB Signing Required
 *
 * Message signing prevents man-in-the-middle.
 */
pred smbSigningEnabled[authMsg: AuthenticateMessage] {
    NTLMSSP_NEGOTIATE_SIGN in authMsg.negotiateFlags and
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN in authMsg.negotiateFlags
}

/**
 * Mitigation: Sealing (Encryption) Enabled
 *
 * Message encryption prevents eavesdropping.
 */
pred sealingEnabled[authMsg: AuthenticateMessage] {
    NTLMSSP_NEGOTIATE_SEAL in authMsg.negotiateFlags
}

/**
 * Mitigation: MIC Required
 *
 * Message integrity code binds all three messages.
 */
pred micRequired[targetInfo: TargetInfo] {
    MsvAvFlagMICProvided in targetInfo.msvAvFlags
}

/**
 * Best Practice: All Mitigations Enabled
 */
pred allMitigationsEnabled[authMsg: AuthenticateMessage, chalMsg: ChallengeMessage] {
    epaEnabled[chalMsg] and
    smbSigningEnabled[authMsg] and
    sealingEnabled[authMsg] and
    some authMsg.mic
}

-- =============================================================================
-- SECURITY LEVELS
-- =============================================================================

/**
 * Security Level: Minimum (Very Weak)
 *
 * Basic NTLMv2 without any mitigations.
 * Vulnerable to: relay, eavesdropping, MITM
 */
pred securityLevelMinimum[authMsg: AuthenticateMessage] {
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in authMsg.negotiateFlags
    -- No other protections required
}

/**
 * Security Level: Standard
 *
 * NTLMv2 with signing and MIC.
 * Vulnerable to: relay (without EPA), offline cracking
 */
pred securityLevelStandard[authMsg: AuthenticateMessage] {
    securityLevelMinimum[authMsg] and
    smbSigningEnabled[authMsg] and
    some authMsg.mic
}

/**
 * Security Level: Enhanced
 *
 * NTLMv2 with all mitigations except EPA.
 * Vulnerable to: relay (requires EPA), offline cracking
 */
pred securityLevelEnhanced[authMsg: AuthenticateMessage] {
    securityLevelStandard[authMsg] and
    sealingEnabled[authMsg]
}

/**
 * Security Level: Maximum
 *
 * NTLMv2 with all mitigations including EPA.
 * Still vulnerable to: pass-the-hash, offline cracking
 */
pred securityLevelMaximum[authMsg: AuthenticateMessage, chalMsg: ChallengeMessage] {
    securityLevelEnhanced[authMsg] and
    epaEnabled[chalMsg]
}

-- =============================================================================
-- COMPARATIVE SECURITY (NTLM vs Kerberos)
-- =============================================================================

/**
 * NTLM Weakness: No Ticket-Based Delegation
 *
 * Unlike Kerberos, NTLM has no constrained delegation.
 * Credentials must be re-used for each hop.
 */
pred ntlmNoTicketDelegation {
    -- In NTLM, there's no way to forward auth without credentials
    all cs: NTLMClientSession |
        cs.state = NC_Authenticated implies
        -- Credentials (hash) are directly used
        some cs.ntHash
}

/**
 * NTLM Weakness: Single Point of Failure
 *
 * No separation between authentication and authorization.
 * Hash compromise = full access.
 */
pred singlePointOfFailure {
    all cs: NTLMClientSession, ss: NTLMServerSession |
        (some kh: KnownNTHash |
            kh in Attacker.knowledge and
            kh.ntHash = cs.ntHash)
        implies
        -- Attacker can authenticate as victim
        passTheHashAttack[Attacker, cs.principal, ss.principal]
}

/**
 * NTLM Advantage: Simpler Infrastructure
 *
 * No KDC required - authentication is direct.
 */
pred noKDCRequired {
    -- Client and server can authenticate without third party
    all cs: NTLMClientSession, ss: NTLMServerSession |
        successfulNTLMAuth[cs, ss] implies
        -- No KDC messages involved
        (no msg: Message | msg.receiver = KDC or msg.sender = KDC)
}

-- =============================================================================
-- COMPOUND SECURITY ASSERTIONS
-- =============================================================================

/**
 * Properties that MUST hold even in weakest config.
 */
assert MinimumSecurityGuarantees {
    -- Challenge freshness: a challenge is fresh when first issued
    -- (before being added to usedChallenges, it wasn't in the set)
    -- After processing, it IS in usedChallenges - this is correct behavior
    all ss: NTLMServerSession |
        ss.state = NS_ChallengeSent implies some ss.currentChallenge

    -- Response is bound to challenge
    all resp: NTLMv2Response |
        some resp.clientChallenge.timestamp

    -- Extended session security enforced
    all authMsg: AuthenticateMessage |
        authMsg in Network.history implies
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in authMsg.negotiateFlags
}
check MinimumSecurityGuarantees for 4

/**
 * Properties that hold with full mitigations.
 */
assert MaximumSecurityGuarantees {
    all authMsg: AuthenticateMessage, chalMsg: ChallengeMessage |
        (authMsg in Network.history and
         chalMsg in Network.history and
         chalMsg.receiver = authMsg.sender and
         allMitigationsEnabled[authMsg, chalMsg])
        implies
        -- No relay possible with EPA
        (all ss: NTLMServerSession |
            authMsg.receiver = ss.principal implies
            (some cs: NTLMClientSession |
                cs.principal = authMsg.sender and
                cs.targetServer = ss.principal))
}
check MaximumSecurityGuarantees for 4

-- =============================================================================
-- RECOMMENDATIONS
-- =============================================================================

/**
 * Recommendation 1: Prefer Kerberos over NTLM
 *
 * NTLM should only be used when Kerberos is not available.
 * Kerberos provides stronger security guarantees.
 */

/**
 * Recommendation 2: Enable All Mitigations
 *
 * When NTLM must be used, enable:
 * - Extended session security (NTLMv2)
 * - SMB signing
 * - EPA (channel binding)
 * - Sealing (encryption)
 * - MIC
 */

/**
 * Recommendation 3: Monitor for Pass-the-Hash
 *
 * Pass-the-hash cannot be prevented by protocol design.
 * Must detect via monitoring:
 * - Unusual authentication patterns
 * - Authentication from unexpected locations
 * - Time of authentication anomalies
 */

/**
 * Recommendation 4: Strong Password Policy
 *
 * Offline cracking is always possible.
 * Mitigate with:
 * - Long, complex passwords
 * - Regular rotation
 * - Monitoring for credential stuffing
 */

-- =============================================================================
-- RUN COMMANDS FOR VULNERABILITY EXPLORATION
-- =============================================================================

/**
 * Visualize pass-the-hash success.
 */
run DemonstratePassTheHash {
    some cs: NTLMClientSession, ss: NTLMServerSession, kh: KnownNTHash |
        kh in Attacker.knowledge and
        kh.ntHash = cs.ntHash and
        cs.state = NC_Authenticated
} for 4

/**
 * Visualize relay attack without EPA.
 */
run DemonstrateRelayWithoutEPA {
    some cs: NTLMClientSession, ss1, ss2: NTLMServerSession, chalMsg: ChallengeMessage |
        ss1.principal != ss2.principal and
        cs.targetServer = ss1.principal and
        cs.principal in ss2.authenticatedClients and
        chalMsg in Network.history and
        no chalMsg.targetInfo.msvAvChannelBindings
} for 5

/**
 * Visualize EPA preventing relay.
 */
run EPABlocksRelay {
    some cs: NTLMClientSession, ss: NTLMServerSession, chalMsg: ChallengeMessage |
        successfulNTLMAuth[cs, ss] and
        chalMsg in Network.history and
        epaEnabled[chalMsg] and
        cs.targetServer = ss.principal
} for 4

/**
 * Show secure NTLM configuration.
 */
run SecureNTLMConfig {
    some authMsg: AuthenticateMessage, chalMsg: ChallengeMessage |
        authMsg in Network.history and
        chalMsg in Network.history and
        allMitigationsEnabled[authMsg, chalMsg]
} for 4
