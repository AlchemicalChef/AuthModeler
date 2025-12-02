/**
 * AuthModeler Kerberos Attack Scenarios
 *
 * Formal models of Kerberos attacks for security research and detection.
 * Each attack includes:
 * - Preconditions (what attacker needs)
 * - Attack predicate (how attack works)
 * - Detection indicators (observable patterns)
 * - Mitigations (defensive configurations)
 *
 * IMPORTANT: Properties that SHOULD FAIL document known vulnerabilities.
 * This is intentional - we use formal verification to confirm attacks work
 * as expected, enabling detection and mitigation development.
 */
module kerberos/attacks

open core/types
open core/crypto
open core/attacker
open kerberos/protocol

-- =============================================================================
-- KERBEROASTING ATTACK
-- =============================================================================

/**
 * Kerberoasting Attack Model
 *
 * ATTACK DESCRIPTION:
 * Any authenticated domain user can request service tickets (TGS-REQ) for
 * accounts with SPNs. The service ticket is encrypted with the service
 * account's password-derived key. Attacker extracts the ticket and performs
 * offline dictionary/brute-force attack to recover the password.
 *
 * PRECONDITIONS:
 * - Attacker has valid domain credentials (any user)
 * - Target service account has an SPN registered
 * - Target has weak/crackable password
 *
 * DETECTION:
 * - Event ID 4769: TGS-REQ for service accounts
 * - Multiple SPN requests from single user
 * - RC4_HMAC encryption type requests (easier to crack)
 *
 * REFERENCES:
 * - https://attack.mitre.org/techniques/T1558/003/
 */

/**
 * Kerberoasting attack preconditions.
 */
pred kerberoastingPreconditions[attacker: Attacker, targetService: ServiceAccount] {
    -- Attacker has valid domain credentials (can get TGT)
    some cs: ClientSession |
        cs.state = CS_HasTGT and
        -- Attacker controls this session's keys
        some kk: KnownKey |
            kk.key = cs.tgtSessionKey and
            kk in attacker.knowledge

    -- Target service has an SPN (implicit in ServiceAccount type)
    some targetService.spn

    -- Target is not KRBTGT (that would be different attack)
    targetService != KRBTGT
}

/**
 * Kerberoasting attack scenario.
 * Attacker obtains service ticket for target SPN and can attempt offline cracking.
 */
pred kerberoastingAttack[attacker: Attacker, targetService: ServiceAccount] {
    -- Preconditions met
    kerberoastingPreconditions[attacker, targetService]

    -- Attacker has obtained a service ticket for the target
    some kt: KnownTicket, st: ServiceTicket |
        kt in attacker.knowledge and
        kt.ticket = st and
        st.serverPrincipal = targetService and
        -- Ticket was legitimately issued by KDC
        st in KDCState.issuedTickets

    -- Attacker has the encrypted ticket data (for offline cracking)
    some kc: KnownCiphertext |
        some st: ServiceTicket |
            st.serverPrincipal = targetService and
            kc.ciphertext = st.encPart and
            kc in attacker.knowledge
}

/**
 * Kerberoasting attack succeeds (password cracked).
 * Models successful offline cracking of weak service account password.
 */
pred kerberoastingSuccess[attacker: Attacker, targetService: ServiceAccount] {
    kerberoastingAttack[attacker, targetService]

    -- Service has weak password (crackable)
    targetService.passwordStrength = WeakPassword

    -- Attacker recovers service key through offline cracking
    some kk: KnownKey, ltk: LongTermKey |
        ltk.owner = targetService and
        kk.key = ltk and
        kk in attacker.knowledge and
        -- Key was NOT in initial knowledge (was cracked)
        kk not in attacker.initialKnowledge
}

/**
 * Detection indicator: TGS-REQ for service account.
 */
pred kerberoastingIndicator[tgsReq: TGSRequest] {
    -- Request is for a service account (has SPN)
    tgsReq.serverPrincipal in ServiceAccount
}

/**
 * Detection indicator: Multiple service ticket requests.
 */
pred kerberoastingBulkIndicator[requests: set TGSRequest, threshold: Int] {
    -- Same requester, multiple service account targets
    some requester: Principal |
        #{ req: requests |
            req.sender = requester and
            req.serverPrincipal in ServiceAccount
        } > threshold
}

/**
 * Detection indicator: RC4 encryption requested (weaker, easier to crack).
 */
pred kerberoastingRC4Indicator[tgsReq: TGSRequest] {
    tgsReq.serverPrincipal in ServiceAccount and
    RC4_HMAC in tgsReq.requestedEtypes
}

-- =============================================================================
-- KERBEROASTING MITIGATIONS
-- =============================================================================

/**
 * Mitigation: Service account has strong password.
 */
pred kerberoastingMitigationStrongPassword[sa: ServiceAccount] {
    sa.passwordStrength = StrongPassword
}

/**
 * Mitigation: Use Group Managed Service Account (gMSA).
 * gMSAs have automatically rotated 240+ character passwords.
 */
pred kerberoastingMitigationGMSA[sa: ServiceAccount] {
    sa in GroupManagedServiceAccount
}

/**
 * Mitigation: Enforce AES encryption (harder to crack than RC4).
 */
pred kerberoastingMitigationAESOnly[sa: ServiceAccount, ltk: LongTermKey] {
    ltk.owner = sa implies
    ltk.enctype = AES256_CTS_HMAC_SHA1
}

/**
 * Combined mitigation check.
 */
pred kerberoastingFullyMitigated[sa: ServiceAccount] {
    kerberoastingMitigationStrongPassword[sa] or
    kerberoastingMitigationGMSA[sa]
}

-- =============================================================================
-- AS-REP ROASTING ATTACK
-- =============================================================================

/**
 * AS-REP Roasting Attack Model
 *
 * ATTACK DESCRIPTION:
 * Target accounts that have "Do not require Kerberos preauthentication" set.
 * Attacker can request AS-REP without proving knowledge of password.
 * The AS-REP encrypted part contains material encrypted with user's key,
 * which can be cracked offline.
 *
 * PRECONDITIONS:
 * - Target account has preAuthRequired = False
 * - Attacker knows target's username (public info)
 *
 * DETECTION:
 * - Event ID 4768: AS-REQ with pre-auth type 0
 * - AS-REQ without PA-DATA
 * - Bulk AS-REQ for multiple accounts
 *
 * REFERENCES:
 * - https://attack.mitre.org/techniques/T1558/004/
 */

/**
 * AS-REQ without pre-authentication data.
 * This is only valid for accounts with preAuthRequired = False.
 */
sig ASRequestNoPreAuth extends ASRequest {} {
    -- No pre-authentication data included
    no padata
}

/**
 * AS-REP Roasting attack preconditions.
 */
pred asrepRoastingPreconditions[attacker: Attacker, victim: UserPrincipal] {
    -- Victim has "Do not require Kerberos preauthentication" set
    victim.preAuthRequired = False

    -- Attacker knows victim's username (public information)
    some kp: KnownPrincipal |
        kp.principal = victim and
        kp in attacker.knowledge
}

/**
 * AS-REP Roasting attack scenario.
 * Attacker requests AS-REP without pre-auth and obtains crackable material.
 */
pred asrepRoastingAttack[attacker: Attacker, victim: UserPrincipal] {
    -- Preconditions met
    asrepRoastingPreconditions[attacker, victim]

    -- AS-REQ sent without pre-authentication
    some asReq: ASRequestNoPreAuth |
        asReq.clientPrincipal = victim and
        asReq in Network.history

    -- AS-REP was returned (KDC didn't require pre-auth)
    some asRep: ASReply |
        asRep.clientPrincipal = victim and
        asRep in Network.history

    -- Attacker has the encrypted AS-REP data (for offline cracking)
    some kc: KnownCiphertext, asRep: ASReply |
        asRep.clientPrincipal = victim and
        kc.ciphertext = asRep.encPart and
        kc in attacker.knowledge
}

/**
 * Detection indicator: AS-REQ without pre-auth data.
 */
pred asrepRoastingIndicator[asReq: ASRequest] {
    no asReq.padata
}

/**
 * Detection indicator: Bulk AS-REQ without pre-auth.
 */
pred asrepRoastingBulkIndicator[requests: set ASRequest, threshold: Int] {
    #{ req: requests | no req.padata } > threshold
}

-- =============================================================================
-- AS-REP ROASTING MITIGATIONS
-- =============================================================================

/**
 * Mitigation: Require pre-authentication for all accounts.
 */
pred asrepRoastingMitigation[u: UserPrincipal] {
    u.preAuthRequired = True
}

/**
 * Organization-wide mitigation: All users require pre-auth.
 */
pred asrepRoastingOrgMitigation {
    all u: UserPrincipal | u.preAuthRequired = True
}

-- =============================================================================
-- SECURITY ASSERTIONS (Document Vulnerabilities)
-- =============================================================================

/**
 * VULNERABILITY ASSERTION: Kerberoasting is possible.
 *
 * This assertion SHOULD FAIL (find counterexample) to document that:
 * - Any authenticated user can request service tickets
 * - Service tickets can be cracked offline if password is weak
 *
 * A counterexample demonstrates the attack is possible.
 */
assert NoOfflineServiceTicketCracking {
    all st: ServiceTicket, attacker: Attacker |
        -- If attacker has obtained a service ticket
        (some kt: KnownTicket |
            kt.ticket = st and
            kt in attacker.knowledge)
        implies
        -- Attacker should NOT be able to derive the service key
        (no kk: KnownKey |
            kk.key = st.encPart.encryptionKey and
            kk in attacker.knowledge and
            kk not in attacker.initialKnowledge)
}
-- Expect counterexample: Kerberoasting vulnerability
check NoOfflineServiceTicketCracking for 4 expect 1

/**
 * VULNERABILITY ASSERTION: AS-REP Roasting is possible.
 *
 * This assertion SHOULD FAIL to document that accounts without
 * pre-authentication can be targeted for offline attacks.
 */
assert PreAuthAlwaysRequired {
    all asReq: ASRequest |
        asReq in Network.history implies
        some asReq.padata
}
-- Expect counterexample: AS-REP Roasting vulnerability
check PreAuthAlwaysRequired for 4 expect 1

/**
 * VULNERABILITY ASSERTION: AS-REP issued without pre-auth.
 *
 * Documents that KDC will issue AS-REP to accounts with pre-auth disabled.
 */
assert NoASREPWithoutPreAuth {
    all u: UserPrincipal |
        u.preAuthRequired = False implies
        -- Should not receive AS-REP
        (no asRep: ASReply |
            asRep.clientPrincipal = u and
            asRep in Network.history)
}
-- Expect counterexample when preAuthRequired = False
check NoASREPWithoutPreAuth for 4 expect 1

-- =============================================================================
-- SECURITY ASSERTIONS (Properties that SHOULD HOLD)
-- =============================================================================

/**
 * Mitigation verification: gMSA resists Kerberoasting.
 *
 * This assertion SHOULD PASS to verify that gMSA accounts
 * are not vulnerable to offline password cracking.
 */
assert GMSAResistsKerberoasting {
    all sa: GroupManagedServiceAccount, attacker: Attacker |
        -- gMSA always has strong password
        sa.passwordStrength = StrongPassword
}
check GMSAResistsKerberoasting for 4

/**
 * Mitigation verification: Pre-auth prevents AS-REP Roasting.
 *
 * When pre-auth is required, AS-REP Roasting is not possible.
 */
assert PreAuthPreventsASREPRoasting {
    all u: UserPrincipal, asReq: ASRequestNoPreAuth |
        u.preAuthRequired = True implies
        -- No AS-REP should be issued for no-preauth request
        (asReq.clientPrincipal = u implies
            no asRep: ASReply |
                asRep.clientPrincipal = u and
                asRep in Network.history)
}
check PreAuthPreventsASREPRoasting for 4

-- =============================================================================
-- RUN COMMANDS FOR ATTACK VISUALIZATION
-- =============================================================================

/**
 * Visualize Kerberoasting attack scenario.
 */
run ShowKerberoastingAttack {
    some attacker: Attacker, sa: ServiceAccount |
        kerberoastingAttack[attacker, sa] and
        sa.passwordStrength = WeakPassword
} for 4

/**
 * Visualize successful Kerberoasting (password cracked).
 */
run ShowKerberoastingSuccess {
    some attacker: Attacker, sa: ServiceAccount |
        kerberoastingSuccess[attacker, sa]
} for 4

/**
 * Visualize AS-REP Roasting attack scenario.
 */
run ShowASREPRoasting {
    some attacker: Attacker, victim: UserPrincipal |
        asrepRoastingAttack[attacker, victim]
} for 4

/**
 * Visualize mitigated service account (gMSA).
 */
run ShowMitigatedServiceAccount {
    some sa: GroupManagedServiceAccount |
        kerberoastingFullyMitigated[sa]
} for 3

/**
 * Visualize detection scenario.
 */
run ShowDetectionIndicators {
    some tgsReq: TGSRequest |
        kerberoastingIndicator[tgsReq] and
        kerberoastingRC4Indicator[tgsReq]
} for 3
