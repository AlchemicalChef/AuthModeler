/**
 * AuthModeler Core Types
 *
 * Fundamental type definitions for authentication protocol modeling.
 * These abstract types form the basis for both Kerberos and NTLM specifications.
 *
 * Reference: RFC 4120 (Kerberos), MS-NLMP (NTLM)
 */
module core/types

open util/ordering[Time]

-- =============================================================================
-- TIME MODEL
-- =============================================================================

/**
 * Discrete time model for protocol execution.
 * Used for ticket validity, timestamp verification, and replay detection.
 */
sig Time {}

/**
 * Timestamp attached to messages for freshness verification.
 * Clock skew tolerance modeled by validity window.
 */
sig Timestamp {
    time: one Time,
    -- Validity window: timestamp is valid if current time within [time - skew, time + skew]
}

-- =============================================================================
-- IDENTITY MODEL
-- =============================================================================

/**
 * Realm represents a Kerberos administrative domain or Windows domain.
 * In AD context, this maps to the domain name (e.g., CORP.CONTOSO.COM).
 */
sig Realm {}

/**
 * Name represents the name component of a principal.
 * Can be a username, service name, or host name.
 */
sig Name {}

/**
 * Principal is a uniquely identifiable entity in the authentication system.
 * Format: name@realm (e.g., user@CORP.CONTOSO.COM or krbtgt/REALM@REALM)
 */
sig Principal {
    name: one Name,
    realm: one Realm
}

/**
 * Special principals in Kerberos infrastructure.
 */
one sig KDC extends Principal {}      -- Key Distribution Center
one sig KRBTGT extends Principal {}   -- Ticket Granting Ticket service

/**
 * Fact: KDC and KRBTGT have distinct identities.
 */
fact SpecialPrincipalIdentities {
    KDC != KRBTGT
    KDC.name != KRBTGT.name
}

-- =============================================================================
-- ACCOUNT TYPES (For Attack Modeling)
-- =============================================================================

/**
 * Service Principal Name (SPN) - identifies a service instance.
 * Format: serviceclass/host:port/servicename (e.g., HTTP/webserver.corp.com)
 * SPNs are targets for Kerberoasting attacks.
 */
sig ServicePrincipalName {
    serviceClass: one Name,   -- e.g., HTTP, MSSQLSvc, LDAP
    host: one Name            -- e.g., server.domain.com
}

/**
 * Password strength classification for attack modeling.
 * Weak passwords can be cracked offline; strong ones resist cracking.
 */
abstract sig PasswordStrength {}
one sig WeakPassword extends PasswordStrength {}    -- Crackable offline
one sig StrongPassword extends PasswordStrength {}  -- Resists offline cracking

/**
 * Service Account - account with SPN registered.
 * These are targets for Kerberoasting attacks because:
 * - Any domain user can request a service ticket
 * - The ticket is encrypted with the service's password-derived key
 * - Weak passwords can be cracked offline
 */
sig ServiceAccount extends Principal {
    spn: one ServicePrincipalName,
    passwordStrength: one PasswordStrength
}

/**
 * Group Managed Service Account (gMSA) - automatic password rotation.
 * These resist Kerberoasting due to 240+ character random passwords.
 */
sig GroupManagedServiceAccount extends ServiceAccount {} {
    -- gMSA always has strong passwords (auto-generated, 240+ chars)
    passwordStrength = StrongPassword
}

/**
 * User Principal - standard user account.
 * preAuthRequired flag determines vulnerability to AS-REP Roasting.
 */
sig UserPrincipal extends Principal {
    -- If False, account is vulnerable to AS-REP Roasting
    preAuthRequired: one Bool
}

/**
 * Boolean type for configuration flags.
 */
abstract sig Bool {}
one sig True, False extends Bool {}

/**
 * Fact: Service accounts have unique SPNs.
 */
fact UniqueSPNs {
    no disj sa1, sa2: ServiceAccount | sa1.spn = sa2.spn
}

-- =============================================================================
-- CRYPTOGRAPHIC MODEL
-- =============================================================================

/**
 * Encryption types supported by the protocol.
 * MVP focuses on AES256; others included for completeness.
 */
abstract sig EncryptionType {}
one sig AES256_CTS_HMAC_SHA1 extends EncryptionType {}
one sig AES128_CTS_HMAC_SHA1 extends EncryptionType {}
one sig RC4_HMAC extends EncryptionType {}  -- Legacy, still used in NTLM

/**
 * Abstract key material - actual bytes abstracted away.
 * Key secrecy is modeled through attacker knowledge sets.
 */
sig KeyMaterial {}

/**
 * Cryptographic key used for encryption/decryption and integrity.
 */
sig Key {
    enctype: one EncryptionType,
    material: one KeyMaterial
}

/**
 * Long-term keys derived from passwords.
 * These should NEVER appear in network messages.
 */
sig LongTermKey extends Key {
    -- The principal this key belongs to
    owner: one Principal
}

/**
 * Session keys for protecting communication.
 * Generated by KDC, shared between client and service.
 */
sig SessionKey extends Key {
    -- Valid time range for this session key
    validFrom: one Time,
    validUntil: one Time
}

/**
 * Nonce for freshness and replay prevention.
 */
sig Nonce {}

-- =============================================================================
-- TICKET MODEL (Kerberos)
-- =============================================================================

/**
 * Ticket flags per RFC 4120 section 5.3.
 */
abstract sig TicketFlag {}
one sig FORWARDABLE extends TicketFlag {}
one sig FORWARDED extends TicketFlag {}
one sig PROXIABLE extends TicketFlag {}
one sig PROXY extends TicketFlag {}
one sig RENEWABLE extends TicketFlag {}
one sig INITIAL extends TicketFlag {}
one sig PRE_AUTHENT extends TicketFlag {}

/**
 * Kerberos ticket structure (abstract representation).
 *
 * A ticket grants the client permission to access a service.
 * It is encrypted with the service's key and opaque to the client.
 */
sig Ticket {
    -- The realm that issued this ticket
    ticketRealm: one Realm,
    -- The service this ticket grants access to
    serverPrincipal: one Principal,
    -- Encrypted portion (client sees this as opaque blob)
    encPart: one EncryptedData
}

/**
 * The encrypted portion of a ticket (decryptable only by service).
 * Contains authorization data invisible to the client.
 */
sig TicketEncPart {
    -- Client principal this ticket is for
    clientPrincipal: one Principal,
    -- Session key for client-service communication
    sessionKey: one SessionKey,
    -- Ticket validity times
    authTime: one Time,
    startTime: lone Time,
    endTime: one Time,
    renewTill: lone Time,
    -- Ticket flags
    flags: set TicketFlag
}

/**
 * TGT - Ticket Granting Ticket.
 * Special ticket for the krbtgt service, used to obtain other tickets.
 */
sig TGT extends Ticket {} {
    -- TGT is always for the KRBTGT service
    serverPrincipal = KRBTGT
}

/**
 * Service Ticket - grants access to a specific service.
 */
sig ServiceTicket extends Ticket {} {
    -- Service ticket is NOT for KRBTGT
    serverPrincipal != KRBTGT
}

-- =============================================================================
-- ENCRYPTED DATA MODEL
-- =============================================================================

/**
 * Encrypted data blob.
 * Models ciphertext without exposing plaintext to unauthorized parties.
 */
sig EncryptedData {
    -- The key used for encryption
    encryptionKey: one Key,
    -- The plaintext content (abstract)
    plaintext: one Plaintext
}

/**
 * Abstract plaintext content.
 * Specialized by specific message types.
 */
abstract sig Plaintext {}

-- =============================================================================
-- AUTHENTICATOR MODEL
-- =============================================================================

/**
 * Authenticator proves possession of a session key.
 * Used in AP-REQ to prevent replay attacks.
 *
 * SECURITY PROPERTY: Each authenticator is unique and used only once.
 */
sig Authenticator {
    -- Client principal creating this authenticator
    clientPrincipal: one Principal,
    -- Client's realm
    clientRealm: one Realm,
    -- Current timestamp (for freshness)
    ctime: one Timestamp,
    -- Microsecond component for uniqueness
    cusec: one Int,
    -- Optional subkey for additional session key negotiation
    subkey: lone SessionKey,
    -- Sequence number for ordered message delivery
    seqNumber: lone Int
}

-- =============================================================================
-- NTLM SPECIFIC TYPES
-- =============================================================================

/**
 * NTLM hash types.
 */
sig NTHash {
    -- Hash of password (MD4 of UTF-16LE password)
    material: one KeyMaterial
}

/**
 * Server challenge for NTLM authentication.
 */
sig ServerChallenge {
    value: one Nonce,
    timestamp: one Timestamp
}

/**
 * Client challenge for NTLMv2.
 */
sig ClientChallenge {
    value: one Nonce,
    timestamp: one Timestamp
}

/**
 * NTLMv2 response computed from challenges and NT hash.
 */
sig NTLMv2Response {
    -- The response blob
    response: one KeyMaterial,
    -- Client challenge included in computation
    clientChallenge: one ClientChallenge
}

-- =============================================================================
-- CONSTRAINTS AND FACTS
-- =============================================================================

/**
 * Fact: Each principal has a unique name-realm combination.
 * No two different principals can have the same name and realm.
 */
fact UniquePrincipals {
    no disj p1, p2: Principal |
        p1.name = p2.name and p1.realm = p2.realm
}

/**
 * Fact: Authenticators are unique by (client, ctime, cusec).
 * This prevents replay attacks since each authenticator can only be used once.
 */
fact AuthenticatorUniqueness {
    no disj a1, a2: Authenticator |
        a1.clientPrincipal = a2.clientPrincipal and
        a1.ctime = a2.ctime and
        a1.cusec = a2.cusec
}

/**
 * Fact: Session keys have valid time ranges.
 */
fact SessionKeyTimeValidity {
    all sk: SessionKey | lt[sk.validFrom, sk.validUntil]
}

/**
 * Fact: Ticket end time must be after start time.
 */
fact TicketTimeOrdering {
    all tep: TicketEncPart |
        (some tep.startTime implies lt[tep.startTime, tep.endTime]) and
        lt[tep.authTime, tep.endTime]
}

/**
 * Fact: Renewable tickets have renewTill set.
 */
fact RenewableTicketsHaveRenewTill {
    all tep: TicketEncPart |
        RENEWABLE in tep.flags implies some tep.renewTill
}

/**
 * Fact: TGT is issued by KDC.
 */
fact TGTIssuedByKDC {
    all tgt: TGT | tgt.ticketRealm = KDC.realm
}

-- =============================================================================
-- HELPER PREDICATES
-- =============================================================================

/**
 * Check if a timestamp is within valid window of reference time.
 * Models clock skew tolerance.
 */
pred timestampValid[ts: Timestamp, refTime: Time, skewBefore: Time, skewAfter: Time] {
    gte[ts.time, skewBefore] and lte[ts.time, skewAfter]
}

/**
 * Check if a ticket is valid at a given time.
 * Note: Requires the ticket's encrypted part to contain a TicketEncPart.
 */
pred ticketValidAt[t: Ticket, time: Time] {
    -- The plaintext must be a TicketEncPart (type guard)
    t.encPart.plaintext in TicketEncPart and
    let tep = t.encPart.plaintext & TicketEncPart |
        (no tep.startTime or gte[time, tep.startTime]) and
        lt[time, tep.endTime]
}

/**
 * Check if a session key is valid at a given time.
 */
pred sessionKeyValidAt[sk: SessionKey, time: Time] {
    gte[time, sk.validFrom] and lt[time, sk.validUntil]
}

-- =============================================================================
-- ASSERTIONS
-- =============================================================================

/**
 * Assert: Every ticket has properly ordered times.
 */
assert TicketTimesOrdered {
    all t: Ticket, tep: TicketEncPart |
        t.encPart.plaintext = tep implies
        lt[tep.authTime, tep.endTime]
}
check TicketTimesOrdered for 5 but 3 Time

/**
 * Assert: No two principals have identical identity.
 */
assert PrincipalUniqueness {
    all disj p1, p2: Principal |
        not (p1.name = p2.name and p1.realm = p2.realm)
}
check PrincipalUniqueness for 5 but 2 Realm, 4 Name

-- =============================================================================
-- RUN COMMANDS FOR EXPLORATION
-- =============================================================================

/**
 * Generate example instances for visualization.
 */
run ShowTicket {
    some t: Ticket | some SessionKey
} for 3

run ShowPrincipals {
    #Principal >= 3 and some TGT
} for 4
