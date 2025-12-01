/**
 * AuthModeler Dolev-Yao Attacker Model
 *
 * Models a network adversary with the following capabilities:
 * - INTERCEPT: Can capture any message on the network
 * - INJECT: Can send arbitrary messages to any party
 * - REPLAY: Can resend previously captured messages
 * - CONSTRUCT: Can create new messages from known components
 * - DECRYPT: Can decrypt ciphertext IF the key is known
 *
 * The attacker CANNOT:
 * - Break cryptographic primitives (no brute force)
 * - Guess random values (nonces, session keys)
 * - Recover plaintext without the decryption key
 * - Forge signatures/MACs without the signing key
 *
 * This model is the standard for protocol security analysis.
 */
module core/attacker

open core/types
open core/crypto
open util/ordering[Time]

-- =============================================================================
-- ATTACKER MODEL
-- =============================================================================

/**
 * The adversary (single attacker for simplicity).
 * In Dolev-Yao model, the network IS the attacker.
 */
one sig Attacker {
    -- Initial knowledge (compromised credentials, public info)
    initialKnowledge: set Knowledge,
    -- Knowledge accumulated during protocol execution
    var knowledge: set Knowledge
}

/**
 * Abstract knowledge item - anything the attacker might know.
 */
abstract sig Knowledge {}

/**
 * Concrete knowledge types.
 */
sig KnownKey extends Knowledge {
    key: one Key
}

sig KnownPlaintext extends Knowledge {
    plaintext: one Plaintext
}

sig KnownCiphertext extends Knowledge {
    ciphertext: one EncryptedData
}

sig KnownNonce extends Knowledge {
    nonce: one Nonce
}

sig KnownTicket extends Knowledge {
    ticket: one Ticket
}

sig KnownTimestamp extends Knowledge {
    timestamp: one Timestamp
}

sig KnownPrincipal extends Knowledge {
    principal: one Principal
}

sig KnownNTHash extends Knowledge {
    ntHash: one NTHash
}

sig KnownChallenge extends Knowledge {
    challenge: one ServerChallenge
}

-- =============================================================================
-- NETWORK MODEL
-- =============================================================================

/**
 * Network channel - all messages pass through here.
 * The attacker controls the network.
 */
one sig Network {
    -- Messages currently in transit
    var inTransit: set Message,
    -- All messages ever sent (for replay)
    var history: set Message
}

/**
 * Abstract network message.
 */
abstract sig Message {
    sender: one Principal + Attacker,
    receiver: one Principal,
    timestamp: one Timestamp
}

-- =============================================================================
-- ATTACKER CAPABILITIES
-- =============================================================================

/**
 * Capability: Intercept messages from the network.
 * Adds message contents to attacker knowledge.
 */
pred intercept[m: Message] {
    m in Network.inTransit
    -- Add message contents to knowledge
    -- (specific extraction depends on message type)
}

/**
 * Capability: Inject a message into the network.
 * Message must be constructible from attacker's knowledge.
 */
pred inject[m: Message] {
    m.sender = Attacker
    constructible[m]
}

/**
 * Capability: Replay a previously seen message.
 */
pred replay[m: Message] {
    m in Network.history
    Network.inTransit' = Network.inTransit + m
}

/**
 * Capability: Decrypt ciphertext if key is known.
 */
pred canDecryptWithKnowledge[ed: EncryptedData] {
    some kk: KnownKey |
        kk in Attacker.knowledge and
        canDecrypt[ed, kk.key]
}

/**
 * Predicate: Message is constructible from attacker knowledge.
 * Abstract - specialized per message type.
 */
pred constructible[m: Message] {
    -- All components of m must be derivable from knowledge
    -- This is protocol-specific and refined in protocol modules
    some Attacker.knowledge
}

-- =============================================================================
-- KNOWLEDGE EVOLUTION
-- =============================================================================

/**
 * Initial attacker knowledge includes:
 * - Public keys/certificates
 * - Network topology (realm names, service names)
 * - Potentially compromised credentials
 */
fact InitialKnowledge {
    -- All realm and principal names are public
    all p: Principal |
        (some kp: KnownPrincipal | kp.principal = p and kp in Attacker.initialKnowledge)

    -- Initial knowledge is subset of all knowledge
    Attacker.initialKnowledge in Attacker.knowledge
}

/**
 * Knowledge can only grow (attacker never forgets).
 */
fact KnowledgeMonotonic {
    always (Attacker.knowledge in Attacker.knowledge')
}

/**
 * Knowledge derivation rules.
 */
pred deriveKnowledge {
    -- Rule 1: Intercept adds message to knowledge
    all m: Network.inTransit |
        messageToKnowledge[m] in Attacker.knowledge'

    -- Rule 2: Decrypt if key is known
    all ed: EncryptedData, kk: KnownKey |
        (kk in Attacker.knowledge and ed.encryptionKey = kk.key) implies
        (some kp: KnownPlaintext | kp.plaintext = ed.plaintext and kp in Attacker.knowledge')

    -- Rule 3: Encrypt if key and plaintext known
    -- (attacker can create ciphertexts)

    -- Rule 4: Compose messages from known parts
    -- (protocol-specific)
}

/**
 * Convert message to knowledge items.
 * Protocol-specific - returns what attacker learns from message.
 */
fun messageToKnowledge[m: Message]: set Knowledge {
    -- Base case: timestamp is always visible
    { kt: KnownTimestamp | kt.timestamp = m.timestamp }
}

-- =============================================================================
-- ATTACK SCENARIOS
-- =============================================================================

/**
 * Passive attacker: only intercepts, does not modify/inject.
 */
pred passiveAttacker {
    all m: Network.inTransit | m.sender != Attacker
    Network.history = Network.history'  -- No replay
}

/**
 * Active attacker: can intercept, inject, and replay.
 */
pred activeAttacker {
    -- No restrictions beyond constructibility
}

/**
 * Scenario: Man-in-the-middle attack.
 * Attacker intercepts messages between client and server.
 */
pred mitm[client: Principal, server: Principal] {
    some m: Message |
        m.sender = client and
        m.receiver = server and
        m in Network.inTransit
    -- Attacker can modify and forward
}

/**
 * Scenario: Replay attack attempt.
 * Attacker resends a captured authentication message.
 * A message from history is re-injected into the network.
 */
pred replayAttempt {
    some m: Message |
        -- Message was previously sent (in history)
        m in Network.history and
        -- And attacker re-injects it into the network
        m in Network.inTransit and
        -- The message sender is not the attacker (it's a legitimate message being replayed)
        m.sender != Attacker
}

/**
 * Scenario: Credential compromise.
 * Attacker has obtained a legitimate user's long-term key.
 */
pred credentialCompromise[p: Principal] {
    some kk: KnownKey, ltk: LongTermKey |
        ltk.owner = p and
        kk.key = ltk and
        kk in Attacker.knowledge
}

/**
 * Scenario: Pass-the-hash attack.
 * Attacker has NT hash but not plaintext password.
 * The victim principal's hash is known but password is not.
 */
pred passTheHash[victim: Principal] {
    some kh: KnownNTHash |
        -- Attacker knows the NT hash
        kh in Attacker.knowledge and
        -- The hash corresponds to the victim (through some computation)
        (some nc: NTHashComputation | nc.hash = kh.ntHash) and
        -- But attacker does NOT know the plaintext password that produced this hash
        not (some kp: KnownPlaintext, nc: NTHashComputation |
            nc.hash = kh.ntHash and
            kp.plaintext = nc.password and
            kp in Attacker.knowledge)
}

/**
 * Scenario: Golden Ticket attack.
 * Attacker has compromised the KRBTGT key.
 */
pred goldenTicketCapability {
    some kk: KnownKey, ltk: LongTermKey |
        ltk.owner = KRBTGT and
        kk.key = ltk and
        kk in Attacker.knowledge
}

/**
 * Scenario: NTLM relay attack.
 * Attacker relays NTLM authentication to a different server.
 */
pred ntlmRelayPossible[victim: Principal, targetServer: Principal] {
    some sc: ServerChallenge |
        -- Attacker receives challenge from target
        some kc: KnownChallenge |
            kc.challenge = sc and kc in Attacker.knowledge
        -- Can forward to victim and relay response
}

-- =============================================================================
-- SECURITY PROPERTIES
-- =============================================================================

/**
 * Property: Attacker cannot learn long-term keys
 * (unless explicitly compromised in initial knowledge).
 */
pred longTermKeySecrecy[ltk: LongTermKey] {
    no kk: KnownKey |
        kk.key = ltk and
        kk in Attacker.knowledge and
        kk not in Attacker.initialKnowledge
}

/**
 * Property: Attacker cannot learn session keys.
 */
pred sessionKeySecrecy[sk: SessionKey] {
    no kk: KnownKey |
        kk.key = sk and
        kk in Attacker.knowledge
}

/**
 * Property: Attacker cannot decrypt ticket contents.
 */
pred ticketConfidentiality[t: Ticket] {
    not canDecryptWithKnowledge[t.encPart]
}

/**
 * Property: Attacker cannot forge valid authenticators.
 */
pred authenticatorUnforgeability {
    all a: Authenticator, kt: KnownTicket |
        (kt.ticket in TGT + ServiceTicket and kt in Attacker.knowledge)
        implies
        -- Cannot create authenticator without session key
        (no kk: KnownKey |
            some tep: TicketEncPart |
                kt.ticket.encPart.plaintext = tep and
                kk.key = tep.sessionKey and
                kk in Attacker.knowledge)
}

-- =============================================================================
-- ASSERTIONS
-- =============================================================================

/**
 * Assert: Perfect forward secrecy for session keys.
 * Compromising long-term key doesn't reveal past session keys.
 */
assert PerfectForwardSecrecy {
    all sk: SessionKey, ltk: LongTermKey |
        credentialCompromise[ltk.owner] implies sessionKeySecrecy[sk]
}
-- Note: This may fail for Kerberos which doesn't have PFS by default
-- check PerfectForwardSecrecy for 4

/**
 * Assert: KRBTGT key compromise is catastrophic.
 * If KRBTGT is compromised, attacker can forge any ticket.
 */
assert GoldenTicketIsCatastrophic {
    goldenTicketCapability implies
    (all t: Ticket | canDecryptWithKnowledge[t.encPart])
}
check GoldenTicketIsCatastrophic for 3

/**
 * Assert: Without key, cannot decrypt.
 */
assert EncryptionProtectsConfidentiality {
    all ed: EncryptedData |
        (no kk: KnownKey | kk.key = ed.encryptionKey and kk in Attacker.knowledge)
        implies not canDecryptWithKnowledge[ed]
}
check EncryptionProtectsConfidentiality for 4

-- =============================================================================
-- RUN COMMANDS
-- =============================================================================

/**
 * Visualize attacker with some knowledge.
 */
run ShowAttackerKnowledge {
    #Attacker.knowledge >= 3
    some KnownKey & Attacker.knowledge
} for 4 but 2 Time, 3 Principal

/**
 * Visualize MITM scenario.
 */
run ShowMITM {
    some disj c, s: Principal | mitm[c, s]
} for 3

/**
 * Visualize credential compromise scenario.
 */
run ShowCompromise {
    some p: Principal - KDC - KRBTGT | credentialCompromise[p]
} for 3

/**
 * Visualize pass-the-hash scenario.
 */
run ShowPassTheHash {
    some p: Principal | passTheHash[p]
} for 3
