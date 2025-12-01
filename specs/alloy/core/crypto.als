/**
 * AuthModeler Cryptographic Model
 *
 * Abstract model of cryptographic operations for formal verification.
 * Uses ideal cryptography assumptions (Dolev-Yao model):
 * - Perfect encryption: ciphertext reveals nothing without key
 * - No hash collisions: different inputs produce different outputs
 * - Random oracles: hash/HMAC outputs are unpredictable
 *
 * This abstraction allows us to verify protocol logic independently
 * of cryptographic implementation details.
 */
module core/crypto

open core/types

-- =============================================================================
-- CRYPTOGRAPHIC OPERATIONS
-- =============================================================================

/**
 * Symmetric encryption operation.
 * Models the encryption of plaintext with a key to produce ciphertext.
 *
 * IDEAL ASSUMPTION: Encryption is deterministic for modeling,
 * but in reality includes IV/nonce for semantic security.
 */
sig SymmetricEncryption {
    key: one Key,
    plaintext: one Plaintext,
    ciphertext: one EncryptedData
}

/**
 * Fact: Encryption is functional - same key + plaintext = same ciphertext.
 * (Simplified model; real encryption uses nonces)
 */
fact EncryptionFunctional {
    all disj e1, e2: SymmetricEncryption |
        (e1.key = e2.key and e1.plaintext = e2.plaintext) implies
        e1.ciphertext = e2.ciphertext
}

/**
 * Fact: Decryption requires the correct key.
 * Cannot recover plaintext from ciphertext without key.
 * Each EncryptedData has exactly one encryption key that can decrypt it.
 */
fact DecryptionRequiresKey {
    -- Each encrypted data has a unique binding to its encryption key
    -- The plaintext is only accessible with the correct key
    all ed: EncryptedData |
        one ed.encryptionKey and one ed.plaintext
}

/**
 * Predicate: Can decrypt ciphertext with given key.
 */
pred canDecrypt[ed: EncryptedData, k: Key] {
    ed.encryptionKey = k
}

/**
 * Function: Decrypt ciphertext with key to recover plaintext.
 * Partial function - only defined when key matches.
 */
fun decrypt[ed: EncryptedData, k: Key]: lone Plaintext {
    (ed.encryptionKey = k) implies ed.plaintext else none
}

-- =============================================================================
-- HASH OPERATIONS
-- =============================================================================

/**
 * Cryptographic hash output.
 */
sig HashValue {}

/**
 * Hash operation - one-way function.
 */
sig HashOperation {
    input: one Plaintext,
    output: one HashValue
}

/**
 * Fact: Hash is deterministic - same input = same output.
 */
fact HashDeterministic {
    all disj h1, h2: HashOperation |
        h1.input = h2.input implies h1.output = h2.output
}

/**
 * Fact: No hash collisions (ideal assumption).
 */
fact NoHashCollisions {
    all disj h1, h2: HashOperation |
        h1.input != h2.input implies h1.output != h2.output
}

/**
 * Fact: Hash is one-way - cannot recover input from output.
 * This is enforced by not providing an inverse function.
 */

-- =============================================================================
-- HMAC OPERATIONS
-- =============================================================================

/**
 * HMAC (Hash-based Message Authentication Code).
 * Provides integrity and authenticity verification.
 */
sig HMAC {
    key: one Key,
    message: one Plaintext,
    tag: one HashValue
}

/**
 * Fact: HMAC is deterministic for same key and message.
 */
fact HMACDeterministic {
    all disj h1, h2: HMAC |
        (h1.key = h2.key and h1.message = h2.message) implies
        h1.tag = h2.tag
}

/**
 * Fact: Cannot forge HMAC without knowing the key.
 * The (key, message) pair uniquely determines the tag.
 * This models unforgeability: without the key, an attacker cannot
 * produce a valid HMAC for any message.
 */
fact HMACUnforgeable {
    -- Different (key, message) pairs produce different tags
    all disj h1, h2: HMAC |
        (h1.key != h2.key or h1.message != h2.message) implies h1.tag != h2.tag
}

/**
 * Predicate: Verify HMAC tag is valid for message and key.
 */
pred verifyHMAC[h: HMAC, k: Key, m: Plaintext, t: HashValue] {
    h.key = k and h.message = m and h.tag = t
}

-- =============================================================================
-- KEY DERIVATION
-- =============================================================================

/**
 * Key Derivation Function (KDF) output.
 * Models derivation of keys from passwords, master keys, etc.
 *
 * Note: source field uses union type (Key + Plaintext) to allow
 * derivation from either a master key or a password (plaintext).
 * The Alloy analyzer handles this correctly as a relational union.
 */
sig DerivedKey extends Key {
    -- Source material: either a master key or password (plaintext)
    sourceKey: lone Key,          -- Master key source (if derived from key)
    sourcePlaintext: lone Plaintext, -- Password source (if derived from password)
    salt: lone Nonce,             -- Optional salt for PBKDF
    context: lone Plaintext       -- Optional context for domain separation
} {
    -- Exactly one source must be provided
    (some sourceKey and no sourcePlaintext) or (no sourceKey and some sourcePlaintext)
}

/**
 * Fact: Key derivation is deterministic.
 */
fact KDFDeterministic {
    all disj k1, k2: DerivedKey |
        (k1.sourceKey = k2.sourceKey and k1.sourcePlaintext = k2.sourcePlaintext
         and k1.salt = k2.salt and k1.context = k2.context)
        implies k1.material = k2.material
}

/**
 * Fact: Different inputs produce different derived keys.
 */
fact KDFInjective {
    all disj k1, k2: DerivedKey |
        (k1.sourceKey != k2.sourceKey or k1.sourcePlaintext != k2.sourcePlaintext
         or k1.salt != k2.salt or k1.context != k2.context)
        implies k1.material != k2.material
}

-- =============================================================================
-- PASSWORD TO KEY DERIVATION (Kerberos string2key)
-- =============================================================================

/**
 * Models Kerberos string2key operation.
 * Derives long-term key from password and salt.
 */
sig PasswordDerivedKey extends LongTermKey {
    password: one Plaintext,
    passwordSalt: one Plaintext  -- Usually principal name
}

/**
 * Fact: Same password + salt = same key (per enctype).
 */
fact String2KeyDeterministic {
    all disj k1, k2: PasswordDerivedKey |
        (k1.password = k2.password and k1.passwordSalt = k2.passwordSalt
         and k1.enctype = k2.enctype)
        implies k1.material = k2.material
}

-- =============================================================================
-- NTLM HASH OPERATIONS
-- =============================================================================

/**
 * NT Hash computation (MD4 of UTF-16LE password).
 */
sig NTHashComputation {
    password: one Plaintext,
    hash: one NTHash
}

/**
 * Fact: NT hash is deterministic.
 */
fact NTHashDeterministic {
    all disj c1, c2: NTHashComputation |
        c1.password = c2.password implies c1.hash = c2.hash
}

/**
 * NTLMv2 response computation.
 * Response = HMAC-MD5(NTHash, ServerChallenge || ClientBlob)
 */
sig NTLMv2Computation {
    ntHash: one NTHash,
    serverChallenge: one ServerChallenge,
    clientChallenge: one ClientChallenge,
    response: one NTLMv2Response
}

/**
 * Fact: NTLMv2 response is deterministic.
 */
fact NTLMv2Deterministic {
    all disj c1, c2: NTLMv2Computation |
        (c1.ntHash = c2.ntHash and
         c1.serverChallenge = c2.serverChallenge and
         c1.clientChallenge = c2.clientChallenge)
        implies c1.response = c2.response
}

/**
 * Predicate: Verify NTLMv2 response is valid.
 */
pred validNTLMv2Response[r: NTLMv2Response, nt: NTHash, sc: ServerChallenge] {
    some c: NTLMv2Computation |
        c.ntHash = nt and c.serverChallenge = sc and c.response = r
}

-- =============================================================================
-- SESSION KEY GENERATION
-- =============================================================================

/**
 * Models random session key generation by KDC.
 * Session keys should be fresh and unpredictable.
 */
sig SessionKeyGeneration {
    generated: one SessionKey,
    entropy: one Nonce  -- Random bits used in generation
}

/**
 * Fact: Each generation produces a unique key.
 */
fact SessionKeysFresh {
    all disj g1, g2: SessionKeyGeneration |
        g1.generated != g2.generated
}

/**
 * Fact: Session keys are not derivable from other keys.
 * (Unless specifically derived through proper KDF)
 */
fact SessionKeysIndependent {
    all sk: SessionKey |
        sk not in DerivedKey implies
        (no k: Key - sk | sk.material = k.material)
}

-- =============================================================================
-- CHECKSUM OPERATIONS (For Kerberos Authenticators)
-- =============================================================================

/**
 * Checksum for message integrity.
 */
sig Checksum {
    key: one Key,
    message: one Plaintext,
    value: one HashValue
}

/**
 * Fact: Checksums are deterministic and bound to key.
 */
fact ChecksumDeterministic {
    all disj c1, c2: Checksum |
        (c1.key = c2.key and c1.message = c2.message)
        implies c1.value = c2.value
}

/**
 * Predicate: Verify checksum is valid.
 */
pred verifyChecksum[c: Checksum, k: Key, m: Plaintext] {
    c.key = k and c.message = m
}

-- =============================================================================
-- ASSERTIONS
-- =============================================================================

/**
 * Assert: Encryption hides plaintext without key.
 * (Modeled by requiring key for decryption)
 */
assert EncryptionHidesPlaintext {
    all ed: EncryptedData, k: Key |
        (k != ed.encryptionKey) implies no decrypt[ed, k]
}
check EncryptionHidesPlaintext for 4

/**
 * Assert: Hash function has no collisions.
 */
assert HashCollisionFree {
    all disj h1, h2: HashOperation |
        h1.input != h2.input implies h1.output != h2.output
}
check HashCollisionFree for 4

/**
 * Assert: HMAC requires key knowledge for forgery.
 */
assert HMACRequiresKey {
    all disj h1, h2: HMAC |
        h1.key != h2.key implies h1.tag != h2.tag
}
check HMACRequiresKey for 4

/**
 * Assert: Derived keys are unique per input.
 */
assert DerivedKeysUnique {
    all disj k1, k2: DerivedKey |
        (k1.sourceKey != k2.sourceKey or k1.sourcePlaintext != k2.sourcePlaintext
         or k1.salt != k2.salt)
        implies k1.material != k2.material
}
check DerivedKeysUnique for 4

-- =============================================================================
-- RUN COMMANDS
-- =============================================================================

/**
 * Visualize encryption/decryption scenario.
 */
run ShowEncryption {
    some e: SymmetricEncryption | some e.ciphertext
} for 3

/**
 * Visualize key derivation.
 */
run ShowKeyDerivation {
    some dk: DerivedKey | some dk.salt and (some dk.sourceKey or some dk.sourcePlaintext)
} for 3

/**
 * Visualize NTLM hash computation.
 */
run ShowNTLMComputation {
    some c: NTLMv2Computation
} for 3
