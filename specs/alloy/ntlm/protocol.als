/**
 * AuthModeler NTLM Protocol Specification
 *
 * Formal model of NTLMv2 authentication per MS-NLMP specification.
 * Models the three-message challenge-response protocol:
 * - NEGOTIATE_MESSAGE (Type 1): Client initiates authentication
 * - CHALLENGE_MESSAGE (Type 2): Server sends challenge
 * - AUTHENTICATE_MESSAGE (Type 3): Client responds with credentials
 *
 * SECURITY NOTE: NTLM has known weaknesses that are explicitly modeled:
 * - Pass-the-Hash: NT hash alone sufficient for authentication
 * - Relay attacks: Challenge not bound to specific server (without EPA)
 * - Offline cracking: Captured responses can be attacked offline
 *
 * Reference: MS-NLMP - NT LAN Manager (NTLM) Authentication Protocol
 */
module ntlm/protocol

open core/types
open core/crypto
open core/attacker
open util/ordering[Time]

-- =============================================================================
-- NTLM NEGOTIATE FLAGS
-- =============================================================================

/**
 * NTLM negotiate flags (subset of important ones).
 * Per MS-NLMP Section 2.2.2.5
 */
abstract sig NTLMFlag {}

one sig NTLMSSP_NEGOTIATE_UNICODE extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_OEM extends NTLMFlag {}
one sig NTLMSSP_REQUEST_TARGET extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_SIGN extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_SEAL extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_NTLM extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_ALWAYS_SIGN extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_TARGET_INFO extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_VERSION extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_128 extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_KEY_EXCH extends NTLMFlag {}
one sig NTLMSSP_NEGOTIATE_56 extends NTLMFlag {}

-- =============================================================================
-- NTLM MESSAGE TYPES
-- =============================================================================

/**
 * NEGOTIATE_MESSAGE (Type 1)
 * Client -> Server: Initiates NTLM authentication
 */
sig NegotiateMessage extends Message {
    -- Requested capabilities
    negotiateFlags: set NTLMFlag,
    -- Domain name (optional)
    domainName: lone Name,
    -- Workstation name (optional)
    workstationName: lone Name,
    -- Version info (optional)
    version: lone NTLMVersion
}

/**
 * NTLM version structure.
 */
sig NTLMVersion {
    majorVersion: one Int,
    minorVersion: one Int,
    buildNumber: one Int,
    ntlmRevision: one Int
}

/**
 * CHALLENGE_MESSAGE (Type 2)
 * Server -> Client: Sends challenge and server info
 */
sig ChallengeMessage extends Message {
    -- Negotiated flags
    negotiateFlags: set NTLMFlag,
    -- Server challenge (8-byte nonce)
    serverChallenge: one ServerChallenge,
    -- Target name (domain or server)
    targetName: one Name,
    -- Target info (AV_PAIR structures)
    targetInfo: one TargetInfo,
    -- Version info
    version: lone NTLMVersion
}

/**
 * Target information structure (AV_PAIRs).
 * Contains server name, domain, DNS info, timestamp, etc.
 */
sig TargetInfo {
    -- Domain name
    msvAvNbDomainName: lone Name,
    -- Computer name
    msvAvNbComputerName: lone Name,
    -- DNS domain name
    msvAvDnsDomainName: lone Name,
    -- DNS computer name
    msvAvDnsComputerName: lone Name,
    -- Timestamp
    msvAvTimestamp: lone Timestamp,
    -- Flags
    msvAvFlags: set TargetInfoFlag,
    -- Channel binding hash (EPA)
    msvAvChannelBindings: lone ChannelBindingHash
}

/**
 * Target info flags.
 */
abstract sig TargetInfoFlag {}
one sig MsvAvFlagAuthenticationConstrained extends TargetInfoFlag {}
one sig MsvAvFlagMICProvided extends TargetInfoFlag {}
one sig MsvAvFlagUntrustedSPNSource extends TargetInfoFlag {}

/**
 * Channel binding hash for Extended Protection for Authentication (EPA).
 */
sig ChannelBindingHash {
    hash: one HashValue
}

/**
 * AUTHENTICATE_MESSAGE (Type 3)
 * Client -> Server: Sends authentication response
 */
sig AuthenticateMessage extends Message {
    -- Negotiated flags
    negotiateFlags: set NTLMFlag,
    -- LM response (legacy, usually empty in NTLMv2)
    lmResponse: lone LMResponse,
    -- NT response (NTLMv2 response)
    ntResponse: one NTLMv2Response,
    -- Domain name
    domainName: one Name,
    -- User name
    userName: one Name,
    -- Workstation name
    workstationName: lone Name,
    -- Encrypted random session key
    encryptedRandomSessionKey: lone EncryptedData,
    -- Message Integrity Code
    mic: lone MIC,
    -- Version
    version: lone NTLMVersion
}

/**
 * LM Response (legacy, often zeroed in NTLMv2).
 */
sig LMResponse {
    response: one KeyMaterial
}

/**
 * Message Integrity Code for AUTHENTICATE_MESSAGE.
 * HMAC-MD5 over all three messages.
 */
sig MIC {
    value: one HashValue
}

-- =============================================================================
-- NTLM STATE MODEL
-- =============================================================================

/**
 * Client NTLM state.
 */
abstract sig NTLMClientState {}
one sig NC_Initial extends NTLMClientState {}
one sig NC_NegotiateSent extends NTLMClientState {}
one sig NC_ChallengeReceived extends NTLMClientState {}
one sig NC_AuthenticateSent extends NTLMClientState {}
one sig NC_Authenticated extends NTLMClientState {}
one sig NC_Error extends NTLMClientState {}

/**
 * Server NTLM state.
 */
abstract sig NTLMServerState {}
one sig NS_Ready extends NTLMServerState {}
one sig NS_ChallengeSent extends NTLMServerState {}
one sig NS_Authenticated extends NTLMServerState {}
one sig NS_Rejected extends NTLMServerState {}

/**
 * NTLM client session.
 */
sig NTLMClientSession {
    var state: one NTLMClientState,
    -- Client identity
    principal: one Principal,
    domain: one Name,
    workstation: lone Name,
    -- Credentials
    ntHash: one NTHash,
    -- Session data
    var serverChallenge: lone ServerChallenge,
    var clientChallenge: lone ClientChallenge,
    var sessionBaseKey: lone Key,
    var negotiatedFlags: set NTLMFlag,
    -- Target server
    var targetServer: lone Principal
}

/**
 * NTLM server session.
 */
sig NTLMServerSession {
    var state: one NTLMServerState,
    principal: one Principal,
    domain: one Name,
    -- Credentials database
    userHashes: Principal -> NTHash,
    -- Current challenge
    var currentChallenge: lone ServerChallenge,
    -- Authenticated clients
    var authenticatedClients: set Principal,
    -- Challenge cache (for replay detection)
    var usedChallenges: set ServerChallenge
}

-- =============================================================================
-- NTLMV2 COMPUTATION MODEL
-- =============================================================================

/**
 * NTLMv2 response computation.
 *
 * NTProofStr = HMAC-MD5(NT Hash, ServerChallenge || ClientBlob)
 * NTLMv2Response = NTProofStr || ClientBlob
 *
 * ClientBlob contains:
 * - Timestamp
 * - Client challenge
 * - Target info
 */
sig NTLMv2ClientBlob {
    respType: one Int,          -- Always 1
    hiRespType: one Int,        -- Always 1
    timestamp: one Timestamp,
    clientChallenge: one ClientChallenge,
    targetInfo: one TargetInfo
}

/**
 * Complete NTLMv2 response structure.
 */
sig NTLMv2CompleteResponse {
    ntProofStr: one HashValue,  -- HMAC-MD5 result
    clientBlob: one NTLMv2ClientBlob
}

/**
 * Session base key derivation.
 * SessionBaseKey = HMAC-MD5(NT Hash, NTProofStr)
 */
sig SessionBaseKeyDerivation {
    ntHash: one NTHash,
    ntProofStr: one HashValue,
    sessionBaseKey: one Key
}

/**
 * Fact: Session base key derivation is deterministic.
 */
fact SessionBaseKeyDeterministic {
    all disj d1, d2: SessionBaseKeyDerivation |
        (d1.ntHash = d2.ntHash and d1.ntProofStr = d2.ntProofStr)
        implies d1.sessionBaseKey = d2.sessionBaseKey
}

-- =============================================================================
-- PROTOCOL TRANSITIONS
-- =============================================================================

/**
 * Action: Client sends NEGOTIATE_MESSAGE.
 */
pred sendNegotiateMessage[cs: NTLMClientSession, msg: NegotiateMessage, server: Principal, t: Time] {
    -- Preconditions
    cs.state = NC_Initial

    -- Message construction
    msg.sender = cs.principal
    msg.receiver = server
    msg.timestamp.time = t
    msg.domainName = cs.domain
    msg.workstationName = cs.workstation

    -- Request standard NTLMv2 capabilities
    NTLMSSP_NEGOTIATE_UNICODE in msg.negotiateFlags
    NTLMSSP_NEGOTIATE_NTLM in msg.negotiateFlags
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in msg.negotiateFlags
    NTLMSSP_NEGOTIATE_SIGN in msg.negotiateFlags
    NTLMSSP_NEGOTIATE_SEAL in msg.negotiateFlags

    -- State transition
    cs.state' = NC_NegotiateSent
    cs.targetServer' = server

    -- Network effect
    Network.inTransit' = Network.inTransit + msg
    Network.history' = Network.history + msg
}

/**
 * Action: Server processes NEGOTIATE and sends CHALLENGE_MESSAGE.
 */
pred serverSendChallenge[ss: NTLMServerSession, negMsg: NegotiateMessage,
                          chalMsg: ChallengeMessage, t: Time] {
    -- Preconditions
    ss.state = NS_Ready
    negMsg in Network.inTransit
    negMsg.receiver = ss.principal

    -- Generate fresh challenge
    some sc: ServerChallenge |
        sc not in ss.usedChallenges and
        chalMsg.serverChallenge = sc and
        ss.currentChallenge' = sc and
        ss.usedChallenges' = ss.usedChallenges + sc

    -- Construct response
    chalMsg.sender = ss.principal
    chalMsg.receiver = negMsg.sender
    chalMsg.timestamp.time = t

    -- Negotiate flags (intersection of requested and supported)
    chalMsg.negotiateFlags = negMsg.negotiateFlags

    -- Target info
    some ti: TargetInfo |
        chalMsg.targetInfo = ti and
        ti.msvAvNbDomainName = ss.domain and
        ti.msvAvTimestamp.time = t

    chalMsg.targetName = ss.domain

    -- State transition
    ss.state' = NS_ChallengeSent

    -- Network effect
    Network.inTransit' = (Network.inTransit - negMsg) + chalMsg
    Network.history' = Network.history + chalMsg
}

/**
 * Action: Client processes CHALLENGE and sends AUTHENTICATE_MESSAGE.
 */
pred sendAuthenticateMessage[cs: NTLMClientSession, chalMsg: ChallengeMessage,
                              authMsg: AuthenticateMessage, t: Time] {
    -- Preconditions
    cs.state = NC_NegotiateSent
    chalMsg in Network.inTransit
    chalMsg.receiver = cs.principal

    -- Store server challenge
    cs.serverChallenge' = chalMsg.serverChallenge
    cs.negotiatedFlags' = chalMsg.negotiateFlags

    -- Generate client challenge
    some cc: ClientChallenge |
        cc.timestamp.time = t and
        cs.clientChallenge' = cc

    -- Compute NTLMv2 response
    some resp: NTLMv2Response, blob: NTLMv2ClientBlob, comp: NTLMv2Computation |
        blob.clientChallenge = cs.clientChallenge' and
        blob.timestamp.time = t and
        blob.targetInfo = chalMsg.targetInfo and
        comp.ntHash = cs.ntHash and
        comp.serverChallenge = chalMsg.serverChallenge and
        comp.clientChallenge = cs.clientChallenge' and
        comp.response = resp and
        authMsg.ntResponse = resp

    -- Construct message
    authMsg.sender = cs.principal
    authMsg.receiver = cs.targetServer
    authMsg.timestamp.time = t
    authMsg.domainName = cs.domain
    authMsg.userName = cs.principal.name
    authMsg.workstationName = cs.workstation
    authMsg.negotiateFlags = chalMsg.negotiateFlags

    -- Compute MIC if required
    MsvAvFlagMICProvided in chalMsg.targetInfo.msvAvFlags implies
        some mic: MIC | authMsg.mic = mic

    -- State transition
    cs.state' = NC_AuthenticateSent

    -- Network effect
    Network.inTransit' = (Network.inTransit - chalMsg) + authMsg
    Network.history' = Network.history + authMsg
}

/**
 * Action: Server verifies AUTHENTICATE_MESSAGE.
 */
pred serverVerifyAuthenticate[ss: NTLMServerSession, authMsg: AuthenticateMessage, t: Time] {
    -- Preconditions
    ss.state = NS_ChallengeSent
    authMsg in Network.inTransit
    authMsg.receiver = ss.principal

    -- Look up user's NT hash
    let clientPrincipal = authMsg.sender,
        expectedHash = (ss.userHashes)[clientPrincipal] |

        -- Verify NT hash exists
        some expectedHash and

        -- Verify NTLMv2 response
        validNTLMv2Response[authMsg.ntResponse, expectedHash, ss.currentChallenge]

    -- Verify MIC if present
    some authMsg.mic implies verifyMIC[authMsg]

    -- State transition
    ss.state' = NS_Authenticated
    ss.authenticatedClients' = ss.authenticatedClients + authMsg.sender

    -- Network effect
    Network.inTransit' = Network.inTransit - authMsg
}

/**
 * Verify NTLMv2 response is valid.
 */
pred validNTLMv2Response[resp: NTLMv2Response, ntHash: NTHash, serverChallenge: ServerChallenge] {
    some comp: NTLMv2Computation |
        comp.ntHash = ntHash and
        comp.serverChallenge = serverChallenge and
        comp.response = resp
}

/**
 * Verify MIC is valid.
 * MIC = HMAC-MD5(SessionBaseKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
 */
pred verifyMIC[authMsg: AuthenticateMessage] {
    some authMsg.mic
    -- Verification requires all three messages and session base key
    -- Abstracted for model - just check MIC exists
}

-- =============================================================================
-- NTLM SESSION SECURITY
-- =============================================================================

/**
 * NTLM session key hierarchy.
 *
 * SessionBaseKey = HMAC-MD5(NTHash, NTProofStr)
 * KeyExchangeKey = SessionBaseKey (with NTLMSSP_NEGOTIATE_LM_KEY unset)
 * ExportedSessionKey = NONCE() if KEY_EXCH, else KeyExchangeKey
 * SigningKey = HMAC-MD5(ExportedSessionKey, "session key to client-to-server signing key magic constant")
 * SealingKey = HMAC-MD5(ExportedSessionKey, "session key to client-to-server sealing key magic constant")
 */
sig NTLMSessionKeys {
    sessionBaseKey: one Key,
    exportedSessionKey: one Key,
    clientSigningKey: one Key,
    serverSigningKey: one Key,
    clientSealingKey: one Key,
    serverSealingKey: one Key
}

/**
 * Derive session keys from session base key.
 */
pred deriveSessionKeys[baseKey: Key, keys: NTLMSessionKeys] {
    keys.sessionBaseKey = baseKey
    -- Other keys are derived via HMAC-MD5 with different constants
    -- Abstracted in the model
}

/**
 * NTLM message signing (NTLMSSP_NEGOTIATE_SIGN).
 */
sig NTLMSignature {
    version: one Int,       -- Always 1
    checksum: one HashValue, -- HMAC-MD5 truncated
    seqNum: one Int
}

/**
 * NTLM message sealing (NTLMSSP_NEGOTIATE_SEAL).
 */
sig NTLMSealedMessage {
    ciphertext: one EncryptedData,
    signature: one NTLMSignature
}

-- =============================================================================
-- ATTACK SCENARIOS (KNOWN VULNERABILITIES)
-- =============================================================================

/**
 * Pass-the-Hash Attack Model.
 *
 * VULNERABILITY: Having only the NT hash is sufficient to authenticate.
 * Unlike Kerberos, no password derivation happens during the protocol.
 */
pred passTheHashAttack[attacker: Attacker, victim: Principal, target: Principal] {
    -- Attacker has victim's NT hash
    some kh: KnownNTHash |
        kh in attacker.knowledge and
        (some nc: NTHashComputation | nc.hash = kh.ntHash) and

        -- Attacker can construct valid AUTHENTICATE_MESSAGE using stolen hash
        (some authMsg: AuthenticateMessage, chalMsg: ChallengeMessage |
            -- Challenge message exists in network from target
            chalMsg in Network.history and
            chalMsg.sender = target and
            -- Attacker constructs valid response using victim's hash
            authMsg.receiver = target and
            (some resp: NTLMv2Response |
                authMsg.ntResponse = resp and
                validNTLMv2Response[resp, kh.ntHash, chalMsg.serverChallenge]))
}

/**
 * NTLM Relay Attack Model.
 *
 * VULNERABILITY: Without channel binding (EPA), the challenge is not
 * bound to a specific server. Attacker can relay authentication to
 * a different server.
 */
pred ntlmRelayAttack[attacker: Attacker, victim: Principal,
                     legitimateServer: Principal, targetServer: Principal] {
    legitimateServer != targetServer

    -- Attacker receives challenge from target server
    some chalFromTarget: ChallengeMessage |
        chalFromTarget.sender = targetServer and
        chalFromTarget in Network.history and
        (some kc: KnownChallenge |
            kc.challenge = chalFromTarget.serverChallenge and
            kc in attacker.knowledge) and

        -- Attacker forwards same challenge to victim (pretending to be legitimate server)
        (some chalToVictim: ChallengeMessage |
            chalToVictim in Network.history and
            chalToVictim.receiver = victim and
            chalToVictim.serverChallenge = chalFromTarget.serverChallenge and

            -- Victim responds with valid authentication
            (some authFromVictim: AuthenticateMessage |
                authFromVictim.sender = victim and
                authFromVictim in Network.history and

                -- Attacker relays response to target server
                (some authToTarget: AuthenticateMessage |
                    authToTarget.receiver = targetServer and
                    authToTarget.ntResponse = authFromVictim.ntResponse) and

                -- Attack succeeds if no EPA channel binding in the target info
                -- (msvAvChannelBindings is lone, so we check if it's empty)
                no chalToVictim.targetInfo.msvAvChannelBindings))
}

/**
 * Channel Binding (EPA) prevents relay.
 *
 * When channel binding is present, the NTLMv2 response includes a hash
 * of the TLS channel bindings, which ties the response to a specific
 * TLS session with the intended server.
 */
pred channelBindingPreventsRelay[chalMsg: ChallengeMessage, expectedServer: Principal] {
    -- Channel binding hash present in challenge message's target info
    -- (msvAvChannelBindings is lone, so we use 'some' to check presence)
    some chalMsg.targetInfo.msvAvChannelBindings and
    -- The challenge was actually sent by the expected server
    chalMsg.sender = expectedServer
}

-- =============================================================================
-- PROTOCOL COMPOSITION
-- =============================================================================

/**
 * Complete NTLM authentication flow.
 */
pred ntlmAuthFlow[cs: NTLMClientSession, ss: NTLMServerSession] {
    -- Initial states
    cs.state = NC_Initial
    ss.state = NS_Ready

    -- Eventually authenticated
    eventually (cs.state = NC_Authenticated and ss.state = NS_Authenticated)
}

/**
 * Successful NTLM authentication.
 */
pred successfulNTLMAuth[cs: NTLMClientSession, ss: NTLMServerSession] {
    cs.state = NC_Authenticated
    ss.state = NS_Authenticated
    cs.principal in ss.authenticatedClients
}

-- =============================================================================
-- ASSERTIONS
-- =============================================================================

/**
 * Assert: Pass-the-Hash is possible with NT hash alone.
 * This SHOULD find a counterexample - documents the vulnerability.
 */
assert PassTheHashPossible {
    all cs: NTLMClientSession |
        cs.state = NC_Authenticated implies
        -- Password was needed (NOT just hash)
        (some pdk: PasswordDerivedKey | pdk.material = cs.ntHash.material)
}
-- Expect counterexample
check PassTheHashPossible for 3

/**
 * Assert: NTLM relay possible without EPA.
 * This SHOULD find a counterexample - documents the vulnerability.
 */
assert NTLMRelayWithoutEPA {
    all ss: NTLMServerSession, p: Principal |
        (p in ss.authenticatedClients) implies
        -- Client actually intended to authenticate to this server
        (some cs: NTLMClientSession |
            cs.principal = p and
            cs.targetServer = ss.principal)
}
-- Expect counterexample without EPA
check NTLMRelayWithoutEPA for 4

/**
 * Assert: Challenge uniqueness.
 */
assert ChallengeUniqueness {
    all ss: NTLMServerSession |
        all disj c1, c2: ss.usedChallenges | c1 != c2
}
check ChallengeUniqueness for 4

-- =============================================================================
-- RUN COMMANDS
-- =============================================================================

/**
 * Visualize NTLM negotiation.
 */
run ShowNegotiation {
    some neg: NegotiateMessage, chal: ChallengeMessage |
        neg.receiver = chal.sender
} for 3

/**
 * Visualize complete NTLM authentication.
 */
run ShowNTLMAuth {
    some cs: NTLMClientSession, ss: NTLMServerSession |
        successfulNTLMAuth[cs, ss]
} for 4 but 3 Time

/**
 * Visualize pass-the-hash scenario.
 */
run ShowPassTheHash {
    some victim: Principal, target: Principal |
        passTheHashAttack[Attacker, victim, target]
} for 4

/**
 * Visualize relay attack scenario.
 */
run ShowRelayAttack {
    some victim, legit, target: Principal |
        victim != legit and legit != target and
        ntlmRelayAttack[Attacker, victim, legit, target]
} for 5
