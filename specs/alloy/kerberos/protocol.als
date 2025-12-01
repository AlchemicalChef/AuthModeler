/**
 * AuthModeler Kerberos Protocol Specification
 *
 * Formal model of Kerberos V5 authentication per RFC 4120.
 * Models the three main exchanges:
 * - AS Exchange: Client obtains TGT from Authentication Service
 * - TGS Exchange: Client obtains service ticket using TGT
 * - AP Exchange: Client authenticates to service using service ticket
 *
 * Reference: RFC 4120 - The Kerberos Network Authentication Service (V5)
 */
module kerberos/protocol

open core/types
open core/crypto
open core/attacker
open util/ordering[Time]

-- =============================================================================
-- KERBEROS MESSAGE TYPES
-- =============================================================================

/**
 * AS-REQ: Authentication Service Request (Client -> KDC)
 * Client requests a TGT.
 */
sig ASRequest extends Message {
    -- Pre-authentication data (encrypted timestamp)
    padata: lone PreAuthData,
    -- Client principal requesting the TGT
    clientPrincipal: one Principal,
    -- Target realm
    targetRealm: one Realm,
    -- Server principal (always krbtgt/REALM)
    serverPrincipal: one Principal,
    -- Requested ticket validity times
    from: lone Time,
    till: one Time,
    -- Nonce for freshness
    reqNonce: one Nonce,
    -- Requested encryption types (preference order)
    requestedEtypes: set EncryptionType
} {
    -- AS-REQ is always addressed to the KDC
    receiver = KDC
    -- Server is always krbtgt
    serverPrincipal = KRBTGT
}

/**
 * Pre-authentication data for AS-REQ.
 * PA-ENC-TIMESTAMP: Encrypted timestamp proving knowledge of password.
 */
sig PreAuthData {
    -- Encrypted timestamp (proves client knows password-derived key)
    encTimestamp: one EncryptedData
}

/**
 * AS-REP: Authentication Service Reply (KDC -> Client)
 * Contains the TGT and session key.
 */
sig ASReply extends Message {
    -- Client principal this reply is for
    clientPrincipal: one Principal,
    -- The TGT (encrypted with krbtgt key, opaque to client)
    ticket: one TGT,
    -- Encrypted part for client (contains session key)
    encPart: one EncryptedData,
    -- The encryption key used for encPart (client's key)
    encKey: one Key
} {
    -- AS-REP is sent by KDC
    sender = KDC
}

/**
 * Contents of AS-REP encrypted part (decryptable by client).
 */
sig ASRepEncPart extends Plaintext {
    -- Session key for TGT
    sessionKey: one SessionKey,
    -- Last successful auth time
    lastReq: lone Time,
    -- Nonce from request (for freshness binding)
    nonce: one Nonce,
    -- Ticket validity times
    authTime: one Time,
    startTime: lone Time,
    endTime: one Time,
    renewTill: lone Time,
    -- Server principal (krbtgt)
    serverPrincipal: one Principal,
    -- Server realm
    serverRealm: one Realm
}

/**
 * TGS-REQ: Ticket Granting Service Request (Client -> KDC)
 * Client uses TGT to request a service ticket.
 */
sig TGSRequest extends Message {
    -- Pre-auth data containing the TGT and authenticator
    padata: one TGSPreAuthData,
    -- Target service principal
    serverPrincipal: one Principal,
    -- Target realm
    targetRealm: one Realm,
    -- Requested validity times
    from: lone Time,
    till: one Time,
    -- Nonce for freshness
    reqNonce: one Nonce,
    -- Requested encryption types
    requestedEtypes: set EncryptionType
} {
    -- TGS-REQ is addressed to KDC
    receiver = KDC
    -- Not requesting TGT again
    serverPrincipal != KRBTGT
}

/**
 * Pre-authentication data for TGS-REQ.
 * Contains the TGT and authenticator.
 */
sig TGSPreAuthData {
    -- The client's TGT
    tgt: one TGT,
    -- Authenticator proving possession of TGT session key
    authenticator: one EncryptedData
}

/**
 * TGS-REP: Ticket Granting Service Reply (KDC -> Client)
 * Contains the service ticket.
 */
sig TGSReply extends Message {
    -- Client principal
    clientPrincipal: one Principal,
    -- The service ticket
    ticket: one ServiceTicket,
    -- Encrypted part for client
    encPart: one EncryptedData,
    -- Encryption key (TGT session key)
    encKey: one SessionKey
} {
    -- TGS-REP is sent by KDC
    sender = KDC
}

/**
 * Contents of TGS-REP encrypted part.
 */
sig TGSRepEncPart extends Plaintext {
    -- Session key for service ticket
    sessionKey: one SessionKey,
    -- Nonce from request
    nonce: one Nonce,
    -- Ticket validity times
    authTime: one Time,
    startTime: lone Time,
    endTime: one Time,
    renewTill: lone Time,
    -- Server principal
    serverPrincipal: one Principal,
    -- Server realm
    serverRealm: one Realm
}

/**
 * AP-REQ: Application Protocol Request (Client -> Service)
 * Client authenticates to service using service ticket.
 */
sig APRequest extends Message {
    -- The service ticket
    ticket: one ServiceTicket,
    -- Authenticator proving possession of service session key
    authenticator: one EncryptedData,
    -- Request mutual authentication
    mutualRequired: one Bool
}

/**
 * Boolean type for flags.
 */
abstract sig Bool {}
one sig True, False extends Bool {}

/**
 * AP-REP: Application Protocol Reply (Service -> Client)
 * Confirms mutual authentication.
 */
sig APReply extends Message {
    -- Encrypted part containing ctime/cusec from authenticator
    encPart: one EncryptedData,
    -- Session key used for encryption
    encKey: one SessionKey
}

/**
 * Contents of AP-REP encrypted part.
 */
sig APRepEncPart extends Plaintext {
    -- Timestamp from client's authenticator
    ctime: one Timestamp,
    cusec: one Int,
    -- Optional subkey
    subkey: lone SessionKey,
    -- Optional sequence number
    seqNumber: lone Int
}

/**
 * Kerberos error message.
 */
sig KerberosError extends Message {
    errorCode: one KerberosErrorCode,
    errorText: lone Plaintext,
    -- Time when error occurred
    serverTime: one Timestamp,
    -- Server's realm and name
    serverRealm: one Realm,
    serverPrincipal: one Principal,
    -- Client info (if known)
    clientRealm: lone Realm,
    clientPrincipal: lone Principal
}

/**
 * Kerberos error codes (subset).
 */
abstract sig KerberosErrorCode {}
one sig KDC_ERR_PREAUTH_REQUIRED extends KerberosErrorCode {}
one sig KDC_ERR_CLIENT_NOT_TRUSTED extends KerberosErrorCode {}
one sig KRB_AP_ERR_BAD_INTEGRITY extends KerberosErrorCode {}
one sig KRB_AP_ERR_TKT_EXPIRED extends KerberosErrorCode {}
one sig KRB_AP_ERR_REPEAT extends KerberosErrorCode {}
one sig KRB_AP_ERR_SKEW extends KerberosErrorCode {}

-- =============================================================================
-- PROTOCOL STATE MODEL
-- =============================================================================

/**
 * Client protocol state.
 */
abstract sig ClientState {}
one sig CS_Initial extends ClientState {}
one sig CS_ASReqSent extends ClientState {}
one sig CS_HasTGT extends ClientState {}
one sig CS_TGSReqSent extends ClientState {}
one sig CS_HasServiceTicket extends ClientState {}
one sig CS_APReqSent extends ClientState {}
one sig CS_Authenticated extends ClientState {}
one sig CS_Error extends ClientState {}

/**
 * Client session state.
 */
sig ClientSession {
    var state: one ClientState,
    principal: one Principal,
    realm: one Realm,
    -- Credentials
    longTermKey: one LongTermKey,
    -- Acquired tickets
    var tgt: lone TGT,
    var tgtSessionKey: lone SessionKey,
    var serviceTicket: lone ServiceTicket,
    var serviceSessionKey: lone SessionKey,
    -- Current target
    var targetService: lone Principal,
    -- Pending nonces (for reply verification)
    var pendingNonce: lone Nonce,
    -- Authenticator cache (for replay detection)
    var usedAuthenticators: set Authenticator
} {
    longTermKey.owner = principal
}

/**
 * Service session state.
 */
sig ServiceSession {
    var state: one ServiceState,
    principal: one Principal,
    realm: one Realm,
    -- Service's long-term key
    longTermKey: one LongTermKey,
    -- Accepted authenticators (for replay detection)
    var authenticatorCache: set Authenticator,
    -- Established sessions
    var activeSessions: set ClientSession
} {
    longTermKey.owner = principal
}

/**
 * Service protocol state.
 */
abstract sig ServiceState {}
one sig SS_Ready extends ServiceState {}
one sig SS_Authenticated extends ServiceState {}

/**
 * KDC state.
 */
one sig KDCState {
    -- Principal database
    principals: set Principal,
    -- Long-term keys for all principals
    keys: Principal -> LongTermKey,
    -- Issued tickets
    var issuedTickets: set Ticket
}

-- =============================================================================
-- PROTOCOL TRANSITIONS
-- =============================================================================

/**
 * Action: Client sends AS-REQ.
 * Precondition: Client in Initial state
 * Postcondition: Client in ASReqSent state
 */
pred sendASRequest[cs: ClientSession, asReq: ASRequest, t: Time] {
    -- Preconditions
    cs.state = CS_Initial
    asReq.clientPrincipal = cs.principal
    asReq.targetRealm = cs.realm
    asReq.timestamp.time = t

    -- Pre-authentication: encrypt current timestamp with client's key
    some pa: PreAuthData |
        asReq.padata = pa and
        pa.encTimestamp.encryptionKey = cs.longTermKey

    -- State transition
    cs.state' = CS_ASReqSent
    cs.pendingNonce' = asReq.reqNonce

    -- Network effect
    Network.inTransit' = Network.inTransit + asReq
    Network.history' = Network.history + asReq
}

/**
 * Action: KDC processes AS-REQ and sends AS-REP.
 * Precondition: Valid AS-REQ received
 * Postcondition: AS-REP sent with TGT
 */
pred kdcProcessASRequest[asReq: ASRequest, asRep: ASReply, t: Time] {
    -- Preconditions
    asReq in Network.inTransit
    asReq.clientPrincipal in KDCState.principals

    -- Verify pre-authentication
    some pa: asReq.padata |
        verifyPreAuth[pa, asReq.clientPrincipal, t]

    -- Generate TGT
    some tgt: TGT, sk: SessionKey, tep: TicketEncPart |
        asRep.ticket = tgt and
        tep.clientPrincipal = asReq.clientPrincipal and
        tep.sessionKey = sk and
        tep.authTime = t and
        tep.endTime = asReq.till and
        tgt.encPart.plaintext = tep and
        -- TGT encrypted with KRBTGT's key
        tgt.encPart.encryptionKey = (KDCState.keys)[KRBTGT]

    -- Encrypt reply with client's key
    some encPart: ASRepEncPart |
        asRep.encPart.plaintext = encPart and
        asRep.encPart.encryptionKey = (KDCState.keys)[asReq.clientPrincipal] and
        encPart.nonce = asReq.reqNonce and
        -- Session key must match the one in the TGT
        (some ticketPlaintext: TicketEncPart |
            asRep.ticket.encPart.plaintext = ticketPlaintext and
            encPart.sessionKey = ticketPlaintext.sessionKey) and
        encPart.authTime = t

    asRep.clientPrincipal = asReq.clientPrincipal
    asRep.receiver = asReq.clientPrincipal
    asRep.timestamp.time = t

    -- Effects
    KDCState.issuedTickets' = KDCState.issuedTickets + asRep.ticket
    Network.inTransit' = Network.inTransit - asReq + asRep
    Network.history' = Network.history + asRep
}

/**
 * Pre-auth timestamp plaintext (proves knowledge of password).
 */
sig PreAuthTimestamp extends Plaintext {
    paTimestamp: one Timestamp
}

/**
 * Verify pre-authentication data.
 * Pre-auth proves knowledge of password by encrypting a timestamp.
 */
pred verifyPreAuth[pa: PreAuthData, p: Principal, currentTime: Time] {
    -- Encrypted timestamp must be decryptable with client's key
    pa.encTimestamp.encryptionKey = (KDCState.keys)[p]
    -- Verify the decrypted content is a timestamp within acceptable skew
    some pat: PreAuthTimestamp |
        pa.encTimestamp.plaintext = pat and
        -- Timestamp within acceptable clock skew window
        (pat.paTimestamp.time = currentTime or
         pat.paTimestamp.time = prev[currentTime] or
         pat.paTimestamp.time = next[currentTime])
}

/**
 * Action: Client processes AS-REP.
 * Precondition: Client in ASReqSent state, AS-REP received
 * Postcondition: Client in HasTGT state
 */
pred processASReply[cs: ClientSession, asRep: ASReply, t: Time] {
    -- Preconditions
    cs.state = CS_ASReqSent
    asRep in Network.inTransit
    asRep.clientPrincipal = cs.principal

    -- Decrypt reply with client's key
    canDecrypt[asRep.encPart, cs.longTermKey]

    -- Verify nonce matches and extract session key
    some encPart: ASRepEncPart |
        asRep.encPart.plaintext = encPart and
        encPart.nonce = cs.pendingNonce and
        -- State transition with proper type access
        cs.state' = CS_HasTGT and
        cs.tgt' = asRep.ticket and
        cs.tgtSessionKey' = encPart.sessionKey and
        cs.pendingNonce' = none

    -- Network effect
    Network.inTransit' = Network.inTransit - asRep
}

/**
 * Action: Client sends TGS-REQ.
 * Precondition: Client has TGT
 * Postcondition: Client in TGSReqSent state
 */
pred sendTGSRequest[cs: ClientSession, tgsReq: TGSRequest, targetService: Principal, t: Time] {
    -- Preconditions
    cs.state = CS_HasTGT
    some cs.tgt
    some cs.tgtSessionKey
    targetService != KRBTGT

    tgsReq.serverPrincipal = targetService
    tgsReq.targetRealm = cs.realm
    tgsReq.timestamp.time = t

    -- Create authenticator encrypted with TGT session key
    some pa: TGSPreAuthData, auth: Authenticator |
        tgsReq.padata = pa and
        pa.tgt = cs.tgt and
        pa.authenticator.encryptionKey = cs.tgtSessionKey and
        pa.authenticator.plaintext = auth and
        auth.clientPrincipal = cs.principal and
        auth.ctime.time = t and
        auth not in cs.usedAuthenticators

    -- State transition
    cs.state' = CS_TGSReqSent
    cs.targetService' = targetService
    cs.pendingNonce' = tgsReq.reqNonce

    -- Update authenticator cache
    cs.usedAuthenticators' = cs.usedAuthenticators + tgsReq.padata.authenticator.plaintext

    -- Network effect
    Network.inTransit' = Network.inTransit + tgsReq
    Network.history' = Network.history + tgsReq
}

/**
 * Action: KDC processes TGS-REQ and sends TGS-REP.
 */
pred kdcProcessTGSRequest[tgsReq: TGSRequest, tgsRep: TGSReply, t: Time] {
    -- Preconditions
    tgsReq in Network.inTransit

    -- Verify TGT
    let tgt = tgsReq.padata.tgt |
        tgt in KDCState.issuedTickets and
        ticketValidAt[tgt, t]

    -- Decrypt and verify authenticator
    let authEnc = tgsReq.padata.authenticator,
        tgt = tgsReq.padata.tgt |
        canDecrypt[authEnc, tgt.encPart.plaintext.sessionKey]

    -- Generate service ticket
    some st: ServiceTicket, sk: SessionKey, tep: TicketEncPart |
        tgsRep.ticket = st and
        st.serverPrincipal = tgsReq.serverPrincipal and
        tep.clientPrincipal = tgsReq.padata.tgt.encPart.plaintext.clientPrincipal and
        tep.sessionKey = sk and
        tep.authTime = t and
        tep.endTime = tgsReq.till and
        st.encPart.plaintext = tep and
        st.encPart.encryptionKey = (KDCState.keys)[tgsReq.serverPrincipal]

    -- Encrypt reply with TGT session key
    some encPart: TGSRepEncPart |
        tgsRep.encPart.plaintext = encPart and
        tgsRep.encPart.encryptionKey = tgsReq.padata.tgt.encPart.plaintext.sessionKey and
        encPart.nonce = tgsReq.reqNonce

    tgsRep.clientPrincipal = tgsReq.padata.tgt.encPart.plaintext.clientPrincipal
    tgsRep.receiver = tgsRep.clientPrincipal
    tgsRep.timestamp.time = t

    -- Effects
    KDCState.issuedTickets' = KDCState.issuedTickets + tgsRep.ticket
    Network.inTransit' = Network.inTransit - tgsReq + tgsRep
    Network.history' = Network.history + tgsRep
}

/**
 * Action: Client processes TGS-REP.
 */
pred processTGSReply[cs: ClientSession, tgsRep: TGSReply, t: Time] {
    -- Preconditions
    cs.state = CS_TGSReqSent
    tgsRep in Network.inTransit
    tgsRep.clientPrincipal = cs.principal

    -- Decrypt with TGT session key
    canDecrypt[tgsRep.encPart, cs.tgtSessionKey]

    -- Verify nonce and extract session key
    some encPart: TGSRepEncPart |
        tgsRep.encPart.plaintext = encPart and
        encPart.nonce = cs.pendingNonce and
        -- State transition with proper type access
        cs.state' = CS_HasServiceTicket and
        cs.serviceTicket' = tgsRep.ticket and
        cs.serviceSessionKey' = encPart.sessionKey and
        cs.pendingNonce' = none

    -- Network effect
    Network.inTransit' = Network.inTransit - tgsRep
}

/**
 * Action: Client sends AP-REQ to service.
 */
pred sendAPRequest[cs: ClientSession, apReq: APRequest, t: Time] {
    -- Preconditions
    cs.state = CS_HasServiceTicket
    some cs.serviceTicket
    some cs.serviceSessionKey

    apReq.ticket = cs.serviceTicket
    apReq.receiver = cs.targetService
    apReq.timestamp.time = t

    -- Create authenticator with service session key
    some auth: Authenticator |
        apReq.authenticator.encryptionKey = cs.serviceSessionKey and
        apReq.authenticator.plaintext = auth and
        auth.clientPrincipal = cs.principal and
        auth.ctime.time = t and
        auth not in cs.usedAuthenticators

    -- State transition
    cs.state' = CS_APReqSent
    cs.usedAuthenticators' = cs.usedAuthenticators + apReq.authenticator.plaintext

    -- Network effect
    Network.inTransit' = Network.inTransit + apReq
    Network.history' = Network.history + apReq
}

/**
 * Action: Service processes AP-REQ.
 */
pred serviceProcessAPRequest[ss: ServiceSession, apReq: APRequest, apRep: APReply, t: Time] {
    -- Preconditions
    apReq in Network.inTransit
    apReq.receiver = ss.principal

    -- Decrypt ticket with service's key
    canDecrypt[apReq.ticket.encPart, ss.longTermKey]

    -- Verify ticket is valid
    ticketValidAt[apReq.ticket, t]

    -- Get session key from ticket
    let tep = apReq.ticket.encPart.plaintext,
        sk = tep.sessionKey |
        -- Decrypt authenticator
        canDecrypt[apReq.authenticator, sk] and
        -- Verify authenticator is fresh (not replay)
        let auth = apReq.authenticator.plaintext |
            auth not in ss.authenticatorCache

    -- Get the ticket's encrypted part as TicketEncPart for session key access
    let ticketPlaintext = apReq.ticket.encPart.plaintext & TicketEncPart,
        authPlaintext = apReq.authenticator.plaintext & Authenticator |

        -- If mutual auth requested, send AP-REP
        (apReq.mutualRequired = True implies
            some encPart: APRepEncPart |
                apRep.encPart.plaintext = encPart and
                apRep.encPart.encryptionKey = ticketPlaintext.sessionKey and
                encPart.ctime = authPlaintext.ctime) and

        -- Effects
        ss.authenticatorCache' = ss.authenticatorCache + authPlaintext and
        ss.state' = SS_Authenticated and

        -- Network effects: add AP-REP only if mutual auth requested
        (apReq.mutualRequired = True implies
            Network.inTransit' = Network.inTransit - apReq + apRep
        else
            Network.inTransit' = Network.inTransit - apReq) and
        Network.history' = Network.history + apRep
}

/**
 * Action: Client processes AP-REP (mutual authentication).
 */
pred processAPReply[cs: ClientSession, apRep: APReply, t: Time] {
    -- Preconditions
    cs.state = CS_APReqSent
    apRep in Network.inTransit

    -- Decrypt with service session key
    canDecrypt[apRep.encPart, cs.serviceSessionKey]

    -- Verify ctime matches what we sent
    -- (confirms service knows session key)

    -- State transition
    cs.state' = CS_Authenticated

    -- Network effect
    Network.inTransit' = Network.inTransit - apRep
}

-- =============================================================================
-- PROTOCOL COMPOSITION
-- =============================================================================

/**
 * Full Kerberos authentication flow.
 * Composes AS, TGS, and AP exchanges.
 */
pred kerberosAuthFlow[cs: ClientSession, ss: ServiceSession] {
    -- Initial state
    cs.state = CS_Initial
    ss.state = SS_Ready
    no cs.tgt
    no cs.serviceTicket

    -- Eventually reaches authenticated state
    eventually (cs.state = CS_Authenticated and ss.state = SS_Authenticated)
}

-- =============================================================================
-- RUN COMMANDS
-- =============================================================================

/**
 * Visualize AS exchange.
 */
run ShowASExchange {
    some asReq: ASRequest, asRep: ASReply |
        asReq.padata != none and
        asRep.ticket in TGT
} for 4 but 2 Time

/**
 * Visualize TGS exchange.
 */
run ShowTGSExchange {
    some tgsReq: TGSRequest, tgsRep: TGSReply |
        tgsRep.ticket in ServiceTicket
} for 5 but 3 Time

/**
 * Visualize AP exchange.
 */
run ShowAPExchange {
    some apReq: APRequest, apRep: APReply |
        apReq.mutualRequired = True
} for 4 but 2 Time

/**
 * Visualize complete protocol flow.
 */
run ShowFullFlow {
    some cs: ClientSession, ss: ServiceSession |
        eventually cs.state = CS_Authenticated
} for 6 but 4 Time
