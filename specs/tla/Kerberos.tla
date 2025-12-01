---------------------------- MODULE Kerberos ----------------------------
(*
 * AuthModeler Kerberos Protocol Specification
 *
 * TLA+ specification of Kerberos V5 authentication protocol.
 * Models the state machine and message exchanges for:
 * - AS Exchange (Authentication Service)
 * - TGS Exchange (Ticket Granting Service)
 * - AP Exchange (Application Protocol)
 *
 * This specification is designed for model checking with TLC.
 *
 * Reference: RFC 4120 - The Kerberos Network Authentication Service (V5)
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

(* =========================================================================
   CONSTANTS
   ========================================================================= *)

CONSTANTS
    Clients,        \* Set of client principals
    Services,       \* Set of service principals
    KDC,           \* The Key Distribution Center
    KRBTGT,        \* Ticket Granting Service principal
    MaxTime        \* Maximum time value for bounded checking

(* =========================================================================
   TYPE DEFINITIONS
   ========================================================================= *)

\* Client protocol states
ClientStates == {
    "Initial",
    "ASReqSent",
    "HasTGT",
    "TGSReqSent",
    "HasServiceTicket",
    "APReqSent",
    "Authenticated",
    "Error"
}

\* Service protocol states
ServiceStates == {"Ready", "Authenticated"}

\* Message types
MessageTypes == {
    "AS_REQ",
    "AS_REP",
    "TGS_REQ",
    "TGS_REP",
    "AP_REQ",
    "AP_REP",
    "KRB_ERROR"
}

\* Nonce type (bounded natural numbers)
Nonces == 0..99

\* Time type (bounded)
Times == 0..MaxTime

\* Key type (abstract identifier)
Keys == {"k_" \o ToString(i) : i \in 1..20}

\* Ticket type (abstract identifier)
Tickets == {"t_" \o ToString(i) : i \in 1..20}

\* Authenticator type (abstract identifier)
Authenticators == {"auth_" \o ToString(i) : i \in 1..20}

(* =========================================================================
   VARIABLES
   ========================================================================= *)

VARIABLES
    \* Client state variables
    clientState,        \* Function: Client -> ClientStates
    clientTGT,          \* Function: Client -> Ticket or NULL
    clientTGTKey,       \* Function: Client -> Key or NULL
    clientServiceTicket,\* Function: Client -> Ticket or NULL
    clientServiceKey,   \* Function: Client -> Key or NULL
    clientPendingNonce, \* Function: Client -> Nonce or NULL
    clientTarget,       \* Function: Client -> Service or NULL

    \* Service state variables
    serviceState,       \* Function: Service -> ServiceStates
    serviceAuthCache,   \* Function: Service -> Set of Authenticators

    \* KDC state variables
    kdcIssuedTickets,   \* Set of issued tickets
    kdcPrincipalKeys,   \* Function: Principal -> Key

    \* Network variables
    network,            \* Set of messages in transit
    messageHistory,     \* Sequence of all messages sent

    \* Time variable
    currentTime,        \* Current system time

    \* Ticket database (maps ticket ID to ticket data)
    ticketDB            \* Function: Ticket -> TicketRecord

\* Variable tuple for TLA+ spec composition
vars == <<
    clientState, clientTGT, clientTGTKey, clientServiceTicket,
    clientServiceKey, clientPendingNonce, clientTarget,
    serviceState, serviceAuthCache,
    kdcIssuedTickets, kdcPrincipalKeys,
    network, messageHistory, currentTime, ticketDB
>>

(* =========================================================================
   TYPE INVARIANTS
   ========================================================================= *)

TypeInvariant ==
    /\ clientState \in [Clients -> ClientStates]
    /\ clientTGT \in [Clients -> Tickets \cup {NULL}]
    /\ clientTGTKey \in [Clients -> Keys \cup {NULL}]
    /\ clientServiceTicket \in [Clients -> Tickets \cup {NULL}]
    /\ clientServiceKey \in [Clients -> Keys \cup {NULL}]
    /\ clientPendingNonce \in [Clients -> Nonces \cup {NULL}]
    /\ clientTarget \in [Clients -> Services \cup {NULL}]
    /\ serviceState \in [Services -> ServiceStates]
    /\ serviceAuthCache \in [Services -> SUBSET Authenticators]
    /\ kdcIssuedTickets \subseteq Tickets
    /\ kdcPrincipalKeys \in [Clients \cup Services \cup {KRBTGT} -> Keys]
    /\ currentTime \in Times
    \* Network and message history type constraints
    /\ network \subseteq [type: MessageTypes, sender: Clients \cup Services \cup {KDC},
                          receiver: Clients \cup Services \cup {KDC}]
    /\ messageHistory \in Seq([type: MessageTypes, sender: Clients \cup Services \cup {KDC},
                               receiver: Clients \cup Services \cup {KDC}])
    \* Ticket database type constraint
    /\ DOMAIN ticketDB \subseteq Tickets

(* =========================================================================
   MESSAGE STRUCTURES
   ========================================================================= *)

\* AS-REQ message structure
ASRequestMsg(client, nonce, timestamp) == [
    type |-> "AS_REQ",
    sender |-> client,
    receiver |-> KDC,
    clientPrincipal |-> client,
    serverPrincipal |-> KRBTGT,
    nonce |-> nonce,
    timestamp |-> timestamp
]

\* AS-REP message structure
ASReplyMsg(client, ticket, sessionKey, nonce, timestamp) == [
    type |-> "AS_REP",
    sender |-> KDC,
    receiver |-> client,
    clientPrincipal |-> client,
    ticket |-> ticket,
    sessionKey |-> sessionKey,
    nonce |-> nonce,
    timestamp |-> timestamp
]

\* TGS-REQ message structure
TGSRequestMsg(client, service, tgt, authenticator, nonce, timestamp) == [
    type |-> "TGS_REQ",
    sender |-> client,
    receiver |-> KDC,
    serverPrincipal |-> service,
    tgt |-> tgt,
    authenticator |-> authenticator,
    nonce |-> nonce,
    timestamp |-> timestamp
]

\* TGS-REP message structure
TGSReplyMsg(client, ticket, sessionKey, nonce, timestamp) == [
    type |-> "TGS_REP",
    sender |-> KDC,
    receiver |-> client,
    ticket |-> ticket,
    sessionKey |-> sessionKey,
    nonce |-> nonce,
    timestamp |-> timestamp
]

\* AP-REQ message structure
APRequestMsg(client, service, ticket, authenticator, timestamp) == [
    type |-> "AP_REQ",
    sender |-> client,
    receiver |-> service,
    ticket |-> ticket,
    authenticator |-> authenticator,
    timestamp |-> timestamp,
    mutualAuth |-> TRUE
]

\* AP-REP message structure
APReplyMsg(service, client, ctime, timestamp) == [
    type |-> "AP_REP",
    sender |-> service,
    receiver |-> client,
    ctime |-> ctime,
    timestamp |-> timestamp
]

\* Error message structure
ErrorMsg(sender, receiver, code, timestamp) == [
    type |-> "KRB_ERROR",
    sender |-> sender,
    receiver |-> receiver,
    errorCode |-> code,
    timestamp |-> timestamp
]

(* =========================================================================
   TICKET RECORD STRUCTURE
   ========================================================================= *)

\* Ticket record stored in ticketDB
\* Includes encryption key to model which principal can decrypt
TicketRecord(client, server, sessionKey, authTime, endTime, encryptionKey) == [
    clientPrincipal |-> client,
    serverPrincipal |-> server,
    sessionKey |-> sessionKey,
    authTime |-> authTime,
    endTime |-> endTime,
    encryptionKey |-> encryptionKey  \* Key used to encrypt this ticket
]

(* =========================================================================
   HELPER PREDICATES
   ========================================================================= *)

\* Clock skew tolerance (in time units)
ClockSkew == 2

\* Check if ticket is valid at given time
TicketValidAt(ticket, time) ==
    /\ ticket \in DOMAIN ticketDB
    /\ ticketDB[ticket].authTime <= time
    /\ time < ticketDB[ticket].endTime

\* Check if timestamp is within acceptable clock skew
TimestampValid(timestamp, referenceTime) ==
    /\ timestamp >= referenceTime - ClockSkew
    /\ timestamp <= referenceTime + ClockSkew

\* Check if authenticator timestamp is fresh (within clock skew)
AuthenticatorFresh(authTimestamp, currentT) ==
    TimestampValid(authTimestamp, currentT)

\* Generate a fresh nonce (simplified - just pick unused one)
FreshNonce(usedNonces) ==
    CHOOSE n \in Nonces : n \notin usedNonces

\* Generate a fresh key
FreshKey(usedKeys) ==
    CHOOSE k \in Keys : k \notin usedKeys

\* Generate a fresh ticket ID
FreshTicket(issuedTickets) ==
    CHOOSE t \in Tickets : t \notin issuedTickets

\* Generate a fresh authenticator ID
FreshAuthenticator(usedAuths) ==
    CHOOSE a \in Authenticators : a \notin usedAuths

\* Get all used keys in the system
UsedKeys ==
    UNION {
        {kdcPrincipalKeys[p] : p \in DOMAIN kdcPrincipalKeys},
        {clientTGTKey[c] : c \in Clients},
        {clientServiceKey[c] : c \in Clients},
        {ticketDB[t].sessionKey : t \in DOMAIN ticketDB}
    }

\* Get all used authenticators
UsedAuthenticators ==
    UNION {serviceAuthCache[s] : s \in Services}

\* NULL constant - represents absence of value
\* Using a distinct string constant to avoid CHOOSE issues with empty sets
NULL == "NULL_VALUE"

\* Safety check: NULL must not collide with any principal/key/ticket/nonce values
ASSUME NULL \notin (Clients \cup Services \cup Keys \cup Tickets \cup Nonces)

(* =========================================================================
   INITIAL STATE
   ========================================================================= *)

Init ==
    /\ clientState = [c \in Clients |-> "Initial"]
    /\ clientTGT = [c \in Clients |-> NULL]
    /\ clientTGTKey = [c \in Clients |-> NULL]
    /\ clientServiceTicket = [c \in Clients |-> NULL]
    /\ clientServiceKey = [c \in Clients |-> NULL]
    /\ clientPendingNonce = [c \in Clients |-> NULL]
    /\ clientTarget = [c \in Clients |-> NULL]
    /\ serviceState = [s \in Services |-> "Ready"]
    /\ serviceAuthCache = [s \in Services |-> {}]
    /\ kdcIssuedTickets = {}
    /\ kdcPrincipalKeys \in [Clients \cup Services \cup {KRBTGT} -> Keys]
    /\ network = {}
    /\ messageHistory = <<>>
    /\ currentTime = 0
    /\ ticketDB = [t \in {} |-> NULL]

(* =========================================================================
   CLIENT ACTIONS
   ========================================================================= *)

\* Client sends AS-REQ to KDC
SendASRequest(c) ==
    /\ clientState[c] = "Initial"
    /\ LET nonce == FreshNonce({})
           msg == ASRequestMsg(c, nonce, currentTime)
       IN /\ network' = network \cup {msg}
          /\ messageHistory' = Append(messageHistory, msg)
          /\ clientState' = [clientState EXCEPT ![c] = "ASReqSent"]
          /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![c] = nonce]
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   currentTime, ticketDB>>

\* Client processes AS-REP
ProcessASReply(c) ==
    /\ clientState[c] = "ASReqSent"
    /\ \E msg \in network :
        /\ msg.type = "AS_REP"
        /\ msg.receiver = c
        /\ msg.nonce = clientPendingNonce[c]
        /\ clientState' = [clientState EXCEPT ![c] = "HasTGT"]
        /\ clientTGT' = [clientTGT EXCEPT ![c] = msg.ticket]
        /\ clientTGTKey' = [clientTGTKey EXCEPT ![c] = msg.sessionKey]
        /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![c] = NULL]
        /\ network' = network \ {msg}
    /\ UNCHANGED <<clientServiceTicket, clientServiceKey, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   messageHistory, currentTime, ticketDB>>

\* Client sends TGS-REQ for service ticket
SendTGSRequest(c, s) ==
    /\ clientState[c] = "HasTGT"
    /\ clientTGT[c] # NULL
    /\ s \in Services
    /\ LET nonce == FreshNonce({clientPendingNonce[c]})
           auth == FreshAuthenticator(UsedAuthenticators)
           msg == TGSRequestMsg(c, s, clientTGT[c], auth, nonce, currentTime)
       IN /\ network' = network \cup {msg}
          /\ messageHistory' = Append(messageHistory, msg)
          /\ clientState' = [clientState EXCEPT ![c] = "TGSReqSent"]
          /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![c] = nonce]
          /\ clientTarget' = [clientTarget EXCEPT ![c] = s]
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientServiceTicket, clientServiceKey,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   currentTime, ticketDB>>

\* Client processes TGS-REP
ProcessTGSReply(c) ==
    /\ clientState[c] = "TGSReqSent"
    /\ \E msg \in network :
        /\ msg.type = "TGS_REP"
        /\ msg.receiver = c
        /\ msg.nonce = clientPendingNonce[c]
        /\ clientState' = [clientState EXCEPT ![c] = "HasServiceTicket"]
        /\ clientServiceTicket' = [clientServiceTicket EXCEPT ![c] = msg.ticket]
        /\ clientServiceKey' = [clientServiceKey EXCEPT ![c] = msg.sessionKey]
        /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![c] = NULL]
        /\ network' = network \ {msg}
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   messageHistory, currentTime, ticketDB>>

\* Client sends AP-REQ to service
SendAPRequest(c) ==
    /\ clientState[c] = "HasServiceTicket"
    /\ clientServiceTicket[c] # NULL
    /\ clientTarget[c] # NULL
    /\ LET s == clientTarget[c]
           auth == FreshAuthenticator(UsedAuthenticators)
           msg == APRequestMsg(c, s, clientServiceTicket[c], auth, currentTime)
       IN /\ network' = network \cup {msg}
          /\ messageHistory' = Append(messageHistory, msg)
          /\ clientState' = [clientState EXCEPT ![c] = "APReqSent"]
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientPendingNonce, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   currentTime, ticketDB>>

\* Client processes AP-REP (mutual authentication)
ProcessAPReply(c) ==
    /\ clientState[c] = "APReqSent"
    /\ \E msg \in network :
        /\ msg.type = "AP_REP"
        /\ msg.receiver = c
        /\ clientState' = [clientState EXCEPT ![c] = "Authenticated"]
        /\ network' = network \ {msg}
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientPendingNonce, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   messageHistory, currentTime, ticketDB>>

(* =========================================================================
   KDC ACTIONS
   ========================================================================= *)

\* KDC processes AS-REQ and sends AS-REP
\* Note: Pre-authentication is modeled by timestamp validation
KDCProcessASRequest ==
    \E msg \in network :
        /\ msg.type = "AS_REQ"
        /\ msg.receiver = KDC
        /\ msg.clientPrincipal \in Clients
        \* Pre-authentication: verify timestamp is within acceptable skew
        /\ TimestampValid(msg.timestamp, currentTime)
        /\ LET client == msg.clientPrincipal
               clientKey == kdcPrincipalKeys[client]
               krbtgtKey == kdcPrincipalKeys[KRBTGT]
               ticket == FreshTicket(kdcIssuedTickets)
               sessionKey == FreshKey(UsedKeys)
               endTime == currentTime + 10  \* Ticket valid for 10 time units
               reply == ASReplyMsg(client, ticket, sessionKey, msg.nonce, currentTime)
               \* TGT is encrypted with KRBTGT's key
               ticketRec == TicketRecord(client, KRBTGT, sessionKey, currentTime, endTime, krbtgtKey)
           IN /\ network' = (network \ {msg}) \cup {reply}
              /\ messageHistory' = Append(messageHistory, reply)
              /\ kdcIssuedTickets' = kdcIssuedTickets \cup {ticket}
              /\ ticketDB' = [ticketDB EXCEPT ![ticket] = ticketRec]
        /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                       clientServiceKey, clientPendingNonce, clientTarget,
                       serviceState, serviceAuthCache,
                       kdcPrincipalKeys, currentTime>>

\* KDC processes TGS-REQ and sends TGS-REP
KDCProcessTGSRequest ==
    \E msg \in network :
        /\ msg.type = "TGS_REQ"
        /\ msg.receiver = KDC
        /\ msg.tgt \in kdcIssuedTickets
        /\ TicketValidAt(msg.tgt, currentTime)
        \* Verify authenticator timestamp is fresh
        /\ AuthenticatorFresh(msg.timestamp, currentTime)
        /\ msg.serverPrincipal \in Services
        /\ LET client == ticketDB[msg.tgt].clientPrincipal
               service == msg.serverPrincipal
               serviceKey == kdcPrincipalKeys[service]
               ticket == FreshTicket(kdcIssuedTickets)
               sessionKey == FreshKey(UsedKeys)
               endTime == currentTime + 8  \* Service ticket shorter validity
               reply == TGSReplyMsg(client, ticket, sessionKey, msg.nonce, currentTime)
               \* Service ticket is encrypted with service's key
               ticketRec == TicketRecord(client, service, sessionKey, currentTime, endTime, serviceKey)
           IN /\ network' = (network \ {msg}) \cup {reply}
              /\ messageHistory' = Append(messageHistory, reply)
              /\ kdcIssuedTickets' = kdcIssuedTickets \cup {ticket}
              /\ ticketDB' = [ticketDB EXCEPT ![ticket] = ticketRec]
        /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                       clientServiceKey, clientPendingNonce, clientTarget,
                       serviceState, serviceAuthCache,
                       kdcPrincipalKeys, currentTime>>

(* =========================================================================
   SERVICE ACTIONS
   ========================================================================= *)

\* Service processes AP-REQ
ServiceProcessAPRequest(s) ==
    /\ s \in Services
    /\ serviceState[s] = "Ready"
    /\ \E msg \in network :
        /\ msg.type = "AP_REQ"
        /\ msg.receiver = s
        /\ msg.ticket \in kdcIssuedTickets
        /\ TicketValidAt(msg.ticket, currentTime)
        \* Verify ticket is for this service (encryption key binding)
        /\ ticketDB[msg.ticket].serverPrincipal = s
        /\ ticketDB[msg.ticket].encryptionKey = kdcPrincipalKeys[s]
        \* Verify authenticator timestamp is fresh (within clock skew)
        /\ AuthenticatorFresh(msg.timestamp, currentTime)
        \* Replay check - authenticator must not have been seen before
        /\ msg.authenticator \notin serviceAuthCache[s]
        /\ LET reply == APReplyMsg(s, ticketDB[msg.ticket].clientPrincipal,
                                    msg.timestamp, currentTime)
           IN /\ network' = (network \ {msg}) \cup {reply}
              /\ messageHistory' = Append(messageHistory, reply)
              /\ serviceState' = [serviceState EXCEPT ![s] = "Authenticated"]
              \* Cache authenticator to prevent replay
              /\ serviceAuthCache' = [serviceAuthCache EXCEPT
                                       ![s] = @ \cup {msg.authenticator}]
    /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientPendingNonce, clientTarget,
                   kdcIssuedTickets, kdcPrincipalKeys, currentTime, ticketDB>>

(* =========================================================================
   TIME PROGRESSION
   ========================================================================= *)

\* Time advances
Tick ==
    /\ currentTime < MaxTime
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientPendingNonce, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   network, messageHistory, ticketDB>>

(* =========================================================================
   NEXT STATE RELATION
   ========================================================================= *)

Next ==
    \/ \E c \in Clients : SendASRequest(c)
    \/ \E c \in Clients : ProcessASReply(c)
    \/ \E c \in Clients, s \in Services : SendTGSRequest(c, s)
    \/ \E c \in Clients : ProcessTGSReply(c)
    \/ \E c \in Clients : SendAPRequest(c)
    \/ \E c \in Clients : ProcessAPReply(c)
    \/ KDCProcessASRequest
    \/ KDCProcessTGSRequest
    \/ \E s \in Services : ServiceProcessAPRequest(s)
    \/ Tick

(* =========================================================================
   SPECIFICATION
   ========================================================================= *)

Spec == Init /\ [][Next]_vars

(* =========================================================================
   FAIRNESS CONDITIONS
   ========================================================================= *)

\* Weak fairness for all actions (ensures progress)
Fairness ==
    /\ \A c \in Clients : WF_vars(SendASRequest(c))
    /\ \A c \in Clients : WF_vars(ProcessASReply(c))
    /\ \A c \in Clients, s \in Services : WF_vars(SendTGSRequest(c, s))
    /\ \A c \in Clients : WF_vars(ProcessTGSReply(c))
    /\ \A c \in Clients : WF_vars(SendAPRequest(c))
    /\ \A c \in Clients : WF_vars(ProcessAPReply(c))
    /\ WF_vars(KDCProcessASRequest)
    /\ WF_vars(KDCProcessTGSRequest)
    /\ \A s \in Services : WF_vars(ServiceProcessAPRequest(s))

FairSpec == Spec /\ Fairness

=============================================================================
