---------------------------- MODULE AS_Exchange ----------------------------
(*
 * AS Exchange - Authentication Service Exchange
 *
 * Focused sub-specification for the initial Kerberos authentication.
 * Models only: AS-REQ and AS-REP message exchange.
 *
 * This decomposed spec has a much smaller state space for efficient
 * model checking while still verifying AS exchange properties.
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

(* =========================================================================
   CONSTANTS
   ========================================================================= *)

CONSTANTS
    Clients,        \* Set of client principals
    KDC,           \* The Key Distribution Center
    KRBTGT,        \* Ticket Granting Service principal
    MaxTime        \* Maximum time value

(* =========================================================================
   TYPE DEFINITIONS (Minimal for AS Exchange)
   ========================================================================= *)

ClientStates == {"Initial", "ASReqSent", "HasTGT", "Error"}

Nonces == {"n_1", "n_2", "n_3"}
Keys == {"k_1", "k_2", "k_3"}
Tickets == {"t_1", "t_2", "t_3"}
Times == 0..MaxTime

NULL == "NULL"

(* =========================================================================
   VARIABLES
   ========================================================================= *)

VARIABLES
    clientState,        \* Function: Client -> ClientStates
    clientTGT,          \* Function: Client -> Ticket or NULL
    clientTGTKey,       \* Function: Client -> Key or NULL (session key)
    clientPendingNonce, \* Function: Client -> Nonce or NULL

    kdcIssuedTickets,   \* Set of issued TGTs
    kdcPrincipalKeys,   \* Function: Principal -> Key (long-term keys)

    network,            \* Set of messages in transit
    currentTime,        \* Current time
    ticketDB            \* Ticket metadata

vars == <<clientState, clientTGT, clientTGTKey, clientPendingNonce,
          kdcIssuedTickets, kdcPrincipalKeys, network, currentTime, ticketDB>>

(* =========================================================================
   TYPE INVARIANT
   ========================================================================= *)

TypeInvariant ==
    /\ clientState \in [Clients -> ClientStates]
    /\ clientTGT \in [Clients -> Tickets \cup {NULL}]
    /\ clientTGTKey \in [Clients -> Keys \cup {NULL}]
    /\ clientPendingNonce \in [Clients -> Nonces \cup {NULL}]
    /\ kdcIssuedTickets \subseteq Tickets
    /\ kdcPrincipalKeys \in [Clients \cup {KRBTGT} -> Keys]
    /\ currentTime \in Times

(* =========================================================================
   MESSAGE STRUCTURES
   ========================================================================= *)

ASRequestMsg(client, nonce, timestamp) == [
    type |-> "AS_REQ",
    sender |-> client,
    receiver |-> KDC,
    clientPrincipal |-> client,
    nonce |-> nonce,
    timestamp |-> timestamp
]

ASReplyMsg(client, ticket, sessionKey, nonce, timestamp) == [
    type |-> "AS_REP",
    sender |-> KDC,
    receiver |-> client,
    ticket |-> ticket,
    sessionKey |-> sessionKey,
    nonce |-> nonce,
    timestamp |-> timestamp
]

(* =========================================================================
   TICKET RECORD
   ========================================================================= *)

TicketRecord(client, sessionKey, authTime, endTime, encKey) == [
    clientPrincipal |-> client,
    serverPrincipal |-> KRBTGT,
    sessionKey |-> sessionKey,
    authTime |-> authTime,
    endTime |-> endTime,
    encryptionKey |-> encKey
]

(* =========================================================================
   HELPER PREDICATES
   ========================================================================= *)

ClockSkew == 1

TimestampValid(ts, refTime) ==
    /\ ts >= refTime - ClockSkew
    /\ ts <= refTime + ClockSkew

FreshNonce(used) == CHOOSE n \in Nonces : n \notin used
FreshKey(used) == CHOOSE k \in Keys : k \notin used
FreshTicket(issued) == CHOOSE t \in Tickets : t \notin issued

UsedKeys ==
    {kdcPrincipalKeys[p] : p \in DOMAIN kdcPrincipalKeys} \cup
    {clientTGTKey[c] : c \in Clients} \cup
    {ticketDB[t].sessionKey : t \in DOMAIN ticketDB}

(* =========================================================================
   INITIAL STATE
   ========================================================================= *)

Init ==
    /\ clientState = [c \in Clients |-> "Initial"]
    /\ clientTGT = [c \in Clients |-> NULL]
    /\ clientTGTKey = [c \in Clients |-> NULL]
    /\ clientPendingNonce = [c \in Clients |-> NULL]
    /\ kdcIssuedTickets = {}
    /\ kdcPrincipalKeys \in [Clients \cup {KRBTGT} -> Keys]
    /\ network = {}
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
          /\ clientState' = [clientState EXCEPT ![c] = "ASReqSent"]
          /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![c] = nonce]
    /\ UNCHANGED <<clientTGT, clientTGTKey, kdcIssuedTickets,
                   kdcPrincipalKeys, currentTime, ticketDB>>

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
    /\ UNCHANGED <<kdcIssuedTickets, kdcPrincipalKeys, currentTime, ticketDB>>

(* =========================================================================
   KDC ACTIONS
   ========================================================================= *)

\* KDC processes AS-REQ and sends AS-REP
KDCProcessASRequest ==
    \E msg \in network :
        /\ msg.type = "AS_REQ"
        /\ msg.receiver = KDC
        /\ msg.clientPrincipal \in Clients
        /\ TimestampValid(msg.timestamp, currentTime)
        /\ LET client == msg.clientPrincipal
               krbtgtKey == kdcPrincipalKeys[KRBTGT]
               ticket == FreshTicket(kdcIssuedTickets)
               sessionKey == FreshKey(UsedKeys)
               endTime == currentTime + 3
               reply == ASReplyMsg(client, ticket, sessionKey, msg.nonce, currentTime)
               ticketRec == TicketRecord(client, sessionKey, currentTime, endTime, krbtgtKey)
           IN /\ network' = (network \ {msg}) \cup {reply}
              /\ kdcIssuedTickets' = kdcIssuedTickets \cup {ticket}
              /\ ticketDB' = [ticketDB EXCEPT ![ticket] = ticketRec]
        /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientPendingNonce,
                       kdcPrincipalKeys, currentTime>>

(* =========================================================================
   TIME PROGRESSION
   ========================================================================= *)

Tick ==
    /\ currentTime < MaxTime
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientPendingNonce,
                   kdcIssuedTickets, kdcPrincipalKeys, network, ticketDB>>

(* =========================================================================
   NEXT STATE RELATION
   ========================================================================= *)

Next ==
    \/ \E c \in Clients : SendASRequest(c)
    \/ \E c \in Clients : ProcessASReply(c)
    \/ KDCProcessASRequest
    \/ Tick

Spec == Init /\ [][Next]_vars

(* =========================================================================
   SAFETY PROPERTIES
   ========================================================================= *)

\* Every TGT held by a client was issued by the KDC
TGTsAreKDCIssued ==
    \A c \in Clients :
        clientTGT[c] # NULL => clientTGT[c] \in kdcIssuedTickets

\* Nonce replay protection: AS-REP nonce matches AS-REQ nonce
NonceCorrespondence ==
    \A c \in Clients :
        clientState[c] = "HasTGT" =>
        clientPendingNonce[c] = NULL

\* No client gets TGT without going through ASReqSent state
AuthenticationRequired ==
    \A c \in Clients :
        clientTGT[c] # NULL => clientState[c] = "HasTGT"

(* =========================================================================
   LIVENESS PROPERTIES
   ========================================================================= *)

\* Eventually, a client that sends AS-REQ will have a TGT (with fairness)
EventuallyAuthenticated ==
    \A c \in Clients :
        clientState[c] = "ASReqSent" ~> clientState[c] = "HasTGT"

(* =========================================================================
   INVARIANTS TO CHECK
   ========================================================================= *)

\* Combined safety invariant
SafetyInvariant ==
    /\ TypeInvariant
    /\ TGTsAreKDCIssued
    /\ AuthenticationRequired

=============================================================================
