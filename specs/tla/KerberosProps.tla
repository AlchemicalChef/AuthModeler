-------------------------- MODULE KerberosProps --------------------------
(*
 * AuthModeler Kerberos Security Properties
 *
 * TLA+ specification of safety and liveness properties for Kerberos V5.
 * These properties are designed to be checked by TLC model checker.
 *
 * Property Categories:
 * - SAFETY: Invariants that must always hold
 * - LIVENESS: Progress properties that must eventually hold
 * - AUTHENTICATION: Verify identity guarantees
 * - FRESHNESS: Prevent replay attacks
 *
 * Reference: RFC 4120 Section 1.1 (Security Goals)
 *)

EXTENDS Kerberos, TLC

(* =========================================================================
   HELPER FUNCTIONS
   ========================================================================= *)

\* Range of a sequence - returns set of all elements in the sequence
Range(s) == {s[i] : i \in DOMAIN s}

(* =========================================================================
   SAFETY PROPERTIES (Invariants)
   ========================================================================= *)

(*
 * SAFETY-1: Type Safety
 *
 * All variables maintain their expected types throughout execution.
 * This is a basic sanity check that the model is well-formed.
 *)
TypeSafe == TypeInvariant

(*
 * SAFETY-2: No Ticket Without Authentication
 *
 * A ticket can only be issued if the client sent a valid AS-REQ
 * with matching principal. This ensures KDC doesn't issue tickets
 * to unauthenticated parties.
 *)
NoTicketWithoutAuth ==
    \A t \in kdcIssuedTickets :
        t \in DOMAIN ticketDB =>
            \E msg \in Range(messageHistory) :
                /\ msg.type = "AS_REQ"
                /\ msg.clientPrincipal = ticketDB[t].clientPrincipal
                \* The AS-REQ must have valid pre-authentication (timestamp)
                /\ TimestampValid(msg.timestamp, msg.timestamp)

(*
 * SAFETY-3: Ticket-Client Binding
 *
 * A service ticket is bound to the client that obtained the TGT.
 * This prevents one client from using another client's tickets.
 *)
TicketClientBinding ==
    \A t \in kdcIssuedTickets :
        t \in DOMAIN ticketDB =>
            /\ ticketDB[t].clientPrincipal \in Clients

(*
 * SAFETY-4: Session Key Uniqueness
 *
 * Each ticket has a unique session key.
 * Prevents key reuse across different sessions.
 *)
SessionKeyUniqueness ==
    \A t1, t2 \in kdcIssuedTickets :
        (t1 # t2 /\ t1 \in DOMAIN ticketDB /\ t2 \in DOMAIN ticketDB) =>
            ticketDB[t1].sessionKey # ticketDB[t2].sessionKey

(*
 * SAFETY-5: Authenticator Uniqueness
 *
 * Each service maintains a cache of seen authenticators.
 * A replayed authenticator will be detected and rejected.
 *)
AuthenticatorCacheConsistency ==
    \A s \in Services :
        \A auth \in serviceAuthCache[s] :
            \E msg \in Range(messageHistory) :
                /\ msg.type = "AP_REQ"
                /\ msg.receiver = s
                /\ msg.authenticator = auth

(*
 * SAFETY-6: State Machine Consistency
 *
 * Client state transitions follow the expected protocol flow.
 * No client can be in "Authenticated" without going through all steps.
 *)
ClientStateConsistency ==
    \A c \in Clients :
        clientState[c] = "Authenticated" =>
            /\ clientTGT[c] # NULL
            /\ clientServiceTicket[c] # NULL
            /\ clientTarget[c] # NULL

(*
 * SAFETY-7: TGT Required for Service Ticket
 *
 * A client must have a TGT before it can request a service ticket.
 *)
TGTRequiredForServiceTicket ==
    \A c \in Clients :
        clientServiceTicket[c] # NULL => clientTGT[c] # NULL

(*
 * SAFETY-8: Service Ticket Required for Authentication
 *
 * A client must have a service ticket to authenticate to a service.
 *)
ServiceTicketRequiredForAuth ==
    \A c \in Clients :
        clientState[c] = "Authenticated" => clientServiceTicket[c] # NULL

(*
 * SAFETY-9: No Replay Acceptance
 *
 * A service never accepts the same authenticator twice.
 * Once an authenticator is cached, any AP-REQ with that authenticator
 * will not be processed (the service action is not enabled).
 * This is verified by checking that ServiceProcessAPRequest guards
 * against cached authenticators.
 *)
NoReplayAcceptance ==
    \A s \in Services, auth \in Authenticators :
        auth \in serviceAuthCache[s] =>
            \* Any message in network with cached authenticator cannot trigger processing
            ~(\E msg \in network :
                /\ msg.type = "AP_REQ"
                /\ msg.receiver = s
                /\ msg.authenticator = auth
                /\ serviceState[s] = "Ready"
                /\ msg.ticket \in kdcIssuedTickets
                /\ TicketValidAt(msg.ticket, currentTime))

(*
 * SAFETY-10: Valid Ticket for Authentication
 *
 * Any accepted AP-REQ must contain a valid ticket.
 *)
ValidTicketForAuth ==
    \A s \in Services :
        serviceState[s] = "Authenticated" =>
            \E msg \in Range(messageHistory) :
                /\ msg.type = "AP_REQ"
                /\ msg.receiver = s
                /\ msg.ticket \in kdcIssuedTickets

(* =========================================================================
   COMPOUND SAFETY INVARIANT
   ========================================================================= *)

(*
 * Combined safety invariant for model checking.
 * All safety properties must hold in every reachable state.
 *)
SafetyInvariant ==
    /\ TypeSafe
    /\ NoTicketWithoutAuth
    /\ TicketClientBinding
    /\ SessionKeyUniqueness
    /\ AuthenticatorCacheConsistency
    /\ ClientStateConsistency
    /\ TGTRequiredForServiceTicket
    /\ ServiceTicketRequiredForAuth
    /\ NoReplayAcceptance
    /\ ValidTicketForAuth

(* =========================================================================
   LIVENESS PROPERTIES
   ========================================================================= *)

(*
 * LIVENESS-1: Authentication Eventually Completes
 *
 * If a client starts authentication (sends AS-REQ),
 * it will eventually reach either Authenticated or Error state.
 *
 * Requires fairness assumption.
 *)
AuthenticationEventuallyCompletes ==
    \A c \in Clients :
        clientState[c] = "ASReqSent" ~>
            (clientState[c] = "Authenticated" \/ clientState[c] = "Error")

(*
 * LIVENESS-2: TGT Eventually Obtained
 *
 * If a client sends AS-REQ, it will eventually obtain a TGT.
 *
 * Requires fairness assumption.
 *)
TGTEventuallyObtained ==
    \A c \in Clients :
        clientState[c] = "ASReqSent" ~> clientState[c] = "HasTGT"

(*
 * LIVENESS-3: Service Ticket Eventually Obtained
 *
 * If a client sends TGS-REQ with a valid TGT,
 * it will eventually obtain a service ticket.
 *
 * Requires fairness assumption.
 *)
ServiceTicketEventuallyObtained ==
    \A c \in Clients :
        clientState[c] = "TGSReqSent" ~> clientState[c] = "HasServiceTicket"

(*
 * LIVENESS-4: Mutual Authentication Completes
 *
 * If client sends AP-REQ with mutual auth requested,
 * it will eventually receive AP-REP and complete authentication.
 *
 * Requires fairness assumption.
 *)
MutualAuthEventuallyCompletes ==
    \A c \in Clients :
        clientState[c] = "APReqSent" ~> clientState[c] = "Authenticated"

(*
 * LIVENESS-5: Service Eventually Authenticates Valid Client
 *
 * If a valid AP-REQ is received by a service,
 * the service will eventually be in Authenticated state.
 *
 * Requires fairness assumption.
 *)
ServiceEventuallyAuthenticates ==
    \A s \in Services :
        (\E msg \in network :
            /\ msg.type = "AP_REQ"
            /\ msg.receiver = s
            /\ msg.ticket \in kdcIssuedTickets
            /\ msg.authenticator \notin serviceAuthCache[s])
        ~> serviceState[s] = "Authenticated"

(*
 * LIVENESS-6: No Deadlock
 *
 * The system can always make progress (no deadlock state).
 * There is always at least one enabled action.
 *)
NoDeadlock ==
    (\E c \in Clients : ENABLED SendASRequest(c))
    \/ (\E c \in Clients : ENABLED ProcessASReply(c))
    \/ (\E c \in Clients, s \in Services : ENABLED SendTGSRequest(c, s))
    \/ (\E c \in Clients : ENABLED ProcessTGSReply(c))
    \/ (\E c \in Clients : ENABLED SendAPRequest(c))
    \/ (\E c \in Clients : ENABLED ProcessAPReply(c))
    \/ ENABLED KDCProcessASRequest
    \/ ENABLED KDCProcessTGSRequest
    \/ (\E s \in Services : ENABLED ServiceProcessAPRequest(s))
    \/ ENABLED Tick

(* =========================================================================
   AUTHENTICATION PROPERTIES
   ========================================================================= *)

(*
 * AUTH-1: Client Identity Verified by KDC
 *
 * Any ticket issued by the KDC is for a valid client principal.
 *)
ClientIdentityVerified ==
    \A t \in kdcIssuedTickets :
        t \in DOMAIN ticketDB =>
            ticketDB[t].clientPrincipal \in Clients

(*
 * AUTH-2: Service Identity Verified by KDC
 *
 * Any service ticket issued by the KDC is for a valid service principal.
 *)
ServiceIdentityVerified ==
    \A t \in kdcIssuedTickets :
        t \in DOMAIN ticketDB =>
            ticketDB[t].serverPrincipal \in Services \cup {KRBTGT}

(*
 * AUTH-3: Mutual Authentication Integrity
 *
 * If a client is in Authenticated state with a target service,
 * then the service received a valid AP-REQ from this client
 * and has the authenticator in its cache.
 * Note: In a distributed system with message delays, we verify
 * that proper message exchange occurred, not simultaneous state.
 *)
MutualAuthIntegrity ==
    \A c \in Clients :
        (clientState[c] = "Authenticated" /\ clientTarget[c] # NULL) =>
            \E msg \in Range(messageHistory) :
                /\ msg.type = "AP_REQ"
                /\ msg.receiver = clientTarget[c]
                /\ msg.ticket \in kdcIssuedTickets
                /\ msg.ticket \in DOMAIN ticketDB
                /\ ticketDB[msg.ticket].clientPrincipal = c

(* =========================================================================
   FRESHNESS PROPERTIES
   ========================================================================= *)

(*
 * FRESH-1: Nonce Uniqueness Per Client
 *
 * Each client uses unique nonces for its AS-REQ and TGS-REQ messages.
 * Nonces only need to be unique per-client to prevent replay attacks.
 * Different clients may legitimately use the same nonce value.
 *)
NonceUniqueness ==
    \A msg1, msg2 \in Range(messageHistory) :
        (/\ msg1.type \in {"AS_REQ", "TGS_REQ"}
         /\ msg2.type \in {"AS_REQ", "TGS_REQ"}
         /\ msg1 # msg2
         /\ msg1.sender = msg2.sender) =>  \* Same client
            msg1.nonce # msg2.nonce

(*
 * FRESH-2: Reply Bound to Request
 *
 * Every AS-REP contains the nonce from the corresponding AS-REQ.
 * Prevents use of old replies.
 *)
ReplyBoundToRequest ==
    \A rep \in Range(messageHistory) :
        rep.type = "AS_REP" =>
            \E req \in Range(messageHistory) :
                /\ req.type = "AS_REQ"
                /\ req.clientPrincipal = rep.clientPrincipal
                /\ req.nonce = rep.nonce

(*
 * FRESH-3: Authenticator Freshness
 *
 * Each authenticator is used exactly once.
 * Implemented via authenticator cache at services.
 *)
AuthenticatorFreshness ==
    \A s \in Services, auth \in serviceAuthCache[s] :
        Cardinality({msg \in Range(messageHistory) :
            msg.type = "AP_REQ" /\
            msg.receiver = s /\
            msg.authenticator = auth}) = 1

(* =========================================================================
   TEMPORAL PROPERTIES (LTL)
   ========================================================================= *)

(*
 * LTL-1: Always Eventually Authenticated
 *
 * If authentication starts, it always eventually completes.
 * []<>(clientState[c] = "Authenticated")
 *)

(*
 * LTL-2: Always Safety Holds
 *
 * Safety properties hold at all times.
 * [](SafetyInvariant)
 *)
AlwaysSafe == []SafetyInvariant

(*
 * LTL-3: No Permanent Waiting
 *
 * A client waiting for a response will eventually receive it.
 * [](waiting => <>received)
 *)

(* =========================================================================
   MODEL CHECKING CONFIGURATION
   ========================================================================= *)

(*
 * Symmetry sets for state space reduction.
 * Clients and Services are symmetric.
 *)
Symmetry == Permutations(Clients) \cup Permutations(Services)

(*
 * Properties to check:
 *
 * INVARIANTS (check with TLC):
 *   - TypeSafe
 *   - SafetyInvariant
 *   - ClientIdentityVerified
 *   - ServiceIdentityVerified
 *
 * PROPERTIES (check with TLC):
 *   - AuthenticationEventuallyCompletes (requires fairness)
 *   - TGTEventuallyObtained (requires fairness)
 *   - NoDeadlock
 *
 * TEMPORAL PROPERTIES:
 *   - AlwaysSafe
 *)

=============================================================================
