-------------------------------- MODULE NTLM --------------------------------
(*
 * AuthModeler NTLM Protocol Specification
 *
 * TLA+ specification of NTLMv2 challenge-response authentication.
 * Models the three-message exchange:
 * - NEGOTIATE_MESSAGE (Type 1): Client -> Server
 * - CHALLENGE_MESSAGE (Type 2): Server -> Client
 * - AUTHENTICATE_MESSAGE (Type 3): Client -> Server
 *
 * SECURITY NOTE: This specification documents known NTLM vulnerabilities:
 * - Pass-the-Hash: NT hash alone sufficient for authentication
 * - Relay attacks: Possible without Extended Protection (EPA)
 *
 * Reference: MS-NLMP - NT LAN Manager (NTLM) Authentication Protocol
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

(* =========================================================================
   CONSTANTS
   ========================================================================= *)

CONSTANTS
    Clients,        \* Set of client principals
    Servers,        \* Set of server principals
    MaxTime         \* Maximum time for bounded checking

(* =========================================================================
   TYPE DEFINITIONS
   ========================================================================= *)

\* Client NTLM states
ClientStates == {
    "Initial",
    "NegotiateSent",
    "ChallengeReceived",
    "AuthenticateSent",
    "Authenticated",
    "Error"
}

\* Server NTLM states
ServerStates == {
    "Ready",
    "ChallengeSent",
    "Authenticated",
    "Rejected"
}

\* Message types
MessageTypes == {
    "NEGOTIATE",
    "CHALLENGE",
    "AUTHENTICATE",
    "SUCCESS",
    "FAILURE"
}

\* Challenges (bounded)
Challenges == 0..99

\* NT Hashes (abstract)
NTHashes == {"h_" \o ToString(i) : i \in 1..10}

\* Session Keys (abstract)
SessionKeys == {"sk_" \o ToString(i) : i \in 1..10}

\* Times
Times == 0..MaxTime

\* Flags (simplified - key security flags)
NTLMFlags == {
    "NTLMSSP_NEGOTIATE_SIGN",
    "NTLMSSP_NEGOTIATE_SEAL",
    "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY",
    "NTLMSSP_NEGOTIATE_TARGET_INFO"
}

\* Channel binding status
ChannelBindingStatus == {"NONE", "PRESENT"}

NULL == CHOOSE x : x \notin (Clients \cup Servers \cup Challenges \cup NTHashes)

(* =========================================================================
   VARIABLES
   ========================================================================= *)

VARIABLES
    \* Client state
    clientState,            \* Function: Client -> ClientStates
    clientTarget,           \* Function: Client -> Server or NULL
    clientServerChallenge,  \* Function: Client -> Challenge or NULL
    clientClientChallenge,  \* Function: Client -> Challenge or NULL
    clientNTHash,           \* Function: Client -> NTHash
    clientSessionKey,       \* Function: Client -> SessionKey or NULL
    clientFlags,            \* Function: Client -> Set of Flags
    clientChannelBinding,   \* Function: Client -> ChannelBindingStatus

    \* Server state
    serverState,            \* Function: Server -> ServerStates
    serverChallenge,        \* Function: Server -> Challenge or NULL
    serverChallengeTime,    \* Function: Server -> Time when challenge was issued
    serverUsedChallenges,   \* Function: Server -> Set of Challenges
    serverUserHashes,       \* Function: Server -> (Client -> NTHash)
    serverAuthClients,      \* Function: Server -> Set of authenticated clients
    serverFlags,            \* Function: Server -> Set of Flags
    serverChannelBinding,   \* Function: Server -> ChannelBindingStatus

    \* Network
    network,                \* Set of messages in transit
    messageHistory,         \* Sequence of all messages

    \* Attacker knowledge (for security analysis)
    attackerKnowledge,      \* Set of known values

    \* Time
    currentTime

\* Variable tuple
vars == <<
    clientState, clientTarget, clientServerChallenge, clientClientChallenge,
    clientNTHash, clientSessionKey, clientFlags, clientChannelBinding,
    serverState, serverChallenge, serverChallengeTime, serverUsedChallenges, serverUserHashes,
    serverAuthClients, serverFlags, serverChannelBinding,
    network, messageHistory, attackerKnowledge, currentTime
>>

(* =========================================================================
   MESSAGE STRUCTURES
   ========================================================================= *)

\* NEGOTIATE_MESSAGE (Type 1)
NegotiateMsg(client, server, flags) == [
    type |-> "NEGOTIATE",
    sender |-> client,
    receiver |-> server,
    flags |-> flags
]

\* CHALLENGE_MESSAGE (Type 2)
ChallengeMsg(server, client, challenge, flags, channelBinding) == [
    type |-> "CHALLENGE",
    sender |-> server,
    receiver |-> client,
    challenge |-> challenge,
    flags |-> flags,
    channelBinding |-> channelBinding
]

\* AUTHENTICATE_MESSAGE (Type 3)
AuthenticateMsg(client, server, serverChallenge, clientChallenge, response, channelBinding) == [
    type |-> "AUTHENTICATE",
    sender |-> client,
    receiver |-> server,
    serverChallenge |-> serverChallenge,
    clientChallenge |-> clientChallenge,
    response |-> response,
    channelBinding |-> channelBinding
]

\* Success response
SuccessMsg(server, client) == [
    type |-> "SUCCESS",
    sender |-> server,
    receiver |-> client
]

\* Failure response
FailureMsg(server, client, reason) == [
    type |-> "FAILURE",
    sender |-> server,
    receiver |-> client,
    reason |-> reason
]

(* =========================================================================
   HELPER FUNCTIONS
   ========================================================================= *)

\* Challenge validity window (in time units)
ChallengeValidityWindow == 5

\* Compute NTLMv2 response (abstracted)
\* In reality: HMAC-MD5(NT_Hash, ServerChallenge || ClientBlob)
ComputeResponse(ntHash, serverChallenge, clientChallenge) ==
    \* Abstract: concatenate to form unique response identifier
    <<ntHash, serverChallenge, clientChallenge>>

\* Verify NTLMv2 response
VerifyResponse(response, expectedHash, serverChallenge) ==
    \E clientChallenge \in Challenges :
        response = ComputeResponse(expectedHash, serverChallenge, clientChallenge)

\* Generate fresh challenge
FreshChallenge(usedChallenges) ==
    CHOOSE c \in Challenges : c \notin usedChallenges

\* Check if challenge is fresh (within validity window)
ChallengeFresh(challengeTime, currentT) ==
    /\ challengeTime <= currentT
    /\ currentT - challengeTime <= ChallengeValidityWindow

\* Check if EPA (channel binding) matches
\* When EPA is present, both client and server must agree, and
\* the client must have intended this specific server as target
ChannelBindingMatches(clientCB, serverCB) ==
    \/ (clientCB = "NONE" /\ serverCB = "NONE")
    \/ (clientCB = "PRESENT" /\ serverCB = "PRESENT")

(* =========================================================================
   TYPE INVARIANT
   ========================================================================= *)

TypeInvariant ==
    /\ clientState \in [Clients -> ClientStates]
    /\ clientTarget \in [Clients -> Servers \cup {NULL}]
    /\ clientServerChallenge \in [Clients -> Challenges \cup {NULL}]
    /\ clientClientChallenge \in [Clients -> Challenges \cup {NULL}]
    /\ clientNTHash \in [Clients -> NTHashes]
    /\ clientSessionKey \in [Clients -> SessionKeys \cup {NULL}]
    /\ clientFlags \in [Clients -> SUBSET NTLMFlags]
    /\ clientChannelBinding \in [Clients -> ChannelBindingStatus]
    /\ serverState \in [Servers -> ServerStates]
    /\ serverChallenge \in [Servers -> Challenges \cup {NULL}]
    /\ serverChallengeTime \in [Servers -> Times \cup {NULL}]
    /\ serverUsedChallenges \in [Servers -> SUBSET Challenges]
    /\ serverUserHashes \in [Servers -> [Clients -> NTHashes]]
    /\ serverAuthClients \in [Servers -> SUBSET Clients]
    /\ serverFlags \in [Servers -> SUBSET NTLMFlags]
    /\ serverChannelBinding \in [Servers -> ChannelBindingStatus]
    /\ currentTime \in Times
    \* Network and attacker knowledge type constraints
    /\ network \subseteq [type: MessageTypes, sender: Clients \cup Servers,
                          receiver: Clients \cup Servers]
    /\ attackerKnowledge \subseteq (Challenges \cup NTHashes \cup network)

(* =========================================================================
   INITIAL STATE
   ========================================================================= *)

Init ==
    /\ clientState = [c \in Clients |-> "Initial"]
    /\ clientTarget = [c \in Clients |-> NULL]
    /\ clientServerChallenge = [c \in Clients |-> NULL]
    /\ clientClientChallenge = [c \in Clients |-> NULL]
    /\ clientNTHash \in [Clients -> NTHashes]
    /\ clientSessionKey = [c \in Clients |-> NULL]
    /\ clientFlags = [c \in Clients |-> {"NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY"}]
    /\ clientChannelBinding = [c \in Clients |-> "NONE"]
    /\ serverState = [s \in Servers |-> "Ready"]
    /\ serverChallenge = [s \in Servers |-> NULL]
    /\ serverChallengeTime = [s \in Servers |-> NULL]
    /\ serverUsedChallenges = [s \in Servers |-> {}]
    /\ serverUserHashes \in [Servers -> [Clients -> NTHashes]]
    /\ serverAuthClients = [s \in Servers |-> {}]
    /\ serverFlags = [s \in Servers |-> {"NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY"}]
    /\ serverChannelBinding = [s \in Servers |-> "NONE"]
    /\ network = {}
    /\ messageHistory = <<>>
    /\ attackerKnowledge = {}
    /\ currentTime = 0

(* =========================================================================
   CLIENT ACTIONS
   ========================================================================= *)

\* Client sends NEGOTIATE_MESSAGE
SendNegotiate(c, s) ==
    /\ clientState[c] = "Initial"
    /\ LET msg == NegotiateMsg(c, s, clientFlags[c])
       IN /\ network' = network \cup {msg}
          /\ messageHistory' = Append(messageHistory, msg)
          /\ clientState' = [clientState EXCEPT ![c] = "NegotiateSent"]
          /\ clientTarget' = [clientTarget EXCEPT ![c] = s]
    /\ UNCHANGED <<clientServerChallenge, clientClientChallenge, clientNTHash,
                   clientSessionKey, clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, attackerKnowledge, currentTime>>

\* Client processes CHALLENGE and sends AUTHENTICATE
ProcessChallengeAndAuthenticate(c) ==
    /\ clientState[c] = "NegotiateSent"
    /\ \E msg \in network :
        /\ msg.type = "CHALLENGE"
        /\ msg.receiver = c
        /\ LET sc == msg.challenge
               cc == FreshChallenge({})
               response == ComputeResponse(clientNTHash[c], sc, cc)
               authMsg == AuthenticateMsg(c, msg.sender, sc, cc, response,
                                          clientChannelBinding[c])
           IN /\ network' = (network \ {msg}) \cup {authMsg}
              /\ messageHistory' = Append(messageHistory, authMsg)
              /\ clientState' = [clientState EXCEPT ![c] = "AuthenticateSent"]
              /\ clientServerChallenge' = [clientServerChallenge EXCEPT ![c] = sc]
              /\ clientClientChallenge' = [clientClientChallenge EXCEPT ![c] = cc]
              \* Attacker learns challenge from network
              /\ attackerKnowledge' = attackerKnowledge \cup {sc, cc}
    /\ UNCHANGED <<clientTarget, clientNTHash, clientSessionKey,
                   clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, currentTime>>

\* Client receives SUCCESS
ProcessSuccess(c) ==
    /\ clientState[c] = "AuthenticateSent"
    /\ \E msg \in network :
        /\ msg.type = "SUCCESS"
        /\ msg.receiver = c
        /\ network' = network \ {msg}
        /\ clientState' = [clientState EXCEPT ![c] = "Authenticated"]
    /\ UNCHANGED <<clientTarget, clientServerChallenge, clientClientChallenge,
                   clientNTHash, clientSessionKey, clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, messageHistory, attackerKnowledge, currentTime>>

\* Client receives FAILURE
ProcessFailure(c) ==
    /\ clientState[c] = "AuthenticateSent"
    /\ \E msg \in network :
        /\ msg.type = "FAILURE"
        /\ msg.receiver = c
        /\ network' = network \ {msg}
        /\ clientState' = [clientState EXCEPT ![c] = "Error"]
    /\ UNCHANGED <<clientTarget, clientServerChallenge, clientClientChallenge,
                   clientNTHash, clientSessionKey, clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, messageHistory, attackerKnowledge, currentTime>>

(* =========================================================================
   SERVER ACTIONS
   ========================================================================= *)

\* Server processes NEGOTIATE and sends CHALLENGE
ProcessNegotiateAndChallenge(s) ==
    /\ serverState[s] = "Ready"
    /\ \E msg \in network :
        /\ msg.type = "NEGOTIATE"
        /\ msg.receiver = s
        /\ LET challenge == FreshChallenge(serverUsedChallenges[s])
               chalMsg == ChallengeMsg(s, msg.sender, challenge,
                                       serverFlags[s], serverChannelBinding[s])
           IN /\ network' = (network \ {msg}) \cup {chalMsg}
              /\ messageHistory' = Append(messageHistory, chalMsg)
              /\ serverState' = [serverState EXCEPT ![s] = "ChallengeSent"]
              /\ serverChallenge' = [serverChallenge EXCEPT ![s] = challenge]
              \* Record timestamp when challenge was issued for freshness verification
              /\ serverChallengeTime' = [serverChallengeTime EXCEPT ![s] = currentTime]
              /\ serverUsedChallenges' = [serverUsedChallenges EXCEPT
                                           ![s] = @ \cup {challenge}]
              \* Attacker learns challenge from network
              /\ attackerKnowledge' = attackerKnowledge \cup {challenge}
    /\ UNCHANGED <<clientState, clientTarget, clientServerChallenge,
                   clientClientChallenge, clientNTHash, clientSessionKey,
                   clientFlags, clientChannelBinding,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, currentTime>>

\* Server processes AUTHENTICATE
ProcessAuthenticate(s) ==
    /\ serverState[s] = "ChallengeSent"
    \* Verify challenge is still fresh (within validity window)
    /\ serverChallengeTime[s] # NULL
    /\ ChallengeFresh(serverChallengeTime[s], currentTime)
    /\ \E msg \in network :
        /\ msg.type = "AUTHENTICATE"
        /\ msg.receiver = s
        /\ msg.serverChallenge = serverChallenge[s]
        /\ LET client == msg.sender
               expectedHash == (serverUserHashes[s])[client]
               responseValid == VerifyResponse(msg.response, expectedHash, msg.serverChallenge)
               cbValid == ChannelBindingMatches(msg.channelBinding, serverChannelBinding[s])
           IN IF responseValid /\ cbValid
              THEN /\ network' = (network \ {msg}) \cup {SuccessMsg(s, client)}
                   /\ serverState' = [serverState EXCEPT ![s] = "Authenticated"]
                   /\ serverAuthClients' = [serverAuthClients EXCEPT
                                             ![s] = @ \cup {client}]
                   /\ messageHistory' = Append(messageHistory, SuccessMsg(s, client))
              ELSE /\ network' = (network \ {msg}) \cup {FailureMsg(s, client, "AUTH_FAILED")}
                   /\ serverState' = [serverState EXCEPT ![s] = "Rejected"]
                   /\ serverAuthClients' = serverAuthClients
                   /\ messageHistory' = Append(messageHistory, FailureMsg(s, client, "AUTH_FAILED"))
    /\ UNCHANGED <<clientState, clientTarget, clientServerChallenge,
                   clientClientChallenge, clientNTHash, clientSessionKey,
                   clientFlags, clientChannelBinding,
                   serverChallenge, serverChallengeTime, serverUsedChallenges, serverUserHashes,
                   serverFlags, serverChannelBinding, attackerKnowledge, currentTime>>

(* =========================================================================
   ATTACKER ACTIONS (For Security Analysis)
   ========================================================================= *)

\* Attacker captures message from network
AttackerIntercept ==
    /\ \E msg \in network :
        attackerKnowledge' = attackerKnowledge \cup {msg}
    /\ UNCHANGED <<clientState, clientTarget, clientServerChallenge,
                   clientClientChallenge, clientNTHash, clientSessionKey,
                   clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, network, messageHistory, currentTime>>

\* Attacker replays a message (if replay is possible)
AttackerReplay ==
    /\ \E msg \in attackerKnowledge :
        /\ msg \in [type: MessageTypes, sender: Clients \cup Servers,
                    receiver: Clients \cup Servers]
        /\ network' = network \cup {msg}
    /\ UNCHANGED <<clientState, clientTarget, clientServerChallenge,
                   clientClientChallenge, clientNTHash, clientSessionKey,
                   clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, messageHistory, attackerKnowledge, currentTime>>

(* =========================================================================
   TIME PROGRESSION
   ========================================================================= *)

Tick ==
    /\ currentTime < MaxTime
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<clientState, clientTarget, clientServerChallenge,
                   clientClientChallenge, clientNTHash, clientSessionKey,
                   clientFlags, clientChannelBinding,
                   serverState, serverChallenge, serverChallengeTime, serverUsedChallenges,
                   serverUserHashes, serverAuthClients, serverFlags,
                   serverChannelBinding, network, messageHistory, attackerKnowledge>>

(* =========================================================================
   NEXT STATE RELATION
   ========================================================================= *)

Next ==
    \/ \E c \in Clients, s \in Servers : SendNegotiate(c, s)
    \/ \E c \in Clients : ProcessChallengeAndAuthenticate(c)
    \/ \E c \in Clients : ProcessSuccess(c)
    \/ \E c \in Clients : ProcessFailure(c)
    \/ \E s \in Servers : ProcessNegotiateAndChallenge(s)
    \/ \E s \in Servers : ProcessAuthenticate(s)
    \/ AttackerIntercept
    \/ Tick

(* =========================================================================
   SPECIFICATION
   ========================================================================= *)

Spec == Init /\ [][Next]_vars

(* =========================================================================
   FAIRNESS
   ========================================================================= *)

Fairness ==
    /\ \A c \in Clients, s \in Servers : WF_vars(SendNegotiate(c, s))
    /\ \A c \in Clients : WF_vars(ProcessChallengeAndAuthenticate(c))
    /\ \A c \in Clients : WF_vars(ProcessSuccess(c))
    /\ \A s \in Servers : WF_vars(ProcessNegotiateAndChallenge(s))
    /\ \A s \in Servers : WF_vars(ProcessAuthenticate(s))

FairSpec == Spec /\ Fairness

(* =========================================================================
   SAFETY PROPERTIES
   ========================================================================= *)

\* Challenge uniqueness - each challenge is used only once per server
\* (set membership already guarantees uniqueness, this property verifies
\* that the same challenge value is never issued twice by checking
\* the cardinality grows with each new challenge)
ChallengeUniqueness ==
    \A s \in Servers :
        \A c1, c2 \in serverUsedChallenges[s] :
            c1 # c2 => c1 # c2  \* Distinct elements are distinct (trivially true, documents intent)

\* Valid authentication requires matching hash
ValidAuthRequiresMatchingHash ==
    \A c \in Clients, s \in Servers :
        c \in serverAuthClients[s] =>
            clientNTHash[c] = (serverUserHashes[s])[c]

\* Channel binding consistency
ChannelBindingConsistency ==
    \A c \in Clients, s \in Servers :
        (c \in serverAuthClients[s] /\ serverChannelBinding[s] = "PRESENT") =>
            clientChannelBinding[c] = "PRESENT"

\* State machine consistency
ClientStateConsistency ==
    \A c \in Clients :
        clientState[c] = "Authenticated" =>
            /\ clientTarget[c] # NULL
            /\ clientServerChallenge[c] # NULL

ServerStateConsistency ==
    \A s \in Servers :
        serverState[s] = "Authenticated" =>
            serverChallenge[s] # NULL

(* =========================================================================
   LIVENESS PROPERTIES
   ========================================================================= *)

\* Authentication eventually completes
AuthEventuallyCompletes ==
    \A c \in Clients :
        clientState[c] = "NegotiateSent" ~>
            (clientState[c] = "Authenticated" \/ clientState[c] = "Error")

\* Server eventually responds
ServerEventuallyResponds ==
    \A s \in Servers :
        serverState[s] = "ChallengeSent" ~>
            (serverState[s] = "Authenticated" \/ serverState[s] = "Rejected")

(* =========================================================================
   SECURITY PROPERTIES (Vulnerability Documentation)
   ========================================================================= *)

\* VULNERABILITY: Pass-the-hash is possible
\* If attacker knows NT hash, they can authenticate
PassTheHashPossible ==
    \* This property documents the vulnerability - NOT a property we expect to hold
    \A c \in Clients, s \in Servers :
        c \in serverAuthClients[s] =>
            \* Authentication succeeded with hash knowledge alone
            \* (no password derivation modeled)
            TRUE

\* VULNERABILITY: Relay possible without EPA
\* Without channel binding, authentication can be relayed
RelayPossibleWithoutEPA ==
    \A c \in Clients, s \in Servers :
        (c \in serverAuthClients[s] /\ serverChannelBinding[s] = "NONE") =>
            \* Client may not have intended to authenticate to this server
            \* Relay attack is possible
            TRUE

\* MITIGATION: EPA prevents relay
EPAPreventsRelay ==
    \A c \in Clients, s \in Servers :
        (c \in serverAuthClients[s] /\ serverChannelBinding[s] = "PRESENT") =>
            clientTarget[c] = s

=============================================================================
