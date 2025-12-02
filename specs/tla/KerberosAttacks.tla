---------------------------- MODULE KerberosAttacks ----------------------------
(*
 * AuthModeler Kerberos Attack Scenarios
 *
 * TLA+ specification of Kerberos attacks for security research and detection.
 * Each attack includes:
 * - Preconditions (what attacker needs)
 * - Attack state machine (how attack progresses)
 * - Detection indicators (observable patterns)
 * - Mitigations (defensive configurations)
 *
 * IMPORTANT: Properties that SHOULD FAIL document known vulnerabilities.
 * This is intentional - we use model checking to confirm attacks work
 * as expected, enabling detection and mitigation development.
 *
 * References:
 * - https://attack.mitre.org/techniques/T1558/003/ (Kerberoasting)
 * - https://attack.mitre.org/techniques/T1558/004/ (AS-REP Roasting)
 *)

EXTENDS Kerberos, TLC

(* =========================================================================
   ATTACKER MODEL
   ========================================================================= *)

CONSTANTS
    Attacker        \* The adversary principal

VARIABLES
    \* Attacker knowledge
    attackerKnowledge,      \* Set of known items (tickets, keys, etc.)
    attackerCrackedKeys,    \* Set of cracked service keys

    \* Attack tracking
    tgsRequestsForSPNs,     \* Count of TGS-REQ for service accounts per client
    asReqWithoutPreAuth     \* AS-REQ sent without pre-authentication

\* Extended variable tuple
attackVars == <<attackerKnowledge, attackerCrackedKeys, tgsRequestsForSPNs, asReqWithoutPreAuth>>

allVars == <<vars, attackVars>>

(* =========================================================================
   KNOWLEDGE TYPES
   ========================================================================= *)

\* Types of knowledge items
KnowledgeTypes == {"Ticket", "SessionKey", "ServiceKey", "Ciphertext", "Principal"}

\* Knowledge item structure
KnowledgeItem == [type: KnowledgeTypes, value: Keys \cup Tickets \cup (Clients \cup Services)]

(* =========================================================================
   ATTACKER INITIAL STATE
   ========================================================================= *)

AttackInit ==
    /\ attackerKnowledge = {}    \* Attacker starts with no knowledge
    /\ attackerCrackedKeys = {}
    /\ tgsRequestsForSPNs = [c \in Clients |-> 0]
    /\ asReqWithoutPreAuth = {}

(* =========================================================================
   KERBEROASTING ATTACK MODEL
   ========================================================================= *)

(*
 * ATTACK DESCRIPTION:
 * Any authenticated domain user can request service tickets (TGS-REQ) for
 * accounts with SPNs. The service ticket is encrypted with the service
 * account's password-derived key. Attacker extracts the ticket and performs
 * offline dictionary/brute-force attack to recover the password.
 *
 * PRECONDITIONS:
 * - Attacker has valid domain credentials (any user) - has TGT
 * - Target service account has an SPN registered
 * - Target has weak/crackable password
 *
 * DETECTION:
 * - Event ID 4769: TGS-REQ for service accounts
 * - Multiple SPN requests from single user
 * - RC4_HMAC encryption type requests (easier to crack)
 *)

\* Precondition: Attacker has TGT (authenticated to domain)
KerberoastingPrecondition(attacker) ==
    /\ attacker \in Clients
    /\ clientState[attacker] \in {"HasTGT", "TGSReqSent", "HasServiceTicket", "APReqSent", "Authenticated"}
    /\ clientTGT[attacker] # NULL

\* Kerberoasting attack step: Request service ticket for SPN target
KerberoastingTGSRequest(attacker, targetService) ==
    /\ KerberoastingPrecondition(attacker)
    /\ targetService \in ServiceAccounts
    /\ clientState[attacker] = "HasTGT"
    /\ clientTGT[attacker] # NULL
    \* Standard TGS-REQ action
    /\ LET nonce == FreshNonce({clientPendingNonce[attacker]})
           auth == FreshAuthenticator(UsedAuthenticators)
           msg == TGSRequestMsg(attacker, targetService, clientTGT[attacker], auth, nonce, currentTime)
       IN /\ network' = network \cup {msg}
          /\ messageHistory' = Append(messageHistory, msg)
          /\ clientState' = [clientState EXCEPT ![attacker] = "TGSReqSent"]
          /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![attacker] = nonce]
          /\ clientTarget' = [clientTarget EXCEPT ![attacker] = targetService]
    \* Track Kerberoasting indicator
    /\ tgsRequestsForSPNs' = [tgsRequestsForSPNs EXCEPT ![attacker] = @ + 1]
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientServiceTicket, clientServiceKey,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   currentTime, ticketDB, serviceAccountInfo, userAccountInfo,
                   attackerKnowledge, attackerCrackedKeys, asReqWithoutPreAuth>>

\* Attacker obtains service ticket (normal TGS-REP processing)
KerberoastingObtainTicket(attacker) ==
    /\ clientState[attacker] = "TGSReqSent"
    /\ clientTarget[attacker] \in ServiceAccounts
    /\ \E msg \in network :
        /\ msg.type = "TGS_REP"
        /\ msg.receiver = attacker
        /\ msg.nonce = clientPendingNonce[attacker]
        /\ clientState' = [clientState EXCEPT ![attacker] = "HasServiceTicket"]
        /\ clientServiceTicket' = [clientServiceTicket EXCEPT ![attacker] = msg.ticket]
        /\ clientServiceKey' = [clientServiceKey EXCEPT ![attacker] = msg.sessionKey]
        /\ clientPendingNonce' = [clientPendingNonce EXCEPT ![attacker] = NULL]
        /\ network' = network \ {msg}
        \* Attacker adds ticket to knowledge for offline cracking
        /\ attackerKnowledge' = attackerKnowledge \cup {[type |-> "Ticket", value |-> msg.ticket]}
    /\ UNCHANGED <<clientTGT, clientTGTKey, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   messageHistory, currentTime, ticketDB, serviceAccountInfo, userAccountInfo,
                   attackerCrackedKeys, tgsRequestsForSPNs, asReqWithoutPreAuth>>

\* Offline password cracking (models successful crack of weak password)
KerberoastingCrackPassword(attacker, targetService) ==
    /\ targetService \in ServiceAccounts
    /\ HasWeakPassword(targetService)
    \* Attacker has the service ticket
    /\ [type |-> "Ticket", value |-> clientServiceTicket[attacker]] \in attackerKnowledge
    /\ ticketDB[clientServiceTicket[attacker]].serverPrincipal = targetService
    \* Crack the service key
    /\ attackerCrackedKeys' = attackerCrackedKeys \cup {targetService}
    /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientPendingNonce, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   network, messageHistory, currentTime, ticketDB, serviceAccountInfo, userAccountInfo,
                   attackerKnowledge, tgsRequestsForSPNs, asReqWithoutPreAuth>>

(* =========================================================================
   AS-REP ROASTING ATTACK MODEL
   ========================================================================= *)

(*
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
 *)

\* AS-REP Roasting: Send AS-REQ without pre-authentication for vulnerable account
ASREPRoastingRequest(victim) ==
    /\ victim \in Clients
    /\ IsASREPRoastable(victim)
    \* Send AS-REQ without proper pre-auth timestamp (simplified model)
    /\ LET nonce == FreshNonce({})
           msg == ASRequestMsg(victim, nonce, currentTime)
       IN /\ network' = network \cup {msg}
          /\ messageHistory' = Append(messageHistory, msg)
    \* Track AS-REP Roasting indicator
    /\ asReqWithoutPreAuth' = asReqWithoutPreAuth \cup {victim}
    /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                   clientServiceKey, clientPendingNonce, clientTarget,
                   serviceState, serviceAuthCache,
                   kdcIssuedTickets, kdcPrincipalKeys,
                   currentTime, ticketDB, serviceAccountInfo, userAccountInfo,
                   attackerKnowledge, attackerCrackedKeys, tgsRequestsForSPNs>>

\* KDC responds to AS-REQ for account without pre-auth requirement
\* Modified to allow AS-REP without pre-auth check for vulnerable accounts
KDCProcessASRequestNoPreAuth ==
    \E msg \in network :
        /\ msg.type = "AS_REQ"
        /\ msg.receiver = KDC
        /\ msg.clientPrincipal \in Clients
        /\ IsASREPRoastable(msg.clientPrincipal)
        \* No timestamp validation required for accounts without pre-auth
        /\ LET client == msg.clientPrincipal
               clientKey == kdcPrincipalKeys[client]
               krbtgtKey == kdcPrincipalKeys[KRBTGT]
               ticket == FreshTicket(kdcIssuedTickets)
               sessionKey == FreshKey(UsedKeys)
               endTime == currentTime + 10
               reply == ASReplyMsg(client, ticket, sessionKey, msg.nonce, currentTime)
               ticketRec == TicketRecord(client, KRBTGT, sessionKey, currentTime, endTime, krbtgtKey)
           IN /\ network' = (network \ {msg}) \cup {reply}
              /\ messageHistory' = Append(messageHistory, reply)
              /\ kdcIssuedTickets' = kdcIssuedTickets \cup {ticket}
              /\ ticketDB' = [ticketDB EXCEPT ![ticket] = ticketRec]
        /\ UNCHANGED <<clientState, clientTGT, clientTGTKey, clientServiceTicket,
                       clientServiceKey, clientPendingNonce, clientTarget,
                       serviceState, serviceAuthCache,
                       kdcPrincipalKeys, currentTime, serviceAccountInfo, userAccountInfo,
                       attackerKnowledge, attackerCrackedKeys, tgsRequestsForSPNs, asReqWithoutPreAuth>>

(* =========================================================================
   DETECTION INDICATORS
   ========================================================================= *)

\* Kerberoasting detection: Multiple TGS-REQ for service accounts
KerberoastingDetected(threshold) ==
    \E c \in Clients : tgsRequestsForSPNs[c] > threshold

\* Kerberoasting detection: RC4 encryption requested for service account
KerberoastingRC4Detected ==
    \E s \in ServiceAccounts : UsesRC4Encryption(s)

\* AS-REP Roasting detection: AS-REQ without pre-auth
ASREPRoastingDetected ==
    asReqWithoutPreAuth # {}

\* Bulk AS-REP Roasting detection
ASREPRoastingBulkDetected(threshold) ==
    Cardinality(asReqWithoutPreAuth) > threshold

(* =========================================================================
   MITIGATIONS
   ========================================================================= *)

\* Mitigation: All service accounts have strong passwords
AllServiceAccountsStrongPassword ==
    \A s \in ServiceAccounts : serviceAccountInfo[s].passwordStrength = "Strong"

\* Mitigation: All service accounts use AES encryption
AllServiceAccountsAES ==
    \A s \in ServiceAccounts : serviceAccountInfo[s].encType = "AES256"

\* Mitigation: All users require pre-authentication
AllUsersRequirePreAuth ==
    \A c \in Clients : userAccountInfo[c].preAuthRequired

\* Combined Kerberoasting mitigation
KerberoastingFullyMitigated ==
    AllServiceAccountsStrongPassword \/ AllServiceAccountsAES

\* Combined AS-REP Roasting mitigation
ASREPRoastingFullyMitigated ==
    AllUsersRequirePreAuth

(* =========================================================================
   SECURITY PROPERTIES (Document Vulnerabilities)
   ========================================================================= *)

(*
 * VULNERABILITY PROPERTY: Kerberoasting is possible.
 *
 * This property SHOULD FAIL (find counterexample) to document that:
 * - Any authenticated user can request service tickets
 * - Service tickets can be cracked offline if password is weak
 *
 * A counterexample demonstrates the attack is possible.
 *)
NoServiceKeyCompromise ==
    attackerCrackedKeys = {}

\* This should FAIL for systems with weak service account passwords
THEOREM KerberoastingVulnerability ==
    Spec => []NoServiceKeyCompromise

(*
 * VULNERABILITY PROPERTY: AS-REP Roasting is possible.
 *
 * This property SHOULD FAIL to document that accounts without
 * pre-authentication can be targeted for offline attacks.
 *)
NoASREPRoastingAttempts ==
    asReqWithoutPreAuth = {}

\* This should FAIL for systems with pre-auth disabled accounts
THEOREM ASREPRoastingVulnerability ==
    Spec => []NoASREPRoastingAttempts

(* =========================================================================
   SECURITY PROPERTIES (Properties that SHOULD HOLD)
   ========================================================================= *)

\* Strong passwords resist Kerberoasting
StrongPasswordsResistKerberoasting ==
    AllServiceAccountsStrongPassword => (attackerCrackedKeys = {})

\* Pre-auth prevents AS-REP Roasting
PreAuthPreventsASREPRoasting ==
    AllUsersRequirePreAuth => (asReqWithoutPreAuth = {})

(* =========================================================================
   ATTACK STATE MACHINE
   ========================================================================= *)

AttackNext ==
    \* Normal protocol actions (from Kerberos module)
    \/ \E c \in Clients : SendASRequest(c) /\ UNCHANGED attackVars
    \/ \E c \in Clients : ProcessASReply(c) /\ UNCHANGED attackVars
    \/ \E c \in Clients, s \in Services : SendTGSRequest(c, s) /\ UNCHANGED attackVars
    \/ \E c \in Clients : ProcessTGSReply(c) /\ UNCHANGED attackVars
    \/ \E c \in Clients : SendAPRequest(c) /\ UNCHANGED attackVars
    \/ \E c \in Clients : ProcessAPReply(c) /\ UNCHANGED attackVars
    \/ KDCProcessASRequest /\ UNCHANGED attackVars
    \/ KDCProcessTGSRequest /\ UNCHANGED attackVars
    \/ \E s \in Services : ServiceProcessAPRequest(s) /\ UNCHANGED attackVars
    \/ Tick /\ UNCHANGED attackVars
    \* Attack actions
    \/ \E attacker \in Clients, target \in ServiceAccounts : KerberoastingTGSRequest(attacker, target)
    \/ \E attacker \in Clients : KerberoastingObtainTicket(attacker)
    \/ \E attacker \in Clients, target \in ServiceAccounts : KerberoastingCrackPassword(attacker, target)
    \/ \E victim \in Clients : ASREPRoastingRequest(victim)
    \/ KDCProcessASRequestNoPreAuth

AttackSpec == (Init /\ AttackInit) /\ [][AttackNext]_allVars

(* =========================================================================
   MODEL CHECKING CONFIGURATIONS
   ========================================================================= *)

\* Configuration for checking Kerberoasting vulnerability
\* Expected result: FAILS (counterexample shows attack)
KerberoastingCheck ==
    /\ ServiceAccounts # {}
    /\ \E s \in ServiceAccounts : HasWeakPassword(s)
    /\ NoServiceKeyCompromise

\* Configuration for checking AS-REP Roasting vulnerability
\* Expected result: FAILS (counterexample shows attack)
ASREPRoastingCheck ==
    /\ PreAuthDisabled # {}
    /\ NoASREPRoastingAttempts

\* Configuration for verifying mitigations work
\* Expected result: PASSES
MitigationVerification ==
    /\ KerberoastingFullyMitigated => (attackerCrackedKeys = {})
    /\ ASREPRoastingFullyMitigated => (asReqWithoutPreAuth = {})

=============================================================================
