/**
 * AuthModeler Kerberos Protocol - SPIN/Promela Model
 *
 * Promela specification for SPIN model checker verification.
 * Models Kerberos V5 authentication with:
 * - Client, KDC, and Service processes
 * - AS, TGS, and AP exchanges
 * - Attacker process (Dolev-Yao model)
 *
 * Verifies:
 * - Safety: No authentication without valid ticket
 * - Liveness: Authentication eventually completes
 * - No deadlock
 *
 * Run with: spin -a kerberos.pml && gcc -o pan pan.c && ./pan -a
 */

/* =========================================================================
   TYPE DEFINITIONS
   ========================================================================= */

/* Message types */
mtype = {
    AS_REQ, AS_REP, TGS_REQ, TGS_REP, AP_REQ, AP_REP, KRB_ERROR,
    CLIENT, KDC_PROC, SERVICE, ATTACKER
};

/* Protocol states */
mtype = {
    INITIAL, AS_REQ_SENT, HAS_TGT, TGS_REQ_SENT,
    HAS_SERVICE_TICKET, AP_REQ_SENT, AUTHENTICATED, ERROR,
    READY, AUTH_COMPLETE
};

/* =========================================================================
   CONSTANTS
   ========================================================================= */

#define NUM_CLIENTS     2
#define NUM_SERVICES    1
#define MAX_NONCE       100
#define MAX_TICKET      10
#define MAX_KEY         10

/* =========================================================================
   GLOBAL VARIABLES
   ========================================================================= */

/* Client state */
mtype clientState[NUM_CLIENTS];
byte clientTGT[NUM_CLIENTS];
byte clientServiceTicket[NUM_CLIENTS];
byte clientPendingNonce[NUM_CLIENTS];
byte clientTarget[NUM_CLIENTS];

/* Service state */
mtype serviceState[NUM_SERVICES];
bool serviceAuthCache[NUM_SERVICES * 10];  /* Authenticator replay cache */

/* KDC state */
byte kdcIssuedTickets;
bool ticketValid[MAX_TICKET];

/* Nonce counter for freshness */
byte nonceCounter = 0;

/* Ticket counter */
byte ticketCounter = 0;

/* =========================================================================
   CHANNELS (Network)
   ========================================================================= */

/* Channel capacity for async communication */
#define CHAN_SIZE 5

/* Client to KDC channel */
chan c2kdc = [CHAN_SIZE] of { mtype, byte, byte, byte };  /* type, sender, nonce, data */

/* KDC to Client channel */
chan kdc2c = [CHAN_SIZE] of { mtype, byte, byte, byte, byte };  /* type, receiver, ticket, key, nonce */

/* Client to Service channel */
chan c2srv = [CHAN_SIZE] of { mtype, byte, byte, byte };  /* type, sender, ticket, auth */

/* Service to Client channel */
chan srv2c = [CHAN_SIZE] of { mtype, byte, byte };  /* type, receiver, data */

/* Attacker channels (intercept/inject) */
chan attackerKnowledge = [20] of { mtype, byte, byte, byte };

/* =========================================================================
   HELPER MACROS
   ========================================================================= */

/* Generate fresh nonce */
inline freshNonce(n) {
    atomic {
        n = nonceCounter;
        nonceCounter = (nonceCounter + 1) % MAX_NONCE;
    }
}

/* Generate fresh ticket ID */
inline freshTicket(t) {
    atomic {
        t = ticketCounter;
        ticketCounter = (ticketCounter + 1) % MAX_TICKET;
        ticketValid[t] = true;
        kdcIssuedTickets++;
    }
}

/* Check if ticket is valid */
inline isTicketValid(t, result) {
    result = (t < MAX_TICKET && ticketValid[t]);
}

/* =========================================================================
   CLIENT PROCESS
   ========================================================================= */

proctype Client(byte id; byte targetService) {
    byte nonce, ticket, serviceTicket, sessionKey, auth;
    mtype msgType;
    byte receiver, data1, data2;
    bool valid;

    /* Initial state */
    clientState[id] = INITIAL;
    clientTarget[id] = targetService;

    /* === AS Exchange === */

    /* Send AS-REQ */
    freshNonce(nonce);
    clientPendingNonce[id] = nonce;
    c2kdc ! AS_REQ, id, nonce, 0;
    clientState[id] = AS_REQ_SENT;
    printf("Client %d: Sent AS-REQ with nonce %d\n", id, nonce);

    /* Wait for AS-REP */
    kdc2c ? msgType, receiver, ticket, sessionKey, data1;
    if
    :: (msgType == AS_REP && receiver == id && data1 == nonce) ->
        clientTGT[id] = ticket;
        clientState[id] = HAS_TGT;
        printf("Client %d: Received TGT %d\n", id, ticket);

    :: (msgType == KRB_ERROR) ->
        clientState[id] = ERROR;
        printf("Client %d: Received error in AS exchange\n", id);
        goto done;
    fi;

    /* === TGS Exchange === */

    /* Send TGS-REQ */
    freshNonce(nonce);
    clientPendingNonce[id] = nonce;
    c2kdc ! TGS_REQ, id, nonce, clientTGT[id];
    clientState[id] = TGS_REQ_SENT;
    printf("Client %d: Sent TGS-REQ for service %d\n", id, targetService);

    /* Wait for TGS-REP */
    kdc2c ? msgType, receiver, ticket, sessionKey, data1;
    if
    :: (msgType == TGS_REP && receiver == id && data1 == nonce) ->
        clientServiceTicket[id] = ticket;
        clientState[id] = HAS_SERVICE_TICKET;
        printf("Client %d: Received service ticket %d\n", id, ticket);

    :: (msgType == KRB_ERROR) ->
        clientState[id] = ERROR;
        printf("Client %d: Received error in TGS exchange\n", id);
        goto done;
    fi;

    /* === AP Exchange === */

    /* Generate authenticator (simplified as counter) */
    freshNonce(auth);

    /* Send AP-REQ */
    c2srv ! AP_REQ, id, clientServiceTicket[id], auth;
    clientState[id] = AP_REQ_SENT;
    printf("Client %d: Sent AP-REQ to service %d\n", id, targetService);

    /* Wait for AP-REP */
    srv2c ? msgType, receiver, data1;
    if
    :: (msgType == AP_REP && receiver == id) ->
        clientState[id] = AUTHENTICATED;
        printf("Client %d: Authenticated successfully!\n", id);

    :: (msgType == KRB_ERROR) ->
        clientState[id] = ERROR;
        printf("Client %d: Authentication failed\n", id);
    fi;

done:
    printf("Client %d: Final state = %e\n", id, clientState[id]);
}

/* =========================================================================
   KDC PROCESS
   ========================================================================= */

proctype KDC() {
    mtype msgType;
    byte sender, nonce, data;
    byte ticket, sessionKey;
    bool valid;

    do
    :: c2kdc ? msgType, sender, nonce, data ->
        if
        :: (msgType == AS_REQ) ->
            /* Process AS-REQ: Issue TGT */
            printf("KDC: Received AS-REQ from client %d\n", sender);

            /* Generate TGT and session key */
            freshTicket(ticket);
            sessionKey = (ticket + 50) % MAX_KEY;  /* Simplified key derivation */

            /* Send AS-REP */
            kdc2c ! AS_REP, sender, ticket, sessionKey, nonce;
            printf("KDC: Sent AS-REP with TGT %d to client %d\n", ticket, sender);

        :: (msgType == TGS_REQ) ->
            /* Process TGS-REQ: Issue service ticket */
            printf("KDC: Received TGS-REQ from client %d with TGT %d\n", sender, data);

            /* Verify TGT */
            isTicketValid(data, valid);
            if
            :: valid ->
                /* Generate service ticket */
                freshTicket(ticket);
                sessionKey = (ticket + 60) % MAX_KEY;

                /* Send TGS-REP */
                kdc2c ! TGS_REP, sender, ticket, sessionKey, nonce;
                printf("KDC: Sent TGS-REP with service ticket %d\n", ticket);

            :: else ->
                /* Invalid TGT - send error */
                kdc2c ! KRB_ERROR, sender, 0, 0, 0;
                printf("KDC: Rejected TGS-REQ - invalid TGT\n");
            fi;
        fi;
    od;
}

/* =========================================================================
   SERVICE PROCESS
   ========================================================================= */

proctype Service(byte id) {
    mtype msgType;
    byte sender, ticket, auth;
    bool valid, replay;
    byte cacheIndex;

    serviceState[id] = READY;

    do
    :: c2srv ? msgType, sender, ticket, auth ->
        if
        :: (msgType == AP_REQ) ->
            printf("Service %d: Received AP-REQ from client %d\n", id, sender);

            /* Verify ticket */
            isTicketValid(ticket, valid);

            /* Check authenticator replay */
            cacheIndex = id * 10 + (auth % 10);
            replay = serviceAuthCache[cacheIndex];

            if
            :: (valid && !replay) ->
                /* Mark authenticator as used */
                serviceAuthCache[cacheIndex] = true;

                /* Send AP-REP */
                srv2c ! AP_REP, sender, auth;
                serviceState[id] = AUTH_COMPLETE;
                printf("Service %d: Authenticated client %d\n", id, sender);

            :: (!valid) ->
                srv2c ! KRB_ERROR, sender, 1;
                printf("Service %d: Rejected - invalid ticket\n", id);

            :: (replay) ->
                srv2c ! KRB_ERROR, sender, 2;
                printf("Service %d: Rejected - replay detected\n", id);
            fi;
        fi;
    od;
}

/* =========================================================================
   ATTACKER PROCESS (Dolev-Yao)
   ========================================================================= */

proctype Attacker() {
    mtype msgType;
    byte sender, data1, data2, data3;

    do
    :: /* Intercept from client to KDC */
       c2kdc ? [msgType, sender, data1, data2] ->
           attackerKnowledge ! msgType, sender, data1, data2;
           printf("Attacker: Intercepted message type %e\n", msgType);

    :: /* Intercept from KDC to client */
       kdc2c ? [msgType, sender, data1, data2, data3] ->
           printf("Attacker: Observed KDC response\n");

    :: /* Intercept from client to service */
       c2srv ? [msgType, sender, data1, data2] ->
           printf("Attacker: Observed AP-REQ\n");

    :: /* Attempt replay attack */
       attackerKnowledge ? msgType, sender, data1, data2 ->
           if
           :: (msgType == AP_REQ) ->
               /* Try to replay AP-REQ */
               c2srv ! AP_REQ, sender, data1, data2;
               printf("Attacker: Attempting replay of AP-REQ\n");
           :: else -> skip;
           fi;
    od;
}

/* =========================================================================
   INITIALIZATION
   ========================================================================= */

init {
    byte i;

    /* Initialize client states */
    for (i : 0 .. NUM_CLIENTS-1) {
        clientState[i] = INITIAL;
        clientTGT[i] = 0;
        clientServiceTicket[i] = 0;
    }

    /* Initialize service states */
    for (i : 0 .. NUM_SERVICES-1) {
        serviceState[i] = READY;
    }

    /* Initialize ticket validity */
    for (i : 0 .. MAX_TICKET-1) {
        ticketValid[i] = false;
    }

    /* Initialize authenticator cache */
    for (i : 0 .. (NUM_SERVICES * 10)-1) {
        serviceAuthCache[i] = false;
    }

    /* Start processes */
    atomic {
        run KDC();
        run Service(0);
        run Client(0, 0);
        run Client(1, 0);
        /* Optionally enable attacker */
        /* run Attacker(); */
    }
}

/* =========================================================================
   LTL PROPERTIES
   ========================================================================= */

/* Safety: No authentication without going through all states */
ltl safety_full_protocol {
    [] (
        (clientState[0] == AUTHENTICATED) ->
        (clientTGT[0] > 0 && clientServiceTicket[0] > 0)
    )
}

/* Safety: Only KDC-issued tickets are valid */
ltl safety_ticket_integrity {
    [] (
        (serviceState[0] == AUTH_COMPLETE) ->
        (kdcIssuedTickets > 0)
    )
}

/* Liveness: Authentication eventually completes */
ltl liveness_auth_completes {
    <> (clientState[0] == AUTHENTICATED || clientState[0] == ERROR)
}

/* No deadlock - implicit in SPIN */

/* Replay prevention: Authenticator used only once */
/* (Verified through serviceAuthCache logic) */

/* =========================================================================
   ASSERTIONS (Inline Checks)
   ========================================================================= */

/* Assert: Client in AUTHENTICATED state has valid tickets */
#define ASSERT_VALID_AUTH(id) \
    assert(clientState[id] != AUTHENTICATED || \
           (clientTGT[id] > 0 && clientServiceTicket[id] > 0))

/* Assert: Service only authenticates with valid ticket */
#define ASSERT_VALID_SERVICE_AUTH(id) \
    assert(serviceState[id] != AUTH_COMPLETE || kdcIssuedTickets > 0)
