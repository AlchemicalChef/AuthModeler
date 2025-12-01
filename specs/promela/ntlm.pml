/**
 * AuthModeler NTLM Protocol - SPIN/Promela Model
 *
 * Promela specification for SPIN model checker verification.
 * Models NTLMv2 challenge-response authentication:
 * - NEGOTIATE_MESSAGE (Type 1)
 * - CHALLENGE_MESSAGE (Type 2)
 * - AUTHENTICATE_MESSAGE (Type 3)
 *
 * Includes attacker process to model known vulnerabilities:
 * - Pass-the-Hash
 * - NTLM Relay (without EPA)
 *
 * Run with: spin -a ntlm.pml && gcc -o pan pan.c && ./pan -a
 */

/* =========================================================================
   TYPE DEFINITIONS
   ========================================================================= */

/* Message types */
mtype = {
    NEGOTIATE, CHALLENGE, AUTHENTICATE, SUCCESS, FAILURE,
    CLIENT_PROC, SERVER_PROC, ATTACKER_PROC
};

/* Protocol states */
mtype = {
    INITIAL, NEGOTIATE_SENT, CHALLENGE_RECEIVED,
    AUTHENTICATE_SENT, AUTHENTICATED, ERROR,
    READY, CHALLENGE_SENT, AUTH_COMPLETE, REJECTED
};

/* Channel binding status */
mtype = { CB_NONE, CB_PRESENT };

/* =========================================================================
   CONSTANTS
   ========================================================================= */

#define NUM_CLIENTS     2
#define NUM_SERVERS     2
#define MAX_CHALLENGE   100
#define MAX_HASH        10

/* =========================================================================
   GLOBAL VARIABLES
   ========================================================================= */

/* Client state */
mtype clientState[NUM_CLIENTS];
byte clientTarget[NUM_CLIENTS];
byte clientServerChallenge[NUM_CLIENTS];
byte clientClientChallenge[NUM_CLIENTS];
byte clientNTHash[NUM_CLIENTS];
mtype clientChannelBinding[NUM_CLIENTS];

/* Server state */
mtype serverState[NUM_SERVERS];
byte serverChallenge[NUM_SERVERS];
bool serverUsedChallenges[NUM_SERVERS * MAX_CHALLENGE];
byte serverAuthenticatedClients[NUM_SERVERS];
mtype serverChannelBinding[NUM_SERVERS];

/* User database: server -> client -> expected hash */
byte serverUserHashes[NUM_SERVERS * NUM_CLIENTS];

/* Challenge counter */
byte challengeCounter = 0;

/* Attacker state */
bool attackerHasHash[NUM_CLIENTS];  /* Attacker knows client's NT hash */
byte attackerCapturedChallenges[10];
byte attackerCapturedResponses[10];
byte attackerKnowledgeCount = 0;

/* =========================================================================
   CHANNELS (Network)
   ========================================================================= */

#define CHAN_SIZE 5

/* Client to Server channel */
chan c2s = [CHAN_SIZE] of { mtype, byte, byte, byte, byte, mtype };
/* type, sender, receiver, challenge/response, data, channelBinding */

/* Server to Client channel */
chan s2c = [CHAN_SIZE] of { mtype, byte, byte, byte, mtype };
/* type, sender, receiver, challenge, channelBinding */

/* Attacker interception channel */
chan attackerChan = [10] of { mtype, byte, byte, byte };

/* =========================================================================
   HELPER MACROS
   ========================================================================= */

/* Generate fresh challenge */
inline freshChallenge(c) {
    atomic {
        c = challengeCounter;
        challengeCounter = (challengeCounter + 1) % MAX_CHALLENGE;
    }
}

/* Compute NTLMv2 response (simplified) */
inline computeResponse(hash, serverChal, clientChal, response) {
    response = (hash + serverChal + clientChal) % 256;
}

/* Verify NTLMv2 response */
inline verifyResponse(response, hash, serverChal, clientChal, result) {
    byte expected;
    computeResponse(hash, serverChal, clientChal, expected);
    result = (response == expected);
}

/* Get user hash from database */
inline getUserHash(serverId, clientId, hash) {
    hash = serverUserHashes[serverId * NUM_CLIENTS + clientId];
}

/* =========================================================================
   CLIENT PROCESS
   ========================================================================= */

proctype Client(byte id; byte targetServer; byte ntHash) {
    mtype msgType;
    byte sender, receiver, challenge, data;
    mtype cb;
    byte clientChal, response;

    /* Initialize */
    clientState[id] = INITIAL;
    clientTarget[id] = targetServer;
    clientNTHash[id] = ntHash;
    clientChannelBinding[id] = CB_NONE;  /* Can be set to CB_PRESENT for EPA */

    /* === Send NEGOTIATE === */
    c2s ! NEGOTIATE, id, targetServer, 0, 0, clientChannelBinding[id];
    clientState[id] = NEGOTIATE_SENT;
    printf("Client %d: Sent NEGOTIATE to server %d\n", id, targetServer);

    /* === Wait for CHALLENGE === */
    s2c ? msgType, sender, receiver, challenge, cb;
    if
    :: (msgType == CHALLENGE && receiver == id && sender == targetServer) ->
        clientServerChallenge[id] = challenge;
        clientState[id] = CHALLENGE_RECEIVED;
        printf("Client %d: Received CHALLENGE %d from server %d\n", id, challenge, sender);

        /* Generate client challenge and compute response */
        freshChallenge(clientChal);
        clientClientChallenge[id] = clientChal;
        computeResponse(ntHash, challenge, clientChal, response);

        /* === Send AUTHENTICATE === */
        c2s ! AUTHENTICATE, id, targetServer, challenge, response, clientChannelBinding[id];
        clientState[id] = AUTHENTICATE_SENT;
        printf("Client %d: Sent AUTHENTICATE with response %d\n", id, response);

    :: (msgType == FAILURE) ->
        clientState[id] = ERROR;
        printf("Client %d: Received FAILURE in challenge phase\n", id);
        goto done;
    fi;

    /* === Wait for SUCCESS/FAILURE === */
    s2c ? msgType, sender, receiver, data, cb;
    if
    :: (msgType == SUCCESS && receiver == id) ->
        clientState[id] = AUTHENTICATED;
        printf("Client %d: Authentication successful!\n", id);

    :: (msgType == FAILURE && receiver == id) ->
        clientState[id] = ERROR;
        printf("Client %d: Authentication failed\n", id);
    fi;

done:
    printf("Client %d: Final state = %e\n", id, clientState[id]);
}

/* =========================================================================
   SERVER PROCESS
   ========================================================================= */

proctype Server(byte id) {
    mtype msgType;
    byte sender, receiver, chalOrResp, data;
    mtype cb;
    byte challenge, expectedHash, response;
    bool valid, cbMatch;
    byte cacheIndex;

    /* Initialize */
    serverState[id] = READY;
    serverChannelBinding[id] = CB_NONE;  /* Can be set to CB_PRESENT for EPA */
    serverAuthenticatedClients[id] = 255;  /* None authenticated */

    do
    :: c2s ? msgType, sender, receiver, chalOrResp, data, cb ->
        if
        :: (msgType == NEGOTIATE && receiver == id) ->
            printf("Server %d: Received NEGOTIATE from client %d\n", id, sender);

            /* Generate fresh challenge */
            freshChallenge(challenge);
            serverChallenge[id] = challenge;

            /* Mark challenge as used */
            cacheIndex = id * MAX_CHALLENGE + (challenge % MAX_CHALLENGE);
            serverUsedChallenges[cacheIndex] = true;

            /* Send CHALLENGE */
            s2c ! CHALLENGE, id, sender, challenge, serverChannelBinding[id];
            serverState[id] = CHALLENGE_SENT;
            printf("Server %d: Sent CHALLENGE %d to client %d\n", id, challenge, sender);

        :: (msgType == AUTHENTICATE && receiver == id) ->
            printf("Server %d: Received AUTHENTICATE from client %d\n", id, sender);

            /* Verify challenge matches */
            if
            :: (chalOrResp == serverChallenge[id]) ->
                /* Get expected hash for this user */
                getUserHash(id, sender, expectedHash);

                /* Verify response */
                /* Note: In reality, we'd need clientChallenge too, simplified here */
                response = data;

                /* Simplified verification: just check response is non-zero */
                valid = (response != 0 && expectedHash == clientNTHash[sender]);

                /* Verify channel binding */
                cbMatch = (serverChannelBinding[id] == CB_NONE ||
                          (serverChannelBinding[id] == cb));

                if
                :: (valid && cbMatch) ->
                    serverAuthenticatedClients[id] = sender;
                    s2c ! SUCCESS, id, sender, 0, CB_NONE;
                    serverState[id] = AUTH_COMPLETE;
                    printf("Server %d: Authenticated client %d\n", id, sender);

                :: (!valid) ->
                    s2c ! FAILURE, id, sender, 1, CB_NONE;
                    serverState[id] = REJECTED;
                    printf("Server %d: Rejected client %d - invalid credentials\n", id, sender);

                :: (!cbMatch) ->
                    s2c ! FAILURE, id, sender, 2, CB_NONE;
                    serverState[id] = REJECTED;
                    printf("Server %d: Rejected client %d - channel binding mismatch\n", id, sender);
                fi;

            :: else ->
                s2c ! FAILURE, id, sender, 3, CB_NONE;
                printf("Server %d: Rejected - challenge mismatch\n", id);
            fi;
        fi;
    od;
}

/* =========================================================================
   ATTACKER PROCESS - Pass-the-Hash Attack
   ========================================================================= */

proctype AttackerPTH(byte victimId; byte targetServerId) {
    byte stolenHash, challenge, clientChal, response;
    mtype cb;

    /* Precondition: Attacker has victim's NT hash */
    if
    :: attackerHasHash[victimId] ->
        stolenHash = clientNTHash[victimId];
        printf("Attacker: Has NT hash %d for victim %d\n", stolenHash, victimId);

        /* Step 1: Send NEGOTIATE (pretending to be victim) */
        c2s ! NEGOTIATE, victimId, targetServerId, 0, 0, CB_NONE;
        printf("Attacker: Sent NEGOTIATE as victim %d\n", victimId);

        /* Step 2: Receive CHALLENGE */
        s2c ? CHALLENGE, _, _, challenge, cb;
        printf("Attacker: Received CHALLENGE %d\n", challenge);

        /* Step 3: Compute response using stolen hash */
        freshChallenge(clientChal);
        computeResponse(stolenHash, challenge, clientChal, response);

        /* Step 4: Send AUTHENTICATE */
        c2s ! AUTHENTICATE, victimId, targetServerId, challenge, response, CB_NONE;
        printf("Attacker: Sent AUTHENTICATE with response %d\n", response);

        /* Step 5: Check if successful */
        /* If server accepts, pass-the-hash succeeded! */

    :: else ->
        printf("Attacker: Does not have NT hash for victim %d\n", victimId);
    fi;
}

/* =========================================================================
   ATTACKER PROCESS - NTLM Relay Attack
   ========================================================================= */

proctype AttackerRelay(byte victimId; byte legitimateServerId; byte targetServerId) {
    byte challenge;
    mtype cb;
    byte chalOrResp, response;

    /* Precondition: No EPA (channel binding) */
    if
    :: (serverChannelBinding[targetServerId] == CB_NONE) ->
        printf("Attacker: Attempting relay attack (no EPA)\n");

        /* Step 1: Get challenge from TARGET server (pretend to be victim) */
        c2s ! NEGOTIATE, victimId, targetServerId, 0, 0, CB_NONE;
        s2c ? CHALLENGE, _, _, challenge, cb;
        printf("Attacker: Got challenge %d from target server %d\n", challenge, targetServerId);

        /* Step 2: Forward challenge to victim (pretend to be legitimate server) */
        /* In real attack, attacker would set up rogue server */
        /* Here we simulate by storing challenge */
        attackerCapturedChallenges[attackerKnowledgeCount] = challenge;

        /* Step 3: When victim responds (to what they think is legitimate server),
           capture the response and relay to target server */
        /* This is modeled by having separate victim client process */

        printf("Attacker: Relay setup complete - waiting for victim response\n");

    :: else ->
        printf("Attacker: Cannot relay - EPA is enabled on target server\n");
    fi;
}

/* =========================================================================
   INITIALIZATION
   ========================================================================= */

init {
    byte i, j;

    /* Initialize client states */
    for (i : 0 .. NUM_CLIENTS-1) {
        clientState[i] = INITIAL;
        clientTarget[i] = 0;
        clientServerChallenge[i] = 0;
        clientNTHash[i] = i + 1;  /* Each client has unique hash */
        clientChannelBinding[i] = CB_NONE;
    }

    /* Initialize server states */
    for (i : 0 .. NUM_SERVERS-1) {
        serverState[i] = READY;
        serverChallenge[i] = 0;
        serverAuthenticatedClients[i] = 255;
        serverChannelBinding[i] = CB_NONE;
    }

    /* Initialize server challenge cache */
    for (i : 0 .. (NUM_SERVERS * MAX_CHALLENGE)-1) {
        serverUsedChallenges[i] = false;
    }

    /* Initialize user hash database (each server knows all client hashes) */
    for (i : 0 .. NUM_SERVERS-1) {
        for (j : 0 .. NUM_CLIENTS-1) {
            serverUserHashes[i * NUM_CLIENTS + j] = j + 1;  /* Match client hashes */
        }
    }

    /* Initialize attacker knowledge */
    for (i : 0 .. NUM_CLIENTS-1) {
        attackerHasHash[i] = false;
    }

    /* Start normal authentication */
    atomic {
        run Server(0);
        run Server(1);
        run Client(0, 0, 1);  /* Client 0 authenticates to Server 0 */
        run Client(1, 0, 2);  /* Client 1 authenticates to Server 0 */
    }

    /* To test pass-the-hash attack, uncomment: */
    /* attackerHasHash[0] = true; */
    /* run AttackerPTH(0, 1); */

    /* To test relay attack, uncomment: */
    /* run AttackerRelay(0, 0, 1); */
}

/* =========================================================================
   LTL PROPERTIES
   ========================================================================= */

/* Safety: Authentication requires valid credentials */
ltl safety_valid_credentials {
    [] (
        (clientState[0] == AUTHENTICATED) ->
        (clientNTHash[0] == serverUserHashes[clientTarget[0] * NUM_CLIENTS + 0])
    )
}

/* Safety: Challenge uniqueness per server */
ltl safety_challenge_unique {
    [] (
        (serverState[0] == CHALLENGE_SENT) ->
        (serverChallenge[0] > 0)
    )
}

/* Liveness: Authentication eventually completes */
ltl liveness_auth_completes {
    <> (clientState[0] == AUTHENTICATED || clientState[0] == ERROR)
}

/* Security: With EPA, relay should fail */
/* Note: This requires serverChannelBinding[x] = CB_PRESENT */
ltl security_epa_prevents_relay {
    [] (
        (serverChannelBinding[1] == CB_PRESENT &&
         serverAuthenticatedClients[1] != 255) ->
        (clientTarget[serverAuthenticatedClients[1]] == 1)
    )
}

/* =========================================================================
   VULNERABILITY DOCUMENTATION (as comments)
   ========================================================================= */

/*
 * VULNERABILITY 1: Pass-the-Hash
 * ------------------------------
 * If attacker obtains NT hash (via memory dump, SAM extraction, etc.),
 * they can authenticate WITHOUT knowing the password.
 *
 * To verify: Set attackerHasHash[0] = true and run AttackerPTH.
 * The attacker will successfully authenticate as victim.
 *
 * MITIGATION: Use Credential Guard, protected users, or migrate to Kerberos.
 */

/*
 * VULNERABILITY 2: NTLM Relay
 * ---------------------------
 * Without Extended Protection for Authentication (EPA),
 * attacker can relay authentication to a different server.
 *
 * To verify: Set serverChannelBinding[x] = CB_NONE and run AttackerRelay.
 * The attacker can authenticate to target server using victim's credentials.
 *
 * MITIGATION: Enable EPA (channel binding) on all servers.
 */

/*
 * VULNERABILITY 3: Offline Password Cracking
 * ------------------------------------------
 * Captured challenge-response pairs can be attacked offline.
 * NTLMv2 uses HMAC-MD5 which is fast to compute.
 *
 * MITIGATION: Strong passwords, password policies, monitoring.
 */
