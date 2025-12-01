# AuthModeler

Formally verified authentication system for on-premises Active Directory.

## Overview

AuthModeler provides a mathematically proven implementation of authentication protocols for Windows Active Directory environments. The project uses formal methods (Alloy, TLA+) and model checking (SPIN) to verify security properties before implementation.

### Supported Protocols

- **Kerberos V5** (RFC 4120) - Primary authentication mechanism
- **NTLMv2** (MS-NLMP) - Legacy support for compatibility

## Project Status

**Phase 1: Core Specifications** - Complete

### Alloy Specifications
- [x] Core types (`specs/alloy/core/types.als`)
- [x] Cryptographic model (`specs/alloy/core/crypto.als`)
- [x] Dolev-Yao attacker model (`specs/alloy/core/attacker.als`)
- [x] Kerberos protocol (`specs/alloy/kerberos/protocol.als`)
- [x] Kerberos security properties (`specs/alloy/kerberos/properties.als`)
- [x] NTLM protocol (`specs/alloy/ntlm/protocol.als`)
- [x] NTLM security properties (`specs/alloy/ntlm/properties.als`)

### TLA+ Specifications
- [x] Kerberos state machine (`specs/tla/Kerberos.tla`)
- [x] Kerberos properties (`specs/tla/KerberosProps.tla`)
- [x] NTLM state machine (`specs/tla/NTLM.tla`)

### SPIN/Promela Models
- [x] Kerberos model (`specs/promela/kerberos.pml`)
- [x] NTLM model (`specs/promela/ntlm.pml`)

**Phase 2: Python Implementation** - Complete

### Python Implementation
- [x] Core types and state machine (`src/authmodeler/core/`)
- [x] Cryptographic operations (`src/authmodeler/core/crypto.py`)
- [x] Kerberos V5 client (`src/authmodeler/kerberos/`)
- [x] NTLM client (`src/authmodeler/ntlm/`)
- [x] AD Authenticator (`src/authmodeler/ad/`)

## Quick Start

```python
from authmodeler import ADAuthenticator, ADConfig

# Configure AD connection
config = ADConfig(
    domain="EXAMPLE.COM",
    dc_host="dc.example.com",
)

# Create authenticator
auth = ADAuthenticator(config=config)

# Authenticate user (uses Kerberos by default, falls back to NTLM)
result = auth.authenticate("username", "password")

if result.success:
    print(f"Authenticated! Session expires: {result.expiration}")

    # Get service ticket (Kerberos only)
    service_ticket = auth.get_service_ticket("http/webserver.example.com")

    # Export traces for TLA+ verification
    traces = auth.export_traces_json()
```

## Architecture

```
AuthModeler/
├── specs/                      # Formal specifications
│   ├── alloy/                  # Alloy bounded model checking
│   │   ├── core/               # Core type definitions
│   │   ├── kerberos/           # Kerberos protocol models
│   │   └── ntlm/               # NTLM protocol models
│   ├── tla/                    # TLA+ temporal logic specs
│   └── promela/                # SPIN model checking
│
├── src/authmodeler/            # Python implementation
│   ├── core/                   # Core abstractions
│   ├── kerberos/               # Kerberos client
│   ├── ntlm/                   # NTLM client
│   └── ad/                     # Active Directory integration
│
├── tests/                      # Test suites
│   ├── unit/                   # Unit tests
│   ├── property/               # Property-based tests (Hypothesis)
│   ├── conformance/            # Spec conformance tests
│   └── integration/            # AD integration tests
│
└── tools/                      # Verification utilities
```

## Security Properties Verified

### Safety Invariants

| Property | Description |
|----------|-------------|
| NoCredentialLeakage | Plaintext passwords never transmitted |
| NoUnauthorizedAccess | Service access requires valid authentication |
| TicketIntegrity | Tickets cannot be forged without KDC key |
| NonceFreshness | Nonces never reused (replay prevention) |
| SessionKeySecrecy | Session keys not exposed to attacker |

### Liveness Properties

| Property | Description |
|----------|-------------|
| AuthenticationTermination | Valid requests eventually complete |
| SessionEstablishment | Authenticated clients receive session |

### Attack Prevention

- Replay attacks (authenticator caching)
- Pass-the-Hash (Kerberos requires password-derived key)
- Man-in-the-Middle (encrypted messages with session keys)
- Golden Ticket (documented - requires KRBTGT protection)

## Requirements

### Formal Verification Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Alloy | 6.2.0+ | Bounded model checking |
| TLA+ Toolbox | 1.8+ | TLC model checker |
| SPIN | 6.5+ | LTL verification |

### Python

- Python 3.11+
- Dependencies in `pyproject.toml`

## Installation

```bash
# Clone repository
git clone https://github.com/AlchemicalChef/AuthModeler.git
cd AuthModeler

# Install Python package (when implementation is ready)
pip install -e ".[dev]"
```

## Running Formal Verification

### Alloy

1. Open Alloy Analyzer
2. Load `specs/alloy/kerberos/properties.als`
3. Execute checks (e.g., `check NoTicketWithoutAuthentication for 5`)

### TLA+

1. Open TLA+ Toolbox
2. Create new spec from `specs/tla/Kerberos.tla`
3. Create model with:
   - Clients = {c1, c2}
   - Services = {s1}
   - MaxTime = 10
4. Add invariant: `SafetyInvariant`
5. Run TLC

## Development Phases

1. **Core Specifications** - Complete
2. **Protocol Specifications** - Complete (Kerberos + NTLM models)
3. **Python Implementation** - Complete
4. **Validation** - In Progress (property-based testing, AD integration)
5. **Documentation** - Pending (security analysis, API docs)

## References

- [RFC 4120 - Kerberos V5](https://datatracker.ietf.org/doc/html/rfc4120)
- [MS-NLMP - NTLM Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp)
- [MS-KILE - Kerberos Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile)
- [Alloy Analyzer](https://alloytools.org/)
- [TLA+ Tools](https://lamport.azurewebsites.net/tla/tla.html)

## Author

**Keith Ramphal**

## License

MIT License - see [LICENSE](LICENSE)
