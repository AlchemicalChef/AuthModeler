"""
AuthModeler - Formally Verified Authentication for Active Directory

This package provides mathematically proven implementations of authentication
protocols for Windows Active Directory environments.

Supported Protocols:
- Kerberos V5 (RFC 4120)
- NTLMv2 (MS-NLMP)

Formal Verification:
- Alloy specifications for protocol safety
- TLA+ specifications for liveness and temporal properties
- SPIN/Promela models for LTL verification

Example Usage:
    from authmodeler import ADAuthenticator, ADConfig, Protocol

    config = ADConfig(
        domain="EXAMPLE.COM",
        dc_host="dc.example.com",
    )
    auth = ADAuthenticator(config)

    result = auth.authenticate(
        username="jdoe",
        password="secret",
    )
    if result.success:
        print(f"Authenticated! Session expires: {result.expiration}")

        # Export trace for TLA+ verification
        trace = auth.export_traces_json()
"""

from authmodeler.core.types import Protocol, AuthResult, Principal, Realm
from authmodeler.ad.authenticator import ADAuthenticator, ADConfig

__version__ = "0.1.0"
__author__ = "Keith Ramphal"

__all__ = [
    # Main API
    "ADAuthenticator",
    "ADConfig",
    # Types
    "Protocol",
    "AuthResult",
    "Principal",
    "Realm",
    # Metadata
    "__version__",
]
