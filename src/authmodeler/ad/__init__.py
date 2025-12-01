"""
AuthModeler Active Directory Module

High-level interface for Active Directory authentication.

Components:
- authenticator: ADAuthenticator for protocol negotiation
- config: AD environment configuration

Supports:
- Kerberos V5 (preferred)
- NTLMv2 (fallback)
- SPNEGO/Negotiate

SPEC: Combines Kerberos and NTLM specifications
"""

from authmodeler.ad.authenticator import ADAuthenticator, ADConfig

__all__ = [
    "ADAuthenticator",
    "ADConfig",
]
