"""
AuthModeler Transport Layer

Network transport and native library integration for authentication protocols.

Components:
- gssapi_wrapper: GSSAPI integration (Unix/Linux/macOS)
- sspi_wrapper: SSPI integration (Windows)
- kdc_transport: KDC network communication
"""

from authmodeler.transport.kdc_transport import KDCTransport, KDCConnection
from authmodeler.transport.gssapi_wrapper import GSSAPIContext, gssapi_available
from authmodeler.transport.sspi_wrapper import SSPIContext, sspi_available

__all__ = [
    # KDC Transport
    "KDCTransport",
    "KDCConnection",
    # GSSAPI
    "GSSAPIContext",
    "gssapi_available",
    # SSPI
    "SSPIContext",
    "sspi_available",
]
