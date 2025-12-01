"""
AuthModeler KDC Transport Layer

Network transport for Kerberos Key Distribution Center (KDC) communication.

SPEC: specs/alloy/kerberos/protocol.als - KDC communication
SPEC: specs/tla/Kerberos.tla - Network messages

Supports:
- TCP transport (default for AD)
- UDP transport (traditional Kerberos)
- DNS-based KDC discovery
- Multiple KDC failover

Protocol:
- Port 88 (Kerberos)
- TCP: 4-byte length prefix + message
- UDP: raw message (max 1400 bytes typical)
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Union

import attrs
import structlog

from authmodeler.core.types import Realm
from authmodeler.core.exceptions import ProtocolError

logger = structlog.get_logger()


# =============================================================================
# DNS DISCOVERY
# =============================================================================


def discover_kdc_servers(realm: str) -> List[Tuple[str, int]]:
    """
    Discover KDC servers for a realm using DNS SRV records.

    Queries: _kerberos._tcp.<realm>
             _kerberos._udp.<realm>

    Args:
        realm: Kerberos realm name

    Returns:
        List of (hostname, port) tuples sorted by priority
    """
    import dns.resolver

    servers = []

    # Try TCP first (preferred for AD)
    for proto in ["_tcp", "_udp"]:
        srv_name = f"_kerberos.{proto}.{realm.lower()}"
        try:
            answers = dns.resolver.resolve(srv_name, "SRV")
            for rdata in answers:
                servers.append({
                    "host": str(rdata.target).rstrip("."),
                    "port": rdata.port,
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                    "proto": proto,
                })
        except Exception as e:
            logger.debug("dns_srv_lookup_failed", name=srv_name, error=str(e))

    # Sort by priority (lower is better), then weight (higher is better)
    servers.sort(key=lambda x: (x["priority"], -x["weight"]))

    return [(s["host"], s["port"]) for s in servers]


def discover_dc_servers(domain: str) -> List[Tuple[str, int]]:
    """
    Discover Domain Controller servers using DNS SRV records.

    Queries: _ldap._tcp.dc._msdcs.<domain>

    Args:
        domain: AD domain name

    Returns:
        List of (hostname, port) tuples sorted by priority
    """
    try:
        import dns.resolver
    except ImportError:
        logger.warning("dnspython_not_available", message="Install dnspython for DNS discovery")
        return []

    servers = []

    # DC SRV records
    srv_name = f"_ldap._tcp.dc._msdcs.{domain.lower()}"
    try:
        answers = dns.resolver.resolve(srv_name, "SRV")
        for rdata in answers:
            servers.append({
                "host": str(rdata.target).rstrip("."),
                "port": rdata.port,
                "priority": rdata.priority,
                "weight": rdata.weight,
            })
    except Exception as e:
        logger.debug("dns_srv_lookup_failed", name=srv_name, error=str(e))

    # Sort by priority and weight
    servers.sort(key=lambda x: (x["priority"], -x["weight"]))

    return [(s["host"], s["port"]) for s in servers]


# =============================================================================
# KDC CONNECTION
# =============================================================================


class TransportProtocol(Enum):
    """KDC transport protocol."""
    TCP = auto()
    UDP = auto()


@attrs.define
class KDCConnection:
    """
    Connection to a Kerberos KDC.

    Handles TCP and UDP communication with length framing.
    """

    host: str
    port: int = 88
    protocol: TransportProtocol = TransportProtocol.TCP
    timeout: float = 10.0

    _socket: Optional[socket.socket] = None
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def connect(self) -> None:
        """Establish connection to KDC."""
        if self._socket:
            return

        try:
            if self.protocol == TransportProtocol.TCP:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.timeout)
                self._socket.connect((self.host, self.port))
                self._logger.debug(
                    "kdc_tcp_connected",
                    host=self.host,
                    port=self.port,
                )
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.settimeout(self.timeout)
                self._logger.debug(
                    "kdc_udp_socket_created",
                    host=self.host,
                    port=self.port,
                )

        except socket.error as e:
            self._logger.error(
                "kdc_connect_failed",
                host=self.host,
                port=self.port,
                error=str(e),
            )
            raise ProtocolError(f"Failed to connect to KDC {self.host}:{self.port}: {e}") from e

    def close(self) -> None:
        """Close connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
            self._logger.debug("kdc_connection_closed", host=self.host)

    def send_receive(self, data: bytes) -> bytes:
        """
        Send a message and receive response.

        For TCP: Uses 4-byte length prefix
        For UDP: Raw message

        Args:
            data: Message bytes to send

        Returns:
            Response bytes from KDC
        """
        if not self._socket:
            self.connect()

        try:
            if self.protocol == TransportProtocol.TCP:
                return self._send_receive_tcp(data)
            else:
                return self._send_receive_udp(data)

        except socket.timeout:
            raise ProtocolError(f"KDC timeout: {self.host}:{self.port}")
        except socket.error as e:
            raise ProtocolError(f"KDC communication error: {e}") from e

    def _send_receive_tcp(self, data: bytes) -> bytes:
        """TCP send/receive with length framing."""
        # Send with 4-byte length prefix (big-endian)
        length_prefix = struct.pack(">I", len(data))
        self._socket.sendall(length_prefix + data)

        self._logger.debug(
            "kdc_tcp_sent",
            length=len(data),
        )

        # Receive length prefix
        length_data = self._recv_exact(4)
        response_length = struct.unpack(">I", length_data)[0]

        # Validate response length
        if response_length > 1024 * 1024:  # 1MB max
            raise ProtocolError(f"Response too large: {response_length}")

        # Receive response
        response = self._recv_exact(response_length)

        self._logger.debug(
            "kdc_tcp_received",
            length=len(response),
        )

        return response

    def _send_receive_udp(self, data: bytes) -> bytes:
        """UDP send/receive."""
        # Send raw message
        self._socket.sendto(data, (self.host, self.port))

        self._logger.debug(
            "kdc_udp_sent",
            length=len(data),
        )

        # Receive response
        response, _ = self._socket.recvfrom(65535)

        self._logger.debug(
            "kdc_udp_received",
            length=len(response),
        )

        return response

    def _recv_exact(self, length: int) -> bytes:
        """Receive exactly length bytes from TCP socket."""
        data = b""
        while len(data) < length:
            chunk = self._socket.recv(length - len(data))
            if not chunk:
                raise ProtocolError("Connection closed by KDC")
            data += chunk
        return data

    def __enter__(self) -> "KDCConnection":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# =============================================================================
# KDC TRANSPORT
# =============================================================================


@attrs.define
class KDCTransport:
    """
    High-level KDC transport with failover support.

    SPEC: specs/alloy/kerberos/protocol.als - KDC communication

    Provides:
    - DNS-based KDC discovery
    - Multiple KDC failover
    - TCP/UDP protocol selection
    - Connection pooling

    Example:
        transport = KDCTransport(realm="EXAMPLE.COM")

        # Send AS-REQ
        response = transport.send_message(as_req_bytes)

        # Parse AS-REP or KRB-ERROR
        ...
    """

    realm: str
    kdc_hosts: List[Tuple[str, int]] = attrs.Factory(list)
    protocol: TransportProtocol = TransportProtocol.TCP
    timeout: float = 10.0
    max_retries: int = 3

    _connections: Dict[str, KDCConnection] = attrs.Factory(dict)
    _current_kdc_index: int = 0
    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    def __attrs_post_init__(self) -> None:
        """Initialize KDC list if not provided."""
        if not self.kdc_hosts:
            self._discover_kdcs()

    def _discover_kdcs(self) -> None:
        """Discover KDCs via DNS."""
        try:
            self.kdc_hosts = discover_kdc_servers(self.realm)
            if self.kdc_hosts:
                self._logger.info(
                    "kdc_discovered",
                    realm=self.realm,
                    count=len(self.kdc_hosts),
                    hosts=[f"{h}:{p}" for h, p in self.kdc_hosts[:3]],
                )
        except Exception as e:
            self._logger.warning(
                "kdc_discovery_failed",
                realm=self.realm,
                error=str(e),
            )

    def add_kdc(self, host: str, port: int = 88) -> None:
        """
        Manually add a KDC server.

        Args:
            host: KDC hostname
            port: KDC port (default 88)
        """
        self.kdc_hosts.append((host, port))
        self._logger.debug("kdc_added", host=host, port=port)

    def send_message(self, data: bytes) -> bytes:
        """
        Send a Kerberos message to the KDC.

        Handles failover between multiple KDCs.

        Args:
            data: Kerberos message bytes (AS-REQ, TGS-REQ, etc.)

        Returns:
            Response bytes (AS-REP, TGS-REP, KRB-ERROR)
        """
        if not self.kdc_hosts:
            raise ProtocolError(f"No KDCs available for realm {self.realm}")

        last_error = None
        tried_kdcs = set()

        for attempt in range(self.max_retries):
            # Get next KDC
            kdc_host, kdc_port = self._get_next_kdc(tried_kdcs)
            tried_kdcs.add((kdc_host, kdc_port))

            try:
                conn = self._get_connection(kdc_host, kdc_port)
                response = conn.send_receive(data)
                return response

            except ProtocolError as e:
                last_error = e
                self._logger.warning(
                    "kdc_request_failed",
                    host=kdc_host,
                    port=kdc_port,
                    attempt=attempt + 1,
                    error=str(e),
                )
                # Remove failed connection
                self._remove_connection(kdc_host, kdc_port)
                continue

        raise ProtocolError(
            f"All KDCs failed for {self.realm}: {last_error}"
        )

    def _get_next_kdc(
        self, exclude: set
    ) -> Tuple[str, int]:
        """Get next KDC to try, excluding already-tried ones."""
        for host, port in self.kdc_hosts:
            if (host, port) not in exclude:
                return host, port

        # All tried, cycle through again
        self._current_kdc_index = (self._current_kdc_index + 1) % len(self.kdc_hosts)
        return self.kdc_hosts[self._current_kdc_index]

    def _get_connection(self, host: str, port: int) -> KDCConnection:
        """Get or create connection to KDC."""
        key = f"{host}:{port}"

        if key not in self._connections:
            conn = KDCConnection(
                host=host,
                port=port,
                protocol=self.protocol,
                timeout=self.timeout,
            )
            conn.connect()
            self._connections[key] = conn

        return self._connections[key]

    def _remove_connection(self, host: str, port: int) -> None:
        """Remove and close a failed connection."""
        key = f"{host}:{port}"
        if key in self._connections:
            try:
                self._connections[key].close()
            except Exception:
                pass
            del self._connections[key]

    def close(self) -> None:
        """Close all connections."""
        for conn in self._connections.values():
            try:
                conn.close()
            except Exception:
                pass
        self._connections.clear()

    def __enter__(self) -> "KDCTransport":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# =============================================================================
# ASYNC KDC TRANSPORT
# =============================================================================


@attrs.define
class AsyncKDCTransport:
    """
    Async KDC transport for high-performance applications.

    Provides async/await interface for KDC communication.
    """

    realm: str
    kdc_hosts: List[Tuple[str, int]] = attrs.Factory(list)
    timeout: float = 10.0

    _logger: Any = attrs.Factory(lambda: structlog.get_logger())

    async def send_message(self, data: bytes) -> bytes:
        """
        Send a Kerberos message asynchronously.

        Args:
            data: Kerberos message bytes

        Returns:
            Response bytes
        """
        if not self.kdc_hosts:
            # Try DNS discovery
            try:
                self.kdc_hosts = discover_kdc_servers(self.realm)
            except Exception:
                pass

        if not self.kdc_hosts:
            raise ProtocolError(f"No KDCs available for realm {self.realm}")

        last_error = None

        for host, port in self.kdc_hosts:
            try:
                return await self._send_tcp(host, port, data)
            except Exception as e:
                last_error = e
                self._logger.warning(
                    "async_kdc_failed",
                    host=host,
                    port=port,
                    error=str(e),
                )
                continue

        raise ProtocolError(f"All KDCs failed: {last_error}")

    async def _send_tcp(
        self, host: str, port: int, data: bytes
    ) -> bytes:
        """Send via TCP with async."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.timeout,
        )

        try:
            # Send with length prefix
            length_prefix = struct.pack(">I", len(data))
            writer.write(length_prefix + data)
            await writer.drain()

            # Receive length
            length_data = await asyncio.wait_for(
                reader.readexactly(4),
                timeout=self.timeout,
            )
            response_length = struct.unpack(">I", length_data)[0]

            # Receive response
            response = await asyncio.wait_for(
                reader.readexactly(response_length),
                timeout=self.timeout,
            )

            return response

        finally:
            writer.close()
            await writer.wait_closed()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def create_kdc_transport(
    realm: str,
    kdc_host: Optional[str] = None,
    kdc_port: int = 88,
    use_tcp: bool = True,
) -> KDCTransport:
    """
    Create a KDC transport for a realm.

    Args:
        realm: Kerberos realm
        kdc_host: Explicit KDC host (None for DNS discovery)
        kdc_port: KDC port
        use_tcp: Use TCP (True) or UDP (False)

    Returns:
        Configured KDCTransport
    """
    kdc_hosts = []
    if kdc_host:
        kdc_hosts.append((kdc_host, kdc_port))

    return KDCTransport(
        realm=realm,
        kdc_hosts=kdc_hosts,
        protocol=TransportProtocol.TCP if use_tcp else TransportProtocol.UDP,
    )
