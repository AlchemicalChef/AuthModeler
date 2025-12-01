"""
Kerberos Authenticator Replay Cache

Replay attack prevention for Kerberos AP exchange.

SPEC: specs/tla/Kerberos.tla - serviceAuthCache

Stores authenticator identifiers to detect replay attacks.
Each authenticator is uniquely identified by (client_principal, ctime, cusec).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

import attrs
import structlog

from authmodeler.kerberos.types import Authenticator

logger = structlog.get_logger()


# =============================================================================
# AUTHENTICATOR KEY
# =============================================================================


@dataclass(frozen=True)
class AuthenticatorKey:
    """
    Unique identifier for an authenticator.

    Used as cache key for replay detection.
    RFC 4120: Authenticators are identified by (crealm, cname, ctime, cusec).
    """

    client_realm: str
    client_principal: str
    ctime: datetime
    cusec: int

    @classmethod
    def from_authenticator(cls, auth: Authenticator) -> "AuthenticatorKey":
        """Create key from Authenticator."""
        return cls(
            client_realm=auth.client_realm.name,
            client_principal=auth.client_principal.name,
            ctime=auth.ctime.time,
            cusec=auth.cusec,
        )


# =============================================================================
# AUTHENTICATOR CACHE
# =============================================================================


@attrs.define
class AuthenticatorCache:
    """
    Replay attack prevention cache.

    SPEC: specs/tla/Kerberos.tla - serviceAuthCache

    Stores (client_principal, ctime, cusec) tuples to detect replay attacks.
    Authenticators are cached for the clock skew window (typically 5 minutes).

    Thread-safe for concurrent validation.

    Example:
        cache = AuthenticatorCache()

        # Check if authenticator is fresh
        if cache.check_and_add(authenticator):
            # First time seeing this authenticator - process it
            pass
        else:
            # Replay detected - reject
            raise ReplayError("Authenticator replay detected")
    """

    # Clock skew window (seconds) - authenticators older than this are rejected
    clock_skew_seconds: int = 300  # 5 minutes default (RFC 4120 recommendation)

    # Maximum cache entries before cleanup
    max_entries: int = 10000

    # Internal state
    _cache: Dict[AuthenticatorKey, datetime] = attrs.Factory(dict)
    _lock: threading.RLock = attrs.Factory(threading.RLock)
    _logger: structlog.BoundLogger = attrs.Factory(lambda: structlog.get_logger())

    def check_and_add(self, authenticator: Authenticator) -> bool:
        """
        Check if authenticator is replayed, add if not.

        SPEC: TLA+ check - msg.authenticator \notin serviceAuthCache[s]

        Args:
            authenticator: The authenticator to check

        Returns:
            True if authenticator is fresh (not seen before)
            False if authenticator was already seen (replay)
        """
        key = AuthenticatorKey.from_authenticator(authenticator)
        now = datetime.now(timezone.utc)

        with self._lock:
            # Check if already in cache
            if key in self._cache:
                self._logger.warning(
                    "replay_detected",
                    client=key.client_principal,
                    ctime=key.ctime.isoformat(),
                )
                return False

            # Add to cache
            self._cache[key] = now

            # Cleanup if needed
            if len(self._cache) > self.max_entries:
                self._cleanup_expired_locked(now)

            self._logger.debug(
                "authenticator_cached",
                client=key.client_principal,
                ctime=key.ctime.isoformat(),
                cache_size=len(self._cache),
            )

            return True

    def is_replay(self, authenticator: Authenticator) -> bool:
        """
        Check if authenticator has been seen before (without adding).

        Args:
            authenticator: The authenticator to check

        Returns:
            True if this is a replay (already seen)
            False if authenticator is fresh
        """
        key = AuthenticatorKey.from_authenticator(authenticator)

        with self._lock:
            return key in self._cache

    def check_timestamp(self, authenticator: Authenticator) -> Tuple[bool, str]:
        """
        Check if authenticator timestamp is within acceptable skew.

        RFC 4120: Authenticator must be within clock skew window.

        Args:
            authenticator: The authenticator to check

        Returns:
            (True, "") if timestamp is valid
            (False, error_message) if timestamp is invalid
        """
        now = datetime.now(timezone.utc)
        auth_time = authenticator.ctime.time
        delta = abs((now - auth_time).total_seconds())

        if delta > self.clock_skew_seconds:
            return False, f"Clock skew too large: {delta:.1f}s (max: {self.clock_skew_seconds}s)"

        return True, ""

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Entries older than 2x clock_skew_seconds are removed.

        Returns:
            Number of entries removed
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            return self._cleanup_expired_locked(now)

    def _cleanup_expired_locked(self, now: datetime) -> int:
        """Internal cleanup (must hold lock)."""
        expiry_threshold = now - timedelta(seconds=self.clock_skew_seconds * 2)
        expired_keys = [
            key for key, added_time in self._cache.items()
            if added_time < expiry_threshold
        ]

        for key in expired_keys:
            del self._cache[key]

        if expired_keys:
            self._logger.debug(
                "cache_cleanup",
                removed=len(expired_keys),
                remaining=len(self._cache),
            )

        return len(expired_keys)

    def clear(self) -> int:
        """
        Clear all entries from cache.

        Returns:
            Number of entries cleared
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    @property
    def size(self) -> int:
        """Current number of cached authenticators."""
        with self._lock:
            return len(self._cache)

    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "max_entries": self.max_entries,
                "clock_skew_seconds": self.clock_skew_seconds,
            }


# =============================================================================
# KERBEROS ERROR CODES (AP exchange related)
# =============================================================================


class KerberosErrorCode:
    """Kerberos error codes per RFC 4120."""

    # General errors
    KRB_AP_ERR_BAD_INTEGRITY = 31  # Decrypt integrity check failed
    KRB_AP_ERR_TKT_EXPIRED = 32  # Ticket expired
    KRB_AP_ERR_TKT_NYV = 33  # Ticket not yet valid
    KRB_AP_ERR_REPEAT = 34  # Request is a replay
    KRB_AP_ERR_NOT_US = 35  # Ticket isn't for us
    KRB_AP_ERR_BADMATCH = 36  # Ticket and authenticator don't match
    KRB_AP_ERR_SKEW = 37  # Clock skew too great
    KRB_AP_ERR_BADADDR = 38  # Incorrect net address
    KRB_AP_ERR_BADVERSION = 39  # Protocol version mismatch
    KRB_AP_ERR_MSG_TYPE = 40  # Invalid message type
    KRB_AP_ERR_MODIFIED = 41  # Message stream modified

    @classmethod
    def get_message(cls, code: int) -> str:
        """Get human-readable error message."""
        messages = {
            cls.KRB_AP_ERR_BAD_INTEGRITY: "Decryption integrity check failed",
            cls.KRB_AP_ERR_TKT_EXPIRED: "Ticket has expired",
            cls.KRB_AP_ERR_TKT_NYV: "Ticket not yet valid",
            cls.KRB_AP_ERR_REPEAT: "Request is a replay",
            cls.KRB_AP_ERR_NOT_US: "Ticket is not for this service",
            cls.KRB_AP_ERR_BADMATCH: "Ticket and authenticator don't match",
            cls.KRB_AP_ERR_SKEW: "Clock skew too great",
            cls.KRB_AP_ERR_BADADDR: "Incorrect network address",
            cls.KRB_AP_ERR_BADVERSION: "Protocol version mismatch",
            cls.KRB_AP_ERR_MSG_TYPE: "Invalid message type",
            cls.KRB_AP_ERR_MODIFIED: "Message stream modified",
        }
        return messages.get(code, f"Unknown error ({code})")
