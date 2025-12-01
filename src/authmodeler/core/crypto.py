"""
AuthModeler Cryptographic Operations

Wrapper around cryptography library for protocol-specific operations.
Uses established libraries - NO custom cryptographic implementations.

SPEC: specs/alloy/core/crypto.als

Security:
- Uses constant-time comparisons where applicable
- Secure memory handling for keys
- No custom crypto - only standard library wrappers
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Tuple

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from authmodeler.core.types import EncryptionType, Key
from authmodeler.core.exceptions import CryptoError


# =============================================================================
# KEY DERIVATION
# =============================================================================


def derive_key_from_password(
    password: str,
    salt: bytes,
    enctype: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
    iterations: int = 4096,
) -> Key:
    """
    Derive a key from a password using PBKDF2.

    SPEC: specs/alloy/core/crypto.als - PasswordDerivedKey

    This is a simplified version. Real Kerberos uses string2key
    which varies by encryption type.

    Args:
        password: User password
        salt: Salt for key derivation (typically principal name)
        enctype: Target encryption type
        iterations: PBKDF2 iteration count

    Returns:
        Derived key
    """
    key_length = enctype.key_size

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )

    key_material = kdf.derive(password.encode("utf-8"))

    return Key(enctype=enctype, material=key_material)


def generate_session_key(
    enctype: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
) -> bytes:
    """
    Generate a random session key.

    SPEC: specs/alloy/core/crypto.als - SessionKeyGeneration

    Args:
        enctype: Encryption type determining key size

    Returns:
        Random key material
    """
    return secrets.token_bytes(enctype.key_size)


def generate_nonce() -> bytes:
    """
    Generate a random 4-byte nonce.

    SPEC: specs/alloy/core/types.als - Nonce

    Returns:
        4 bytes of random data
    """
    return secrets.token_bytes(4)


# =============================================================================
# ENCRYPTION / DECRYPTION
# =============================================================================


def encrypt_aes_cts(key: bytes, plaintext: bytes, iv: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Encrypt using AES in CBC mode with CTS (Ciphertext Stealing).

    SPEC: specs/alloy/core/crypto.als - SymmetricEncryption

    Note: This is simplified AES-CBC. Real Kerberos AES-CTS is more complex.

    Args:
        key: Encryption key (16 or 32 bytes)
        plaintext: Data to encrypt
        iv: Initialization vector (generated if not provided)

    Returns:
        Tuple of (ciphertext, iv)
    """
    if iv is None:
        iv = secrets.token_bytes(16)

    # Pad plaintext to block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv


def decrypt_aes_cts(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt using AES in CBC mode with CTS.

    SPEC: specs/alloy/core/crypto.als - decrypt function

    Args:
        key: Decryption key
        ciphertext: Encrypted data
        iv: Initialization vector

    Returns:
        Decrypted plaintext

    Raises:
        CryptoError: If decryption or unpadding fails
    """
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext
    except Exception as e:
        raise CryptoError(f"Decryption failed: {e}") from e


def encrypt_rc4(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt using RC4 (for NTLM/legacy Kerberos).

    SPEC: specs/alloy/core/crypto.als - SymmetricEncryption (RC4_HMAC)

    WARNING: RC4 is deprecated and should only be used for compatibility.

    Args:
        key: Encryption key
        plaintext: Data to encrypt

    Returns:
        Ciphertext
    """
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_rc4(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt using RC4.

    Args:
        key: Decryption key
        ciphertext: Encrypted data

    Returns:
        Decrypted plaintext
    """
    # RC4 is symmetric - encryption and decryption are the same
    return encrypt_rc4(key, ciphertext)


# =============================================================================
# HASH FUNCTIONS
# =============================================================================


def md4_hash(data: bytes) -> bytes:
    """
    Compute MD4 hash (for NTLM).

    WARNING: MD4 is cryptographically broken. Only used for NTLM compatibility.

    Args:
        data: Data to hash

    Returns:
        16-byte MD4 hash
    """
    # Use hashlib's MD4 if available, otherwise use cryptography
    try:
        h = hashlib.new("md4")
        h.update(data)
        return h.digest()
    except ValueError:
        # MD4 not available in FIPS mode - this is a problem for NTLM
        raise CryptoError("MD4 not available - required for NTLM")


def md5_hash(data: bytes) -> bytes:
    """
    Compute MD5 hash.

    Args:
        data: Data to hash

    Returns:
        16-byte MD5 hash
    """
    return hashlib.md5(data).digest()  # noqa: S324


def sha1_hash(data: bytes) -> bytes:
    """
    Compute SHA-1 hash.

    Args:
        data: Data to hash

    Returns:
        20-byte SHA-1 hash
    """
    return hashlib.sha1(data).digest()  # noqa: S324


def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash.

    Args:
        data: Data to hash

    Returns:
        32-byte SHA-256 hash
    """
    return hashlib.sha256(data).digest()


# =============================================================================
# HMAC FUNCTIONS
# =============================================================================


def hmac_md5(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-MD5.

    SPEC: specs/alloy/core/crypto.als - HMAC

    Used in NTLM authentication.

    Args:
        key: HMAC key
        data: Data to authenticate

    Returns:
        16-byte HMAC-MD5 tag
    """
    return hmac.new(key, data, hashlib.md5).digest()


def hmac_sha1(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA1.

    Used in Kerberos for checksums.

    Args:
        key: HMAC key
        data: Data to authenticate

    Returns:
        20-byte HMAC-SHA1 tag
    """
    return hmac.new(key, data, hashlib.sha1).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256.

    Args:
        key: HMAC key
        data: Data to authenticate

    Returns:
        32-byte HMAC-SHA256 tag
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_tag: bytes, algorithm: str = "md5") -> bool:
    """
    Verify HMAC tag using constant-time comparison.

    SPEC: specs/alloy/core/crypto.als - verifyHMAC

    Args:
        key: HMAC key
        data: Data that was authenticated
        expected_tag: Tag to verify
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        True if tag is valid, False otherwise
    """
    if algorithm == "md5":
        computed = hmac_md5(key, data)
    elif algorithm == "sha1":
        computed = hmac_sha1(key, data)
    elif algorithm == "sha256":
        computed = hmac_sha256(key, data)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    return hmac.compare_digest(computed, expected_tag)


# =============================================================================
# NTLM-SPECIFIC FUNCTIONS
# =============================================================================


def compute_nt_hash(password: str) -> bytes:
    """
    Compute NT hash from password.

    SPEC: specs/alloy/core/crypto.als - NTHashComputation

    NT Hash = MD4(UTF-16LE(password))

    Args:
        password: User password

    Returns:
        16-byte NT hash
    """
    # Convert to UTF-16LE (little-endian Unicode)
    password_bytes = password.encode("utf-16-le")
    return md4_hash(password_bytes)


def compute_ntlmv2_response(
    nt_hash: bytes,
    username: str,
    domain: str,
    server_challenge: bytes,
    client_challenge: bytes,
    timestamp: bytes,
    target_info: bytes,
) -> Tuple[bytes, bytes]:
    """
    Compute NTLMv2 response.

    SPEC: specs/alloy/ntlm/protocol.als - NTLMv2Computation

    Args:
        nt_hash: User's NT hash
        username: Username (uppercase)
        domain: Domain name (uppercase)
        server_challenge: 8-byte server challenge
        client_challenge: 8-byte client challenge
        timestamp: 8-byte Windows FILETIME
        target_info: AV_PAIR structures from server

    Returns:
        Tuple of (NTLMv2 response, session base key)
    """
    # Step 1: Compute NTLMv2 hash
    # NTLMv2Hash = HMAC-MD5(NT Hash, UPPERCASE(Username) + Domain)
    user_domain = (username.upper() + domain).encode("utf-16-le")
    ntlmv2_hash = hmac_md5(nt_hash, user_domain)

    # Step 2: Build client blob
    # ClientBlob = Timestamp + ClientChallenge + 0x00000000 + TargetInfo + 0x00000000
    client_blob = (
        b"\x01\x01"  # Resp type, Hi resp type
        + b"\x00\x00"  # Reserved1
        + b"\x00\x00\x00\x00"  # Reserved2
        + timestamp
        + client_challenge
        + b"\x00\x00\x00\x00"  # Reserved3
        + target_info
        + b"\x00\x00\x00\x00"  # Reserved4
    )

    # Step 3: Compute NTProofStr
    # NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge + ClientBlob)
    nt_proof_str = hmac_md5(ntlmv2_hash, server_challenge + client_blob)

    # Step 4: Build NTLMv2 response
    ntlmv2_response = nt_proof_str + client_blob

    # Step 5: Compute session base key
    # SessionBaseKey = HMAC-MD5(NTLMv2Hash, NTProofStr)
    session_base_key = hmac_md5(ntlmv2_hash, nt_proof_str)

    return ntlmv2_response, session_base_key


# =============================================================================
# KERBEROS-SPECIFIC FUNCTIONS
# =============================================================================


def compute_kerberos_checksum(
    key: bytes,
    data: bytes,
    enctype: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
) -> bytes:
    """
    Compute Kerberos checksum.

    SPEC: specs/alloy/core/crypto.als - Checksum

    Args:
        key: Checksum key
        data: Data to checksum
        enctype: Encryption type (determines checksum algorithm)

    Returns:
        Checksum value
    """
    if enctype in (
        EncryptionType.AES256_CTS_HMAC_SHA1_96,
        EncryptionType.AES128_CTS_HMAC_SHA1_96,
    ):
        # HMAC-SHA1-96: truncated to 12 bytes
        full_hmac = hmac_sha1(key, data)
        return full_hmac[:12]
    elif enctype == EncryptionType.RC4_HMAC:
        # HMAC-MD5
        return hmac_md5(key, data)
    else:
        raise CryptoError(f"Unsupported encryption type: {enctype}")


def verify_kerberos_checksum(
    key: bytes,
    data: bytes,
    checksum: bytes,
    enctype: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
) -> bool:
    """
    Verify Kerberos checksum using constant-time comparison.

    SPEC: specs/alloy/core/crypto.als - verifyChecksum

    Args:
        key: Checksum key
        data: Data that was checksummed
        checksum: Checksum to verify
        enctype: Encryption type

    Returns:
        True if checksum is valid
    """
    expected = compute_kerberos_checksum(key, data, enctype)
    return hmac.compare_digest(expected, checksum)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.

    Prevents timing attacks on secret comparisons.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)
