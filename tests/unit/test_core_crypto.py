"""
Unit tests for authmodeler.core.crypto module.

Tests cryptographic operations used in Kerberos and NTLM.
"""

import pytest
import secrets

from authmodeler.core.crypto import (
    derive_key_from_password,
    generate_session_key,
    encrypt_aes_cts,
    decrypt_aes_cts,
    compute_nt_hash,
    compute_ntlmv2_response,
    hmac_md5,
    encrypt_rc4,
    decrypt_rc4,
)
from authmodeler.core.types import EncryptionType
from authmodeler.core.exceptions import CryptoError


class TestKeyDerivation:
    """Tests for key derivation functions."""

    def test_derive_key_from_password_aes256(self):
        """Test AES256 key derivation from password."""
        key = derive_key_from_password(
            password="TestPassword123!",
            salt=b"EXAMPLE.COMuser",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert len(key.material) == 32  # AES256 = 256 bits = 32 bytes
        assert isinstance(key.material, bytes)

    def test_derive_key_from_password_aes128(self):
        """Test AES128 key derivation from password."""
        key = derive_key_from_password(
            password="TestPassword123!",
            salt=b"EXAMPLE.COMuser",
            enctype=EncryptionType.AES128_CTS_HMAC_SHA1_96,
        )
        assert len(key.material) == 16  # AES128 = 128 bits = 16 bytes

    def test_derive_key_deterministic(self):
        """Test key derivation is deterministic (same input = same output)."""
        key1 = derive_key_from_password(
            password="TestPassword",
            salt=b"EXAMPLE.COMuser",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        key2 = derive_key_from_password(
            password="TestPassword",
            salt=b"EXAMPLE.COMuser",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert key1.material == key2.material

    def test_derive_key_different_passwords(self):
        """Test different passwords produce different keys."""
        key1 = derive_key_from_password(
            password="Password1",
            salt=b"EXAMPLE.COMuser",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        key2 = derive_key_from_password(
            password="Password2",
            salt=b"EXAMPLE.COMuser",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert key1.material != key2.material

    def test_derive_key_different_salts(self):
        """Test different salts produce different keys."""
        key1 = derive_key_from_password(
            password="Password",
            salt=b"EXAMPLE.COMuser1",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        key2 = derive_key_from_password(
            password="Password",
            salt=b"EXAMPLE.COMuser2",
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert key1.material != key2.material


class TestSessionKeyGeneration:
    """Tests for session key generation."""

    def test_generate_session_key_aes256(self):
        """Test AES256 session key generation."""
        key = generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96)
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_session_key_aes128(self):
        """Test AES128 session key generation."""
        key = generate_session_key(EncryptionType.AES128_CTS_HMAC_SHA1_96)
        assert len(key) == 16

    def test_generate_session_key_rc4(self):
        """Test RC4 session key generation."""
        key = generate_session_key(EncryptionType.RC4_HMAC)
        assert len(key) == 16

    def test_generate_session_key_random(self):
        """Test session keys are random."""
        key1 = generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96)
        key2 = generate_session_key(EncryptionType.AES256_CTS_HMAC_SHA1_96)
        assert key1 != key2


class TestAESEncryption:
    """Tests for AES-CTS encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        key = secrets.token_bytes(32)  # AES256 key
        plaintext = b"This is a test message for encryption!"

        ciphertext, iv = encrypt_aes_cts(key, plaintext)
        decrypted = decrypt_aes_cts(key, ciphertext, iv)

        assert decrypted == plaintext

    def test_encrypt_produces_ciphertext(self):
        """Test encryption produces different output."""
        key = secrets.token_bytes(32)
        plaintext = b"Secret data"

        ciphertext, iv = encrypt_aes_cts(key, plaintext)

        assert ciphertext != plaintext
        assert len(ciphertext) >= len(plaintext)

    def test_decrypt_wrong_key_fails(self):
        """Test decryption with wrong key fails."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        plaintext = b"Secret data"

        ciphertext, iv = encrypt_aes_cts(key1, plaintext)

        # Decrypting with wrong key should raise CryptoError or produce garbage
        try:
            decrypted = decrypt_aes_cts(key2, ciphertext, iv)
            # If it doesn't raise, the decrypted data should be different
            assert decrypted != plaintext
        except CryptoError:
            # This is also valid behavior
            pass

    def test_iv_is_random(self):
        """Test IV is random for each encryption."""
        key = secrets.token_bytes(32)
        plaintext = b"Same plaintext"

        _, iv1 = encrypt_aes_cts(key, plaintext)
        _, iv2 = encrypt_aes_cts(key, plaintext)

        assert iv1 != iv2


def requires_md4():
    """Check if MD4 is available."""
    try:
        import hashlib
        hashlib.new("md4")
        return False
    except ValueError:
        return True


@pytest.mark.skipif(requires_md4(), reason="MD4 not available (FIPS mode or unsupported)")
class TestNTLMCrypto:
    """Tests for NTLM cryptographic functions."""

    def test_compute_nt_hash(self):
        """Test NT hash computation."""
        nt_hash = compute_nt_hash("Password")
        assert len(nt_hash) == 16  # MD4 produces 128 bits = 16 bytes
        assert isinstance(nt_hash, bytes)

    def test_compute_nt_hash_deterministic(self):
        """Test NT hash is deterministic."""
        hash1 = compute_nt_hash("Password123")
        hash2 = compute_nt_hash("Password123")
        assert hash1 == hash2

    def test_compute_nt_hash_different_passwords(self):
        """Test different passwords produce different hashes."""
        hash1 = compute_nt_hash("Password1")
        hash2 = compute_nt_hash("Password2")
        assert hash1 != hash2

    def test_compute_nt_hash_empty_password(self):
        """Test NT hash of empty password."""
        nt_hash = compute_nt_hash("")
        assert len(nt_hash) == 16
        # Known value for empty password
        assert nt_hash == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_compute_ntlmv2_response(self):
        """Test NTLMv2 response computation."""
        nt_hash = compute_nt_hash("Password")
        server_challenge = secrets.token_bytes(8)
        client_challenge = secrets.token_bytes(8)
        timestamp = b"\x00" * 8  # Placeholder timestamp

        response, session_base_key = compute_ntlmv2_response(
            nt_hash=nt_hash,
            username="testuser",
            domain="EXAMPLE",
            server_challenge=server_challenge,
            client_challenge=client_challenge,
            timestamp=timestamp,
            target_info=b"",
        )

        assert len(response) > 0
        assert len(session_base_key) == 16

    def test_hmac_md5(self):
        """Test HMAC-MD5 computation."""
        key = b"secret_key"
        data = b"message to authenticate"

        mac = hmac_md5(key, data)

        assert len(mac) == 16  # MD5 = 128 bits
        assert isinstance(mac, bytes)

    def test_hmac_md5_deterministic(self):
        """Test HMAC-MD5 is deterministic."""
        key = b"key"
        data = b"data"

        mac1 = hmac_md5(key, data)
        mac2 = hmac_md5(key, data)

        assert mac1 == mac2


class TestRC4Encryption:
    """Tests for RC4 encryption (used in legacy NTLM)."""

    def test_encrypt_decrypt_rc4(self):
        """Test RC4 encryption/decryption roundtrip."""
        key = secrets.token_bytes(16)
        plaintext = b"Test message for RC4"

        ciphertext = encrypt_rc4(key, plaintext)
        decrypted = decrypt_rc4(key, ciphertext)

        assert decrypted == plaintext

    def test_rc4_stream_cipher(self):
        """Test RC4 is a stream cipher (same length)."""
        key = secrets.token_bytes(16)
        plaintext = b"Exactly this length"

        ciphertext = encrypt_rc4(key, plaintext)

        assert len(ciphertext) == len(plaintext)

    def test_rc4_wrong_key(self):
        """Test RC4 decryption with wrong key fails."""
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(16)
        plaintext = b"Secret"

        ciphertext = encrypt_rc4(key1, plaintext)
        decrypted = decrypt_rc4(key2, ciphertext)

        assert decrypted != plaintext
