"""
Property-based tests for cryptographic operations.

Uses Hypothesis to test invariants across many random inputs.
"""

import pytest
from hypothesis import given, strategies as st, assume, settings

from authmodeler.core.crypto import (
    derive_key_from_password,
    generate_session_key,
    encrypt_aes_cts,
    decrypt_aes_cts,
    compute_nt_hash,
    hmac_md5,
    encrypt_rc4,
    decrypt_rc4,
)
from authmodeler.core.types import EncryptionType


# =============================================================================
# STRATEGIES
# =============================================================================

# Strategy for valid passwords (printable characters, reasonable length)
password_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N', 'P', 'S')),
    min_size=1,
    max_size=128,
)

# Strategy for salt values
salt_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N')),
    min_size=1,
    max_size=64,
)

# Strategy for plaintext data
plaintext_strategy = st.binary(min_size=1, max_size=1024)

# Strategy for AES key sizes
aes256_key_strategy = st.binary(min_size=32, max_size=32)
aes128_key_strategy = st.binary(min_size=16, max_size=16)


# =============================================================================
# KEY DERIVATION PROPERTIES
# =============================================================================


class TestKeyDerivationProperties:
    """Property-based tests for key derivation."""

    @given(password=password_strategy, salt=salt_strategy)
    @settings(max_examples=50)
    def test_key_derivation_deterministic(self, password: str, salt: str):
        """Property: Same input always produces same key."""
        salt_bytes = salt.encode("utf-8")
        key1 = derive_key_from_password(
            password=password,
            salt=salt_bytes,
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        key2 = derive_key_from_password(
            password=password,
            salt=salt_bytes,
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert key1.material == key2.material

    @given(password=password_strategy, salt=salt_strategy)
    @settings(max_examples=50)
    def test_key_length_aes256(self, password: str, salt: str):
        """Property: AES256 key is always 32 bytes."""
        key = derive_key_from_password(
            password=password,
            salt=salt.encode("utf-8"),
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert len(key.material) == 32

    @given(password=password_strategy, salt=salt_strategy)
    @settings(max_examples=50)
    def test_key_length_aes128(self, password: str, salt: str):
        """Property: AES128 key is always 16 bytes."""
        key = derive_key_from_password(
            password=password,
            salt=salt.encode("utf-8"),
            enctype=EncryptionType.AES128_CTS_HMAC_SHA1_96,
        )
        assert len(key.material) == 16

    @given(
        password1=password_strategy,
        password2=password_strategy,
        salt=salt_strategy,
    )
    @settings(max_examples=50)
    def test_different_passwords_different_keys(
        self, password1: str, password2: str, salt: str
    ):
        """Property: Different passwords produce different keys."""
        assume(password1 != password2)

        salt_bytes = salt.encode("utf-8")
        key1 = derive_key_from_password(
            password=password1,
            salt=salt_bytes,
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        key2 = derive_key_from_password(
            password=password2,
            salt=salt_bytes,
            enctype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
        )
        assert key1.material != key2.material


# =============================================================================
# AES ENCRYPTION PROPERTIES
# =============================================================================


class TestAESEncryptionProperties:
    """Property-based tests for AES encryption."""

    @given(key=aes256_key_strategy, plaintext=plaintext_strategy)
    @settings(max_examples=100)
    def test_encrypt_decrypt_roundtrip(self, key: bytes, plaintext: bytes):
        """Property: Decrypt(Encrypt(x)) == x for all x."""
        ciphertext, iv = encrypt_aes_cts(key, plaintext)
        decrypted = decrypt_aes_cts(key, ciphertext, iv)
        assert decrypted == plaintext

    @given(key=aes256_key_strategy, plaintext=plaintext_strategy)
    @settings(max_examples=50)
    def test_encryption_produces_different_output(self, key: bytes, plaintext: bytes):
        """Property: Ciphertext differs from plaintext (with high probability)."""
        ciphertext, iv = encrypt_aes_cts(key, plaintext)
        # For any reasonably sized plaintext, ciphertext should differ
        assert ciphertext != plaintext

    @given(key=aes256_key_strategy, plaintext=plaintext_strategy)
    @settings(max_examples=50)
    def test_iv_randomness(self, key: bytes, plaintext: bytes):
        """Property: IVs are different for each encryption."""
        _, iv1 = encrypt_aes_cts(key, plaintext)
        _, iv2 = encrypt_aes_cts(key, plaintext)
        assert iv1 != iv2

    @given(
        key1=aes256_key_strategy,
        key2=aes256_key_strategy,
        plaintext=plaintext_strategy,
    )
    @settings(max_examples=50)
    def test_wrong_key_produces_wrong_plaintext(
        self, key1: bytes, key2: bytes, plaintext: bytes
    ):
        """Property: Decrypting with wrong key doesn't recover plaintext."""
        from authmodeler.core.exceptions import CryptoError
        assume(key1 != key2)

        ciphertext, iv = encrypt_aes_cts(key1, plaintext)
        try:
            wrong_decrypted = decrypt_aes_cts(key2, ciphertext, iv)
            # With overwhelming probability, wrong key gives wrong plaintext
            assert wrong_decrypted != plaintext
        except CryptoError:
            # This is also valid - decryption can fail with wrong key
            pass


# =============================================================================
# NT HASH PROPERTIES
# =============================================================================


class TestNTHashProperties:
    """Property-based tests for NT hash computation."""

    @pytest.fixture(autouse=True)
    def skip_if_md4_unavailable(self):
        """Skip tests if MD4 is not available."""
        try:
            import hashlib
            hashlib.new("md4")
        except ValueError:
            pytest.skip("MD4 not available (FIPS mode or unsupported)")

    @given(password=password_strategy)
    @settings(max_examples=100)
    def test_nt_hash_deterministic(self, password: str):
        """Property: Same password always produces same hash."""
        hash1 = compute_nt_hash(password)
        hash2 = compute_nt_hash(password)
        assert hash1 == hash2

    @given(password=password_strategy)
    @settings(max_examples=100)
    def test_nt_hash_length(self, password: str):
        """Property: NT hash is always 16 bytes (MD4 output)."""
        nt_hash = compute_nt_hash(password)
        assert len(nt_hash) == 16

    @given(password1=password_strategy, password2=password_strategy)
    @settings(max_examples=50)
    def test_different_passwords_different_hashes(self, password1: str, password2: str):
        """Property: Different passwords produce different hashes."""
        assume(password1 != password2)

        hash1 = compute_nt_hash(password1)
        hash2 = compute_nt_hash(password2)
        assert hash1 != hash2


# =============================================================================
# HMAC-MD5 PROPERTIES
# =============================================================================


class TestHMACMD5Properties:
    """Property-based tests for HMAC-MD5."""

    @given(key=st.binary(min_size=1, max_size=64), data=st.binary(min_size=0, max_size=512))
    @settings(max_examples=100)
    def test_hmac_deterministic(self, key: bytes, data: bytes):
        """Property: Same input always produces same MAC."""
        mac1 = hmac_md5(key, data)
        mac2 = hmac_md5(key, data)
        assert mac1 == mac2

    @given(key=st.binary(min_size=1, max_size=64), data=st.binary(min_size=0, max_size=512))
    @settings(max_examples=100)
    def test_hmac_length(self, key: bytes, data: bytes):
        """Property: HMAC-MD5 is always 16 bytes."""
        mac = hmac_md5(key, data)
        assert len(mac) == 16

    @given(
        key1=st.binary(min_size=1, max_size=64),
        key2=st.binary(min_size=1, max_size=64),
        data=st.binary(min_size=1, max_size=256),
    )
    @settings(max_examples=50)
    def test_different_keys_different_macs(self, key1: bytes, key2: bytes, data: bytes):
        """Property: Different keys produce different MACs."""
        assume(key1 != key2)

        mac1 = hmac_md5(key1, data)
        mac2 = hmac_md5(key2, data)
        assert mac1 != mac2


# =============================================================================
# RC4 ENCRYPTION PROPERTIES
# =============================================================================


class TestRC4Properties:
    """Property-based tests for RC4 encryption."""

    # RC4 key sizes: Valid sizes are 5-16 bytes (40-128 bits)
    # Use sampled_from to only generate valid key sizes
    rc4_key_strategy = st.sampled_from([5, 7, 8, 10, 16]).flatmap(
        lambda size: st.binary(min_size=size, max_size=size)
    )

    @given(key=rc4_key_strategy, plaintext=plaintext_strategy)
    @settings(max_examples=100)
    def test_rc4_roundtrip(self, key: bytes, plaintext: bytes):
        """Property: Decrypt(Encrypt(x)) == x for RC4."""
        ciphertext = encrypt_rc4(key, plaintext)
        decrypted = decrypt_rc4(key, ciphertext)
        assert decrypted == plaintext

    @given(key=rc4_key_strategy, plaintext=plaintext_strategy)
    @settings(max_examples=50)
    def test_rc4_length_preserved(self, key: bytes, plaintext: bytes):
        """Property: RC4 is a stream cipher - length preserved."""
        ciphertext = encrypt_rc4(key, plaintext)
        assert len(ciphertext) == len(plaintext)

    @given(key=rc4_key_strategy, plaintext=plaintext_strategy)
    @settings(max_examples=50)
    def test_rc4_symmetric(self, key: bytes, plaintext: bytes):
        """Property: RC4 encryption is symmetric (E = D)."""
        # RC4 encrypt and decrypt are the same operation
        encrypted = encrypt_rc4(key, plaintext)
        double_encrypted = encrypt_rc4(key, encrypted)
        assert double_encrypted == plaintext


# =============================================================================
# SESSION KEY GENERATION PROPERTIES
# =============================================================================


class TestSessionKeyProperties:
    """Property-based tests for session key generation."""

    @given(st.sampled_from([
        EncryptionType.AES256_CTS_HMAC_SHA1_96,
        EncryptionType.AES128_CTS_HMAC_SHA1_96,
        EncryptionType.RC4_HMAC,
    ]))
    @settings(max_examples=30)
    def test_session_key_correct_length(self, enctype: EncryptionType):
        """Property: Session keys have correct length for encryption type."""
        key = generate_session_key(enctype)

        expected_lengths = {
            EncryptionType.AES256_CTS_HMAC_SHA1_96: 32,
            EncryptionType.AES128_CTS_HMAC_SHA1_96: 16,
            EncryptionType.RC4_HMAC: 16,
        }
        assert len(key) == expected_lengths[enctype]

    @given(st.sampled_from([
        EncryptionType.AES256_CTS_HMAC_SHA1_96,
        EncryptionType.AES128_CTS_HMAC_SHA1_96,
    ]))
    @settings(max_examples=20)
    def test_session_keys_unique(self, enctype: EncryptionType):
        """Property: Generated session keys are unique."""
        key1 = generate_session_key(enctype)
        key2 = generate_session_key(enctype)
        assert key1 != key2
