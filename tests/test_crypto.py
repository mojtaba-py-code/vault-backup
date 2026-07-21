from __future__ import annotations

import pytest

from securesync import crypto
from securesync.errors import CryptoError


def test_seal_open_roundtrip():
    key = crypto.new_key()
    nonce, ct = crypto.seal(key, b"hello world", b"aad")
    assert crypto.open_sealed(key, nonce, ct, b"aad") == b"hello world"


def test_wrong_key_fails():
    nonce, ct = crypto.seal(crypto.new_key(), b"secret", b"aad")
    with pytest.raises(CryptoError):
        crypto.open_sealed(crypto.new_key(), nonce, ct, b"aad")


def test_tampered_ciphertext_fails():
    key = crypto.new_key()
    nonce, ct = crypto.seal(key, b"secret data", b"aad")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(CryptoError):
        crypto.open_sealed(key, nonce, bytes(tampered), b"aad")


def test_wrong_aad_fails():
    key = crypto.new_key()
    nonce, ct = crypto.seal(key, b"secret", b"chunk-id-A")
    with pytest.raises(CryptoError):
        crypto.open_sealed(key, nonce, ct, b"chunk-id-B")


def test_kdf_deterministic_and_salt_sensitive():
    pw = b"correct horse battery staple"
    salt = crypto.new_salt()
    params = crypto.KdfParams()
    k1 = crypto.derive_kek(pw, salt, params)
    k2 = crypto.derive_kek(pw, salt, params)
    assert k1 == k2 and len(k1) == 32
    assert crypto.derive_kek(pw, crypto.new_salt(), params) != k1


def test_subkey_separation():
    master = crypto.new_key()
    a = crypto.derive_subkey(master, b"role-a")
    b = crypto.derive_subkey(master, b"role-b")
    assert a != b
    assert crypto.derive_subkey(master, b"role-a") == a


def test_constant_time_equal():
    assert crypto.constant_time_equal(b"abc", b"abc")
    assert not crypto.constant_time_equal(b"abc", b"abd")


def test_empty_password_rejected():
    with pytest.raises(CryptoError):
        crypto.derive_kek(b"", crypto.new_salt(), crypto.KdfParams())
