from __future__ import annotations

import pytest

from securesync import keystore
from securesync.errors import CryptoError


def test_create_and_unlock():
    kf, master = keystore.create_keyfile(b"hunter2")
    assert keystore.unlock(kf, b"hunter2") == master


def test_wrong_password_fails():
    kf, _ = keystore.create_keyfile(b"hunter2")
    with pytest.raises(CryptoError):
        keystore.unlock(kf, b"wrong-password")


def test_keyfile_json_roundtrip():
    kf, master = keystore.create_keyfile(b"pw")
    restored = keystore.KeyFile.from_json(kf.to_json())
    assert keystore.unlock(restored, b"pw") == master


def test_change_password_preserves_master_key():
    kf, master = keystore.create_keyfile(b"old-pw")
    kf2 = keystore.rewrap(kf, b"old-pw", b"new-pw")
    assert keystore.unlock(kf2, b"new-pw") == master
    with pytest.raises(CryptoError):
        keystore.unlock(kf2, b"old-pw")


def test_keyfile_has_no_plaintext_key():
    kf, master = keystore.create_keyfile(b"pw")
    raw = kf.to_json()
    assert master not in raw
