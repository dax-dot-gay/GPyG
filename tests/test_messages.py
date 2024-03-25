from gpyg import *


def test_encryption(smallenv):
    env, key = smallenv
    DATA = b"test-data"
    encrypted = env.messages.encrypt(b"test-data", key)
    assert encrypted != DATA
    decrypted = env.messages.decrypt(encrypted, key, passphrase="user")
    assert decrypted == DATA


def test_recipients(smallenv):
    env, key = smallenv
    DATA = b"test-data"
    encrypted = env.messages.encrypt(b"test-data", key)
    assert encrypted != DATA

    recipients = env.messages.get_recipients(encrypted)
    assert len(recipients) == 1
    assert isinstance(recipients[0], Key)
    assert recipients[0].key_id == key.key_id


def test_sign(smallenv):
    env, key = smallenv
    DATA = b"test-data"
    encrypted = env.messages.encrypt(b"test-data", key)
    assert encrypted != DATA
    signed = env.messages.sign(encrypted, key, passphrase="user")
    assert signed != encrypted
    verification = env.messages.verify(signed)
    assert len(verification) > 0
    assert verification[0][0] == key.key_id


def test_symmetric(smallenv):
    env, key = smallenv
    DATA = b"test-data"
    encrypted = env.messages.encrypt_symmetric(DATA, "test")
    assert encrypted != DATA
    decrypted = env.messages.decrypt(encrypted, passphrase="test")
    assert decrypted == DATA
