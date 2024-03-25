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
