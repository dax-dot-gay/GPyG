from gpyg import *


def test_key_generation(instance):
    result = instance.keys.generate_key(
        "Test User",
        email="test@example.com",
        comment="Test Comment",
        passphrase="test-psk",
    )
    assert result != None
    assert result.type == "public"
    assert len(result.subkeys) == 1


def test_pubkey_list(environment):
    result = environment.keys.list_keys()
    assert len(result) == 4
    assert all([r.type == "public" for r in result])
    assert all([len(r.subkeys) == 1 for r in result])


def test_seckey_list(environment):
    result = environment.keys.list_keys(key_type="secret")
    assert len(result) == 4
    assert all([r.type == "secret" for r in result])
    assert all([len(r.subkeys) == 1 for r in result])


def test_key_reload(environment):
    result = environment.keys.list_keys(key_type="secret")
    for key in result:
        previous = key.fingerprint
        assert previous == key.reload().fingerprint


def test_subkeys_wrapped(environment):
    result = environment.keys.list_keys(key_type="secret")
    for key in result:
        assert key.subkeys[0].operator != None
