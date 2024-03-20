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


def test_export(environment):
    result = environment.keys.list_keys()
    exported = result[0].export()
    assert exported.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert exported.endswith(b"-----END PGP PUBLIC KEY BLOCK-----")

    result = environment.keys.list_keys(key_type="secret")
    exported = result[0].export(password="test-psk-0")
    assert exported.startswith(b"-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert exported.endswith(b"-----END PGP PRIVATE KEY BLOCK-----")
