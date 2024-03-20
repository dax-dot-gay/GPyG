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


def test_expire_key(environment):
    result = environment.keys.list_keys()[0]
    result.set_expiration(expiration=datetime.date(2026, 1, 1), password="test-psk-0")
    assert result.expiration_date.date() == datetime.date(2026, 1, 1)


def test_key_passwords(environment):
    keys = environment.keys.list_keys()
    has_pass = keys[0]
    no_pass = keys[2]
    assert has_pass.is_protected()
    assert has_pass.check_password("test-psk-0")
    assert not has_pass.check_password("test-psk-2")

    assert not no_pass.is_protected()
    assert no_pass.check_password("wrong")
