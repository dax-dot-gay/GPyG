import os
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


def test_sign_key(environment):
    keys = environment.keys.list_keys()
    keys[0].sign_key(keys[1], password="test-psk-0")
    assert len(keys[1].signatures) == 2


def test_subkeys_wrapped(environment):
    result = environment.keys.list_keys(key_type="secret")
    for key in result:
        assert key.subkeys[0].operator != None


def test_add_uid(environment):
    result = environment.keys.list_keys()[0]
    result.add_user_id(
        uid="Added Test User <atu@example.com> (Test Comment)", passphrase="test-psk-0"
    )
    result.add_user_id(
        name="Second Added Test User", email="satu@example.com", passphrase="test-psk-0"
    )
    assert len(result.user_ids) == 3
    assert "Added Test User <atu@example.com> (Test Comment)" in [
        i.uid for i in result.user_ids
    ]
    assert "Second Added Test User <satu@example.com>" in [
        i.uid for i in result.user_ids
    ]


def test_revoke_uid(environment):
    result = environment.keys.list_keys()[1]
    result.add_user_id(
        uid="Added Test User <atu@example.com> (Test Comment)", passphrase="test-psk-1"
    )
    assert len(result.user_ids) == 2
    result.revoke_uid(
        "Added Test User <atu@example.com> (Test Comment)", passphrase="test-psk-1"
    )
    assert len(result.user_ids) == 2
    assert result.user_ids[1].validity == "r"


def test_set_primary_uid(environment):
    key = environment.keys.list_keys()[3]

    key.add_user_id(uid="New Primary")
    assert len(key.user_ids) == 2
    key.set_primary_uid("New Primary")
    assert key.user_ids[0].uid == "New Primary"


def test_delete_key(environment):
    key = environment.keys.list_keys()[3]
    assert len(key.subkeys) == 1
    key.subkeys[0].delete()
    key.reload()
    assert len(key.subkeys) == 0


def test_import_key(environment):
    keys = environment.keys.list_keys()
    assert len(keys) == 4
    with open(os.path.join(environment.homedir, "export.asc"), "wb") as f:
        f.write(keys[0].export())

    keys[0].delete()
    assert len(environment.keys.list_keys()) == 3
    environment.keys.import_key(os.path.join(environment.homedir, "export.asc"))
    assert len(environment.keys.list_keys()) == 4
