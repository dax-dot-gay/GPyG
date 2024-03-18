from gpyg import GPG


def test_generate(homed_context):
    result = homed_context.keys.generate_key(
        "test-name",
        email="test-email",
        key_type="RSA",
        key_length=3072,
        passphrase="test-psk",
    )
    assert len(result.uids) == 1
    uid = result.uids[0]
    assert uid.name == "test-name"
    assert uid.email == "test-email"
    assert result.fingerprint


def test_list(session):
    keys = session.keys.list_keys()
    assert len(keys) == 3
    assert all([len(i.uids) == 1 for i in keys])

    keys = session.keys.list_keys(secret=True)
    assert len(keys) == 3
    assert all([len(i.uids) == 1 for i in keys])


def test_get(session):
    keys = session.keys.list_keys()
    assert len(keys) == 3

    result = session.keys.get_key(keys[0].fingerprint)
    assert result.fingerprint == keys[0].fingerprint
    assert result == keys[0]
