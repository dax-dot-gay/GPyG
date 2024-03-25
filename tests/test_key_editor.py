def test_instance_working(interactive):
    editor, signee, signer = interactive
    assert editor.key.fingerprint == signee.fingerprint
    assert len(editor.list()) > 0


def test_sign(interactive):
    editor, signee, signer = interactive
    assert len(signee.signatures) == 1
    editor.sign(signer_passphrase="signer")
    editor.save()
    signee.reload()
    assert len(signee.signatures) == 2


def test_delete_sign(interactive):
    editor, signee, signer = interactive
    assert len(signee.signatures) == 1
    editor.sign(signer_passphrase="signer")
    editor.set_uid("1")
    editor.set_key("1")
    editor.delete_signature(signer)
    editor.save()
    signee.reload()
    assert len(signee.signatures) == 1


def test_add_uid(interactive):
    editor, signee, signer = interactive
    assert len(signee.user_ids) == 1
    editor.add_uid("OtherSignee", passphrase="signee")
    editor.save()
    signee.reload()
    assert len(signee.user_ids) == 2


def test_delete_uid(interactive):
    editor, signee, signer = interactive
    assert len(signee.user_ids) == 1
    editor.add_uid("OtherSignee", passphrase="signee")
    editor.set_uid(2)
    editor.delete_uid()
    editor.save()
    signee.reload()
    assert len(signee.user_ids) == 1


def test_delete_key(interactive):
    editor, signee, signer = interactive
    assert len(signee.subkeys) > 0
    editor.set_key("1")
    editor.delete_key()
    editor.save()
    signee.reload()
    assert len(signee.subkeys) == 0
