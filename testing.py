from gpyg import GPG
import shutil

shutil.rmtree("./tests/output")

gpg = GPG(homedir="./tests/output")
generated = gpg.generate(
    key_type="RSA",
    key_length=1024,
    passphrase="test-psk",
    name_real="Dax Harris",
    name_comment="Test Comment",
    name_email="dharr@lle.rochester.edu",
)
print(generated.info.fingerprint)
with generated.edit() as editor:
    keys, users = editor.list()
    print(users)
    editor.add_user_id("Bongus Wongus", email="bongo@gmail.com", comment="Test comment")
    keys, users = editor.list()
    print(users)
    editor.revoke_user_id(2, description="i hate u")
    keys, users = editor.list()
    print(users)
    editor.quit()
