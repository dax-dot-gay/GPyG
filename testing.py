from gpyg import GPG
from gpyg.gpg.edit_key import AddKeyType
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
    print(keys)
