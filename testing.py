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
print(gpg.get_key(generated.fingerprint))
print(gpg.get_key(generated.fingerprint, secret=True))
