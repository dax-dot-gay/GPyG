from gpyg import GPG
import shutil

shutil.rmtree("./tests/output")

gpg = GPG(homedir="./tests/output")
print(
    gpg.generate(
        key_type="RSA", key_length=1024, passphrase="test-psk", name_real="Dax Harris"
    )
)
