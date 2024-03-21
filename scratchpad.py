from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory(dir="tmp", delete=False) as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test-signed")
    key_signer = gpg.keys.generate_key("Signer", passphrase="test-signer")
    key_signer.sign_key(key, password="test-signer")
    key.revoke_signature(key_signer, passphrase="test-signed")
    print(key.model_dump_json(indent=4))
