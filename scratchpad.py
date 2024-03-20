from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    key.add_subkey(password="test", key_passphrase="test-sub")
    print(key.model_dump_json(indent=4))
