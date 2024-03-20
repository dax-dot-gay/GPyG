from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key1 = gpg.keys.generate_key("Bongus", passphrase="test")
    key2 = gpg.keys.generate_key("Bingus", passphrase="toast")
    key1.sign_key(key2, password="test", force=True)
    print(key2.model_dump_json(indent=4))
