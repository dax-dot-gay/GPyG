from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    print(gpg.keys.generate_key("Bongus", passphrase="test").model_dump_json(indent=4))
