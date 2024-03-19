import subprocess
from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    gpg.keys.generate_key("Bongus", passphrase="beenusususus")
    print([i.as_dict() for i in gpg.keys.list_keys()])
