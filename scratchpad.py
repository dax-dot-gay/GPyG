import subprocess
from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    gpg.keys.generate_key("Bongus", passphrase="beenusususus")
    subprocess.run(["gpg", "--homedir", tmpdir, "-k"])