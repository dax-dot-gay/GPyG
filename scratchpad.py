import datetime
from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    print(key.is_protected())
    print(key.check_password("test"))
    print(key.check_password("beans"))
