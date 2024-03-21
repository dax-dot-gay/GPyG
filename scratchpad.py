from tempfile import TemporaryDirectory
import time
from gpyg import GPG

with TemporaryDirectory(dir="tmp", delete=False) as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    key.add_user_id(uid="New Prime", passphrase="test")
    key.set_primary_uid("New Prime", passphrase="test")
    print(key.model_dump_json(indent=4))
