import json
import subprocess
from tempfile import TemporaryDirectory
from gpyg import GPG

with TemporaryDirectory() as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    print(gpg.keys.generate_key("Bongus", passphrase="beenusususus"))
    print(
        json.dumps(
            [i.model_dump(mode="json") for i in gpg.keys.list_keys(key_type="secret")],
            indent=4,
        )
    )
