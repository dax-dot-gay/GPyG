# Scratchpad for quick tests

import os
from gpyg import GPG, UserID

os.makedirs("./gpg", exist_ok=True)
with GPG(homedir="./gpg") as gpg:
    print(
        gpg.keys.create_key(
            UserID(name="Dax Harris", email="dharr@lle.rochester.edu"),
            algorithm="rsa3072",
            expiration=None,
            force=True,
            passphrase="test-psk",
        )
    )
