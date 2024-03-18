# Scratchpad for quick tests

import os
from gpyg import GPG

os.makedirs("./gpg", exist_ok=True)
with GPG(homedir="./gpg") as gpg:
    print(
        gpg.keys.generate_key(
            "Dax Harris",
            key_type="RSA",
            key_length=2048,
            email="dharr@lle.rochester.edu",
            passphrase="test-psk",
        )
    )
