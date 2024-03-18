# Scratchpad for quick tests

import os
from gpyg import GPG

os.makedirs("./gpg", exist_ok=True)
with GPG(homedir="./gpg") as gpg:
    first = gpg.keys.generate_key(
        "Alice",
        key_type="RSA",
        key_length=2048,
        email="alice@lle.rochester.edu",
        passphrase="test-psk1",
    )

    second = gpg.keys.generate_key(
        "Bob",
        key_type="RSA",
        key_length=2048,
        email="bob@lle.rochester.edu",
        passphrase="test-psk2",
    )

    sec_first = gpg.keys.get_key(
        first.fingerprint,
        secret=True,
        include_signatures=True,
        include_signature_notations=True,
    )
    sec_second = gpg.keys.get_key(
        second.fingerprint,
        secret=True,
        include_signatures=True,
        include_signature_notations=True,
    )

    sec_first.sign(sec_second, expiration=10000, passphrase="test-psk2")

    print(
        gpg.keys.get_key(
            first.fingerprint, include_signatures=True, secret=True
        ).model_dump_json(indent=4)
    )
