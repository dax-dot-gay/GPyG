import os
import shutil
from tempfile import TemporaryDirectory
import time
from gpyg import GPG, StatusInteractive, ProcessSession

if os.path.exists("./tmp"):
    shutil.rmtree("./tmp")

os.makedirs("./tmp", exist_ok=True)
with TemporaryDirectory(dir="tmp", delete=False) as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    with gpg.smart_card() as card:
        if card.active:
            card.reset()
            card.change_pin("123456", "123457")
            card.unblock_pin_as_admin("12345678", "123456")
            card.change_admin_pin("12345678", "87654321")
            card.change_reset_code("87654321", "87654321")
            card.unblock_pin("87654321", "123456")
            # print(card.active.model_dump_json(indent=4))

    """gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    key_other = gpg.keys.generate_key("Bingus", passphrase="test")

    print("BONGUS:", key.fingerprint)
    print("BINGUS:", key_other.fingerprint)
    with key.edit(passphrase="test", run_as=key_other.fingerprint) as editor:
        print(editor.sign())

    key.reload()"""
