import os
import shutil
from tempfile import TemporaryDirectory
import time
from gpyg import GPG, Interactive, ProcessSession

if os.path.exists("./tmp"):
    shutil.rmtree("./tmp")

os.makedirs("./tmp", exist_ok=True)
with TemporaryDirectory(dir="tmp", delete=False) as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    key_other = gpg.keys.generate_key("Bingus", passphrase="test2")
    with ProcessSession() as session:
        with Interactive(
            session,
            f"gpg --command-fd 0 --status-fd 1 --homedir {tmpdir} -u {key_other.fingerprint} --pinentry-mode loopback --with-colons --edit-key {key.fingerprint}",
        ) as interact:
            for line in interact.readlines():
                if line != None:
                    print(line)
                    if b"keyedit.prompt" in line:
                        interact.writelines("list")

    """gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    key_other = gpg.keys.generate_key("Bingus", passphrase="test")

    print("BONGUS:", key.fingerprint)
    print("BINGUS:", key_other.fingerprint)
    with key.edit(passphrase="test", run_as=key_other.fingerprint) as editor:
        print(editor.sign())

    key.reload()"""
