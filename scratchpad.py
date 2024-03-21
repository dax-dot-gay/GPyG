import os
import shutil
from tempfile import TemporaryDirectory
import time
from gpyg import GPG

if os.path.exists("./tmp"):
    shutil.rmtree("./tmp")

os.makedirs("./tmp", exist_ok=True)
with TemporaryDirectory(dir="tmp", delete=False) as tmpdir:
    gpg = GPG(homedir=tmpdir, kill_existing_agent=True)
    key = gpg.keys.generate_key("Bongus", passphrase="test")
    with key.edit(passphrase="test") as editor:
        print(editor.execute("passwd", editor.passphrase + "wrong", "new-pass"))
