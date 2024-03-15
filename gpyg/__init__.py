import json
import os

try:
    from .gpgme import *
except:
    from .bootstrap import bootstrap

    bootstrap(
        os.path.join(os.path.dirname(__file__), "gpgme.prefix"),
        os.path.join(os.path.dirname(__file__), "gpgme"),
    )
    from .gpgme import *
