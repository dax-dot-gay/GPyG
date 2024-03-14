import os

try:
    raise Exception
except:
    from .bootstrap import bootstrap

    bootstrap(os.path.join(os.path.dirname(__file__), "gpgme"))
