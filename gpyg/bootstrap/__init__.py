import logging
import os
from tempfile import TemporaryDirectory

from .constants import GPGME_VERSION
from .acquire_source import acquire_source
from .build import build


def bootstrap(target: str):
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Bootstrapping GPGME...")
    os.makedirs("./cache", exist_ok=True)
    with TemporaryDirectory() as cache:
        acquire_source("./cache")
        build(
            os.path.join("./cache", "source", f"gpgme-{GPGME_VERSION}"),
            target,
        )


if __name__ == "__main__":
    bootstrap()
