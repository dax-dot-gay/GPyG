import logging
import os
import platform
from re import L
import shutil
import sys
from tempfile import TemporaryDirectory

from .constants import GPGME_VERSION
from .acquire_source import acquire_source
from .build import build


def codegen(library: str):
    ENUM_TEMPLATE = """
class {namespace}{etype}(IntEnum):
{members}
    """

    from ..gpgme import gpgme

    enums = [i for i in dir(gpgme) if i.startswith("GPG_") or i.startswith("GPGME_")]

    resolved: dict[str, dict[str, dict[str, int]]] = {}
    for e in enums:
        parts = e.split("_", maxsplit=2)
        if len(parts) == 3:
            namespace, etype, name = parts
            if not namespace in resolved.keys():
                resolved[namespace] = {}

            if not etype in resolved[namespace].keys():
                resolved[namespace][etype] = {}

            resolved[namespace][etype][name] = getattr(gpgme, e)

    with open(os.path.join(library, "__init__.py"), "w") as output:
        with open(
            os.path.join(os.path.dirname(__file__), "init.template.py"), "r"
        ) as template:
            enum_strings = []
            for namespace, types in resolved.items():
                for etype, members in types.items():
                    if len(members.keys()) > 1:
                        enum_strings.append(
                            ENUM_TEMPLATE.format(
                                namespace=namespace.title(),
                                etype=etype.title(),
                                members="\n".join(
                                    [
                                        "    " + key + " = " + str(value)
                                        for key, value in members.items()
                                    ]
                                ),
                            )
                        )

            output.write(template.read().format(enums="\n\n".join(enum_strings)))


def bootstrap(prefix: str, library: str):
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Bootstrapping GPGME...")
    with TemporaryDirectory() as cache:
        acquire_source(cache)
        build(
            os.path.join(cache, "source", f"gpgme-{GPGME_VERSION}"),
            prefix,
        )
        os.makedirs(library, exist_ok=True)
        for path in [
            "_gpgme.py",
            "gpgme.py",
            f"_gpgme.{sys.implementation.cache_tag}-{sys.implementation._multiarch}.so",
        ]:
            shutil.copy(
                os.path.join(
                    prefix,
                    "lib",
                    f"python{sys.version_info.major}.{sys.version_info.minor}",
                    "site-packages",
                    f"gpg-{GPGME_VERSION}-py{sys.version_info.major}.{sys.version_info.minor}-{sys.platform}-{platform.machine()}.egg",
                    "gpg",
                    path,
                ),
                os.path.join(library, path),
            )
    codegen(library)


if __name__ == "__main__":
    bootstrap()
