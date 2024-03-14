from bz2 import decompress
import logging
import os
import shlex
import subprocess
from tarfile import TarFile
from .constants import *
from requests import get


def download_files(cache: str) -> tuple[str, str, str]:
    if not os.path.exists(
        os.path.join(cache, f"gpgme_archive_{GPGME_VERSION}.tar.bz2")
    ):
        response = get(TARBALL_BASE.format(version=GPGME_VERSION), stream=True)
        response.raise_for_status()
        with open(
            os.path.join(cache, f"gpgme_archive_{GPGME_VERSION}.tar.bz2"), "wb"
        ) as tarball:
            for chunk in response.iter_content(chunk_size=None):
                tarball.write(chunk)

    if not os.path.exists(
        os.path.join(cache, f"gpgme_signature_{GPGME_VERSION}.tar.bz2.sig")
    ):
        response = get(TARBALL_SIG.format(version=GPGME_VERSION), stream=True)
        response.raise_for_status()
        with open(
            os.path.join(cache, f"gpgme_signature_{GPGME_VERSION}.tar.bz2.sig"), "wb"
        ) as signature:
            for chunk in response.iter_content(chunk_size=None):
                signature.write(chunk)

    if not os.path.exists(os.path.join(cache, "gpg_sig.asc")):
        response = get(GPG_SIGNING_KEY, stream=True)
        response.raise_for_status()
        with open(os.path.join(cache, "gpg_sig.asc"), "wb") as signing:
            for chunk in response.iter_content(chunk_size=None):
                signing.write(chunk)

    return (
        f"gpgme_archive_{GPGME_VERSION}.tar.bz2",
        f"gpgme_signature_{GPGME_VERSION}.tar.bz2.sig",
        "gpg_sig.asc",
    )


def verify(cache: str, tarball: str, signature: str, signing_key: str) -> bool:
    key_result = subprocess.run(
        shlex.split(f"gpg --import {os.path.join(cache, signing_key)}"),
        capture_output=True,
    )
    if key_result.returncode != 0:
        raise RuntimeError("Failed to download GPG signing key.")

    result = subprocess.run(
        shlex.split(
            VERIFY_CMD.format(
                signature=os.path.join(cache, signature),
                tarball=os.path.join(cache, tarball),
            )
        ),
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Failed to verify sources.")
    if not "good signature" in result.stderr.decode().lower():
        raise RuntimeError("Failed to verify sources.")
    return True


def extract_source(cache: str, tarball: str):
    os.makedirs(os.path.join(cache, "source"), exist_ok=True)
    with open(os.path.join(cache, tarball), "rb") as compressed_source:
        with open(os.path.join(cache, "intermediate.tar"), "wb") as intermediate:
            intermediate.write(decompress(compressed_source.read()))

    with TarFile(os.path.join(cache, "intermediate.tar")) as archive:
        archive.extractall(path=os.path.join(cache, "source"), filter="fully_trusted")

    os.remove(os.path.join(cache, "intermediate.tar"))


def acquire_source(cache: str):
    logging.info("Downloading & verifying sources...")
    tarball, signature, signing_key = download_files(cache)
    verify(cache, tarball, signature, signing_key)
    logging.info(f"Sources downloaded (v{GPGME_VERSION}) & verified.")
    extract_source(cache, tarball)
