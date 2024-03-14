import logging
import os
import shlex
import subprocess
import sys


def build(source: str, output: str):
    logging.info("Building GPGME...")
    os.makedirs(output, exist_ok=True)

    result = subprocess.Popen(
        f"./configure --prefix {output}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=source,
    )
    full_stdout = b""
    while True:
        line = result.stdout.readline()
        if line:
            logging.debug(line.decode().strip())
            full_stdout += line
        else:
            break
    if not "configured as follows" in full_stdout.decode():
        raise RuntimeError("Failed to configure GPGME.")

    make_result = subprocess.Popen(
        "make", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=source, shell=True
    )

    while True:
        line = make_result.stdout.readline()
        if line:
            logging.debug(line.decode().strip())
        else:
            break

    make_install_result = subprocess.Popen(
        "make install",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=source,
        shell=True,
    )
    while True:
        line = make_install_result.stdout.readline()
        if line:
            logging.debug(line.decode().strip())
        else:
            break
