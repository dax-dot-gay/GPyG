from tempfile import NamedTemporaryFile
from typing import Literal
from .common import BaseOperator
from .keys import Key
from ..util import ExecutionError


class MessageOperator(BaseOperator):
    def encrypt(
        self,
        data: bytes,
        *recipients: Key | str,
        compress: bool = True,
        format: Literal["ascii", "pgp"] = "ascii",
    ) -> bytes:
        """Encrypt a message to at least one recipient

        Args:
            data (bytes): Data to encrypt
            compress (bool, optional): Whether to compress data. Defaults to True.
            format (ascii | pgp, optional): What format to output. Defaults to "ascii".

        Raises:
            ValueError: If no recipients were specified

        Returns:
            bytes: Encrypted data
        """
        if len(recipients) == 0:
            raise ValueError("Must specify at least one recipient")
        parsed_recipients = " ".join(
            [f"-r {r.key_id if isinstance(r, Key) else r}" for r in recipients]
        )
        cmd = (
            "gpg {compress} --batch --encrypt {recipients} {armored} --output -".format(
                compress="-z 0" if not compress else "",
                recipients=parsed_recipients,
                armored="--armor" if format == "ascii" else "",
            )
        )
        result = self.session.run(cmd, decode=False, input=data)
        if result.code == 0:
            return result.output
        raise ExecutionError(f"Failed to encrypt:\n{result.output}")

    def decrypt(
        self, data: bytes, key: Key | None = None, passphrase: str | None = None
    ) -> bytes:
        """Decrypt PGP-encrypted data

        Args:
            data (bytes): Data to decrypt
            key (Key | None, optional): Recipient key. Defaults to None
            passphrase (str | None, optional): Passphrase, if required. Defaults to None.

        Raises:
            ExecutionError: If the operation fails

        Returns:
            bytes: Decrypted data (with header info removed)
        """
        with NamedTemporaryFile() as datafile:
            datafile.write(data)
            datafile.seek(0)
            cmd = f"gpg {'-u ' + key.fingerprint if key else ''} --batch --pinentry-mode loopback --passphrase-fd 0 --output - --decrypt {datafile.name}"
            result = self.session.run(
                cmd, decode=False, input=passphrase + "\n" if passphrase else None
            )
        if result.code == 0:
            return result.output.split(b"\n", maxsplit=2)[-1]
        raise ExecutionError(f"Failed to decrypt:\n{result.output}")

    def encrypt_symmetric(
        self,
        data: bytes,
        passphrase: str,
        algo: str = "AES",
        format: Literal["ascii", "pgp"] = "ascii",
    ) -> bytes:
        """Symmetrically encrypt data with <algo> and <passphrase>

        Args:
            data (bytes): Data to encrypt
            passphrase (str): Passphrase to use
            algo (str, optional): Algorithm selection. Defaults to "AES".
            format (ascii | pgp, optional): Output format. Defaults to "ascii".

        Raises:
            ExecutionError: If operation fails

        Returns:
            bytes: Encrypted data
        """
        with NamedTemporaryFile() as datafile:
            datafile.write(data)
            datafile.seek(0)
            result = self.session.run(
                f"gpg {'--armor' if format == 'ascii' else ''} --cipher-algo {algo} --output - --passphrase-fd 0 --pinentry-mode loopback --symmetric {datafile.name}",
                decode=False,
                input=passphrase,
            )

            if result.code == 0:
                return result.output
            raise ExecutionError(f"Failed to encrypt:\n{result.output}")

    def get_recipients(
        self,
        data: bytes,
        translate: bool = True,
        include: list[Literal["known", "unknown"]] = ["known", "unknown"],
    ) -> list[Key | str]:
        """Gets all recipients associated with an encrypted message

        Args:
            data (bytes): Encrypted message
            translate (bool, optional): Whether to find existing keys
            include (list[known | unknown], optional): Which keys to include (keys that are known vs keys that are not). Defaults to ["known", "unknown"].

        Raises:
            ExecutionError: If operation fails

        Returns:
            list[Key | str]: List of Key objects or, if none match, key IDs
        """
        with NamedTemporaryFile() as datafile:
            datafile.write(data)
            datafile.seek(0)
            cmd = f"gpg -d --list-only -v {datafile.name}"
            result = self.session.run(cmd)
        if result.code == 0:
            key_ids = [
                i.split()[-1] for i in result.output.split("\n") if "public key is" in i
            ]
            if translate:
                keys = []
                for i in key_ids:
                    existing = self.gpg.keys.get_key(i)
                    if i:
                        if "known" in include:
                            keys.append(existing)
                    else:
                        if "unknown" in include:
                            keys.append(i)

                return keys
            else:
                return key_ids
        raise ExecutionError(f"Failed to get recipients:\n{result.output}")

    def sign(
        self,
        data: bytes,
        key: Key,
        mode: Literal["standard", "clear", "detach"] = "standard",
        passphrase: str | None = None,
        format: Literal["ascii", "pgp"] = "ascii",
    ) -> bytes:
        """Signs data with the specified key.

        Args:
            data (bytes): Data to sign
            key (Key): Key to sign with
            mode (standard | clear | detach, optional): What kind of signature to create. Defaults to "standard".
            passphrase (str | None, optional): Key passphrase, if required. Defaults to None.
            format (ascii | pgp, optional): Output format. Defaults to "ascii".

        Raises:
            ExecutionError: If the operation fails

        Returns:
            bytes: Signed data/detached signature
        """
        with NamedTemporaryFile() as datafile:
            datafile.write(data)
            datafile.seek(0)
            cmd = "gpg --default-key {key} --batch --yes --pinentry-mode loopback {format} --passphrase-fd 0 -o - {operation} {file}".format(
                key=key.key_id,
                format="--armor" if format == "ascii" else "",
                operation={
                    "standard": "--sign",
                    "clear": "--clear-sign",
                    "detach": "--detach-sign",
                }[mode],
                file=datafile.name,
            )
            result = self.session.run(
                cmd, decode=False, input=passphrase + "\n" if passphrase else None
            )
            if result.code == 0:
                return b"\n".join(
                    [
                        i
                        for i in result.output.splitlines()
                        if not i.startswith(b"gpg: ")
                    ]
                )
            raise ExecutionError(f"Failed to sign message:\n{result.output}")

    def verify(
        self,
        data: bytes,
        signature: bytes | None = None,
    ) -> list[tuple[str, str]]:
        """Gets a list of signatures on the given data, with an optional detached signature

        Args:
            data (bytes): Data, or in the case that `signature` is not specified, signed data.
            signature (bytes | None, optional): A detached signature. Defaults to None.

        Returns:
            list[tuple[str, str]]: List of `(Key ID, User ID)` records
        """
        with NamedTemporaryFile() as datafile:
            datafile.write(data)
            datafile.seek(0)
            if signature:
                with NamedTemporaryFile() as sigfile:
                    sigfile.write(signature)
                    sigfile.seek(0)
                    cmd = f"gpg --status-fd 1 --batch -v --verify {sigfile.name} {datafile.name}"
                    result = self.session.run(cmd)
            else:
                cmd = f"gpg --status-fd 1 --batch -v --verify {datafile.name}"
                result = self.session.run(cmd)
        return [
            (i.split(" ")[2], i.split(" ", maxsplit=3)[3])
            for i in result.output.splitlines()
            if i.startswith("[GNUPG:] GOODSIG")
        ]
