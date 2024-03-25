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
                compress="-z 0" if compress else "",
                recipients=parsed_recipients,
                armored="--armor" if format == "ascii" else "",
            )
        )
        result = self.session.run(cmd, decode=False, input=data)
        if result.code == 0:
            return result.output
        raise ExecutionError(f"Failed to encrypt:\n{result.output}")

    def decrypt(self, data: bytes, key: Key, passphrase: str | None = None) -> bytes:
        """Decrypt PGP-encrypted data

        Args:
            data (bytes): Data to decrypt
            key (Key): Recipient key
            passphrase (str | None, optional): Recipient passphrase, if present. Defaults to None.

        Raises:
            ExecutionError: If the operation fails

        Returns:
            bytes: Decrypted data (with header info removed)
        """
        with NamedTemporaryFile() as datafile:
            datafile.write(data)
            datafile.seek(0)
            cmd = f"gpg -u {key.fingerprint} --batch --pinentry-mode loopback --passphrase-fd 0 --output - --decrypt {datafile.name}"
            result = self.session.run(
                cmd, decode=False, input=passphrase + "\n" if passphrase else None
            )
        if result.code == 0:
            return result.output.split(b"\n", maxsplit=2)[-1]
        raise ExecutionError(f"Failed to decrypt:\n{result.output}")

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
