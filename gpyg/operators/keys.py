from datetime import datetime, timedelta
from typing import Literal
from .common import BaseOperator
from ..util import ExecutionError
from ..models import InfoLine, parse_infoline


class KeyOperator(BaseOperator):
    def generate_key(
        self,
        name: str,
        email: str | None = None,
        comment: str | None = None,
        algorithm: str | None = None,
        usage: list[Literal["sign", "auth", "encr", "cert"]] | None = None,
        expiration: datetime | timedelta | int | None = None,
        passphrase: str | None = None,
        force: bool = False,
    ):
        uid = "{name}{email}{comment}".format(name=name, email=f" <{email}> " if email else " ", comment=f"({comment})" if comment else "").strip()

        if isinstance(expiration, datetime):
            expire_str = expiration.isoformat()
        elif isinstance(expiration, timedelta):
            expire_str = "seconds=" + str(expiration.seconds)
        elif type(expiration) == int:
            expire_str = "seconds=" + str(expiration)
        else:
            expire_str = "none"

        command = "gpg {force} --batch --pinentry-mode loopback --passphrase {passphrase} --quick-gen-key '{uid}' {algo} {usage} {expire}".format(
            force="--yes" if force else "",
            passphrase="'" + passphrase + "'" if passphrase else "''",
            uid=uid,
            algo=algorithm if algorithm else "default",
            usage=",".join(usage) if usage else "default",
            expire=expire_str
        )
        proc = self.session.spawn(command)
        proc.wait()
        if "certificate stored" in proc.output:
            pass
        else:
            raise ExecutionError(proc.output)

    def list_keys(
        self,
        pattern: str = None,
        key_type: Literal["public", "secret"] = "public",
        include_fingerprint: bool = True,
        include_subkey_fingerprint: bool = True,
        include_keygrip: bool = True,
        include_signatures: bool = True,
    ) -> list[InfoLine]:
        args = [
            i
            for i in [
                "gpg",
                "--with-colons",
                "--with-fingerprint" if include_fingerprint else None,
                "--with-subkey-fingerprint" if include_subkey_fingerprint else None,
                "--with-keygrip" if include_keygrip else None,
                "--with-sig-check" if include_signatures else None,
                f"--list-{key_type}-keys",
                pattern,
            ]
            if i != None
        ]
        proc = self.session.spawn(args)
        proc.wait()

        lines = [i for i in proc.output.splitlines() if not i.startswith("gpg: ")]
        parsed = [parse_infoline(line) for line in lines]
        return parsed
