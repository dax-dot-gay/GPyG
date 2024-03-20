from datetime import datetime, timedelta
from typing import Literal

from pydantic import Field, PrivateAttr
from .common import BaseOperator
from ..util import ExecutionError, ProcessSession
from ..models import InfoLine, parse_infoline, KeyModel


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
    ) -> "Key | None":
        uid = "{name}{email}{comment}".format(
            name=name,
            email=f" <{email}> " if email else " ",
            comment=f"({comment})" if comment else "",
        ).strip()

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
            expire=expire_str,
        )
        proc = self.session.spawn(command)
        proc.wait()
        if "certificate stored" in proc.output.strip().split("\n")[-1]:
            return self.list_keys(
                pattern=proc.output.strip().split("\n")[-1].split("/")[-1].split(".")[0]
            )[0]
        else:
            raise ExecutionError(proc.output)

    def list_keys(
        self,
        pattern: str = None,
        key_type: Literal["public", "secret"] = "public",
        check_sigs: bool = True,
    ) -> list["Key"]:
        args = [
            i
            for i in [
                "gpg",
                "--with-colons",
                "--with-fingerprint",
                "--with-subkey-fingerprint",
                "--with-keygrip",
                "--with-sig-check" if check_sigs else "--with-sig-list",
                f"--list-{key_type}-keys",
                pattern,
            ]
            if i != None
        ]
        proc = self.session.spawn(args)
        proc.wait()

        lines = [i for i in proc.output.splitlines() if not i.startswith("gpg: ")]
        parsed = [parse_infoline(line) for line in lines]
        return Key.from_infolines(self, parsed)

    def get_key(
        self, fingerprint: str, key_type: Literal["public", "secret"] = "public"
    ) -> "Key | None":
        results = self.list_keys(pattern=fingerprint, key_type=key_type)
        if len(results) == 0:
            return None

        return results[0]


class Key(KeyModel):
    operator: KeyOperator = Field(exclude=True)
    subkeys: list["Key"] = []
    model_config = {"arbitrary_types_allowed": True}

    @property
    def session(self) -> ProcessSession:
        return self.operator.session

    @staticmethod
    def apply(operator: KeyOperator, model: KeyModel) -> "Key":
        model.subkeys = [Key.apply(operator, i) for i in model.subkeys][:]
        return Key(operator=operator, **dict(model))

    @classmethod
    def from_infolines(
        cls, operator: KeyOperator, lines: list[InfoLine]
    ) -> list["Key"]:
        return [Key.apply(operator, i) for i in super().from_infolines(lines)]

    def reload(self) -> "Key":
        result = self.operator.get_key(self.fingerprint, key_type=self.type)
        if result:
            for name, value in result.__dict__.items():
                setattr(self, name, value)
        else:
            raise RuntimeError(
                "This key has been deleted/is no longer able to be referenced."
            )

        return self

    def export(
        self,
        mode: Literal["gpg", "ascii"] = "ascii",
        password: str | None = None,
        filters: list[tuple[Literal["keep-uid", "drop-subkey"], str]] = [],
        export_local_sigs: bool | None = None,
        export_attributes: bool | None = None,
        export_sensitive_revkeys: bool | None = None,
        export_backup: bool | None = None,
        export_clean: bool | None = None,
        export_minimal: bool | None = None,
        export_revocs: bool | None = None,
        export_dane: bool | None = None,
        mode1003: bool | None = None,
    ) -> bytes:
        options = dict(
            export_local_sigs=export_local_sigs,
            export_attributes=export_attributes,
            export_sensitive_revkeys=export_sensitive_revkeys,
            export_backup=export_backup,
            export_clean=export_clean,
            export_minimal=export_minimal,
            export_revocs=export_revocs,
            export_dane=export_dane,
            mode1003=mode1003,
        )

        cmd = "gpg{format} --pinentry-mode loopback --batch{passphrase} --export-options '{options}' {filters} --export{secret} {fingerprint}".format(
            format=" --armor" if mode == "ascii" else "",
            secret="-secret-keys" if self.type == "secret" else "",
            fingerprint=self.fingerprint,
            passphrase=" --passphrase-fd 0" if password else "",
            options=",".join(
                [
                    ("" if v else "no-") + k.replace("_", "-")
                    for k, v in options.items()
                    if v != None
                ]
            ),
            filters=(
                " ".join(
                    ["--export-filter " + name + "=" + expr for name, expr in filters]
                )
                if len(filters) > 0
                else ""
            ),
        )

        result = self.session.run(
            cmd, decode=False, input=password + "\n" if password else None
        )
        if result.code == 0:
            return result.output.strip()
        raise ExecutionError(result.output.decode())
