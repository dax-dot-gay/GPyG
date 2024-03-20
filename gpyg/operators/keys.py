from datetime import date, datetime, timedelta
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
        """Generate a key given a set of parameters.

        Args:
            name (str): UID Name
            email (str | None, optional): Optional UID email. Defaults to None.
            comment (str | None, optional): Optional UID comment. Defaults to None.
            algorithm (str | None, optional): Algorithm name. Defaults to None.
            usage (list["sign" | "auth" | "encr" | "cert"] | None, optional): List of usages, or None for default. Defaults to None.
            expiration (datetime | timedelta | int | None, optional): Key expiration. Defaults to None.
            passphrase (str | None, optional): Key passphrase (if left empty, no passphrase). Defaults to None.
            force (bool, optional): Force creation. Defaults to False.

        Raises:
            ExecutionError: If key generation fails

        Returns:
            Returns the generated key
        """
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
        """List keys, optionally filtering by a pattern.

        Args:
            pattern (str | None, optional): Optional pattern to filter results by
            key_type (public | secret, optional): What key type to return
            check_sigs (bool, optional): Whether to check signatures or just list them

        Returns:
            List of results
        """

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
        """Gets a specific key given a fingerprint

        Args:
            fingerprint (str): Fingerprint to search for
            key_type (public | secret, optional): What key type to return. Defaults to "public".

        Returns:
            The located Key, or None if not found.
        """
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
        """Gets the internal ProcessSession instance

        Returns:
            ProcessSession: Internal session
        """
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
        """Reloads cached information from the keyring.

        Raises:
            RuntimeError: Fails if the key has been deleted or is otherwise inaccessible

        Returns:
            Key: A reference to the Key instance
        """
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
        """Exports a key in the given format.

        Args:
            mode (gpg | ascii, optional): Whether to output as GPG binary or ASCII armor. Defaults to "ascii".
            password (str | None, optional): Password required to unlock secret key, which may or may not be relevant. Defaults to None.
            filters (list[tuple[keep-uid | drop-subkey, str]], optional): List of export filters. For more information, see the GPG manual. Defaults to [].

            export_local_sigs (bool | None, optional): Allow exporting key signatures marked as "local". This is not generally useful unless a shared keyring scheme is being used. Defaults to no. Defaults to None.
            export_attributes (bool | None, optional): Include attribute user IDs (photo IDs) while exporting. Not including attribute user IDs is useful to export keys that are going to be used by an OpenPGP program that does not accept attribute user IDs. Defaults to yes. Defaults to None.
            export_sensitive_revkeys (bool | None, optional): Include designated revoker information that was marked as "sensitive". Defaults to no. Defaults to None.
            export_backup (bool | None, optional): Export for use as a backup. The exported data includes all data which is needed to restore the key or keys later with GnuPG. The format is basically the OpenPGP format but enhanced with GnuPG specific data. All other contradicting options are overridden. Defaults to None.
            export_clean (bool | None, optional): Compact (remove all signatures from) user IDs on the key being exported if the user IDs are not usable. Also, do not export any signatures that are not usable. This includes signatures that were issued by keys that are not present on the keyring. This option is the same as running the --edit-key command "clean" before export except that the local copy of the key is not modified. Defaults to no. Defaults to None.
            export_minimal (bool | None, optional): Export the smallest key possible. This removes all signatures except the most recent self-signature on each user ID. This option is the same as running the --edit-key command "minimize" before export except that the local copy of the key is not modified. Defaults to no. Defaults to None.
            export_revocs (bool | None, optional): Export only standalone revocation certificates of the key. This option does not export revocations of 3rd party certificate revocations. Defaults to None.
            export_dane (bool | None, optional): Instead of outputting the key material output OpenPGP DANE records suitable to put into DNS zone files. An ORIGIN line is printed before each record to allow diverting the records to the corresponding zone file. Defaults to None.
            mode1003 (bool | None, optional): Enable the use of a new secret key export format. This format avoids the re-encryption as required with the current OpenPGP format and also improves the security of the secret key if it has been protected with a passphrase. Note that an unprotected key is exported as-is and thus not secure; the general rule to convey secret keys in an OpenPGP encrypted file still applies with this mode. Versions of GnuPG before 2.4.0 are not able to import such a secret file. Defaults to None.

        Raises:
            ExecutionError: Raised if the attempted export operation fails.

        Returns:
            bytes: byte-encoded output.
        """
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

    def set_expiration(
        self,
        expiration: date | None = None,
        subkeys: list[str] | Literal["*"] | None = None,
        password: str | None = None,
    ) -> None:
        """Sets the expiration date of the current Key

        Args:
            expiration (date | None, optional): Expiration date, or None to remove expiration. Defaults to None.
            subkeys (list[str] | Literal[, optional): Which subkeys to apply to. Can be a list of fingerprints, "*", or None for just the primary key. Defaults to None.
            password (str | None, optional): Key password. Defaults to None.

        Raises:
            ExecutionError: Raised if the operation fails
        """
        cmd = "gpg --batch --pinentry-mode loopback --passphrase-fd 0 --quick-set-expire {fingerprint} {expiry} {targets}".format(
            fingerprint=self.fingerprint,
            expiry=expiration.isoformat() if expiration else "0",
            targets=(" ".join(subkeys) if subkeys != "*" else "'*'") if subkeys else "",
        )

        result = self.session.run(cmd, input=password + "\n" if password else None)
        if result.code == 0:
            self.reload()
            return
        raise ExecutionError(result.output)

    def is_protected(self) -> bool:
        """Checks if the current key is password-protected

        Returns:
            bool: True if protected, False otherwise
        """
        proc = self.session.run(
            f"gpg --dry-run --batch --passphrase-fd 0 --pinentry-mode loopback --passwd '{self.fingerprint}'",
            input="\n",
        )
        return "error" in proc.output

    def check_password(self, password: str) -> bool:
        """Checks whether the given password is valid for this key

        Args:
            password (str): Password to try

        Returns:
            bool: True if correct, False otherwise
        """
        if not self.is_protected():
            return True

        proc = self.session.run(
            f"gpg --dry-run --batch --passphrase-fd 0 --pinentry-mode loopback --passwd '{self.fingerprint}'",
            input=password + "\n",
        )
        return not "error" in proc.output

    def sign_key(
        self,
        target: "str | Key",
        users: list[str] | None = None,
        password: str | None = None,
        exportable: bool = True,
        force: bool = False,
    ):
        """Signs another key using the current key

        Args:
            target (str | Key): Key to sign
            users (list[str] | None, optional): Which users to sign. Defaults to None.
            password (str | None, optional): Password of current key, if needed. Defaults to None.
            exportable (bool, optional): Whether the signature should be exportable. Defaults to True.
            force (bool, optional): Whether to force signing. Defaults to False.

        Raises:
            ExecutionError: Raised if the operation fails.
        """
        if isinstance(target, Key):
            parsed_target = target.fingerprint
        else:
            parsed_target = target

        cmd = "gpg --batch --pinentry-mode loopback --passphrase-fd 0 -u {current} {force} --quick-{local}sign-key {fingerprint} {names}".format(
            current=self.fingerprint,
            force="--force-sign-key" if force else "",
            local="" if exportable else "l",
            fingerprint=parsed_target,
            names=" ".join(['"' + name + '"' for name in users]) if users else "",
        )
        proc = self.session.run(cmd, input=password + "\n" if password else None)
        if proc.code == 0:
            if isinstance(target, Key):
                target.reload()
        else:
            raise ExecutionError(proc.output)
