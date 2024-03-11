import datetime
import os
from tempfile import NamedTemporaryFile, TemporaryDirectory
from ..util import SubprocessResult, SubprocessSession
import psutil
import stat
from .models import KeyGenerationResult


class GPG:
    def __init__(self, homedir: str = None):
        self.homedir = homedir
        for ps in [
            i
            for i in psutil.process_iter(attrs=["pid", "name"])
            if i.info["name"] == "gpg-agent"
        ]:
            try:
                ps.kill()
            except:
                pass

        if homedir and not os.path.exists(homedir):
            os.makedirs(homedir, exist_ok=True)

        try:
            os.chmod(
                homedir,
                stat.S_IREAD
                | stat.S_IWRITE
                | stat.S_IEXEC
                | stat.S_ISUID
                | stat.S_ISGID,
            )
        except:
            pass
        self.session = SubprocessSession(
            environment={"GNUPGHOME": os.path.realpath(homedir)} if homedir else None,
            working_directory=homedir,
            shell=True,
        )

    @classmethod
    def create_temporary(self) -> "GPG":
        tempdir = TemporaryDirectory(delete=False)
        return GPG(homedir=tempdir.name)

    def generate(
        self,
        key_type: str = "default",
        key_length: int = None,
        key_curve: str = None,
        key_grip: str = None,
        key_usage: list[str] = None,
        subkey_type: str = None,
        subkey_length: int = None,
        subkey_curve: str = None,
        subkey_usage: list[str] = None,
        passphrase: str = None,
        name_real: str = None,
        name_comment: str = None,
        name_email: str = None,
        expire_date: str | datetime.date = None,
        creation_date: datetime.date = None,
        preferences: str = None,
        revoker: str = None,
        keyserver: str = None,
        handle: str = None,
    ) -> KeyGenerationResult:
        with NamedTemporaryFile(mode="w+") as params:
            params.write("%echo Generating GPG key...\n")
            if not passphrase:
                params.write("%no-protection\n")

            params.write(f"Key-Type: {key_type}\n")
            if key_length:
                params.write(f"Key-Length: {key_length}\n")
            if key_curve:
                params.write(f"Key-Curve: {key_curve}\n")
            if key_grip:
                params.write(f"Key-Grip: {key_grip}\n")
            if key_usage:
                params.write(f"Key-Usage: {','.join(key_usage)}\n")
            if subkey_type:
                params.write(f"Subkey-Type: {subkey_type}\n")
            if subkey_length:
                params.write(f"Subkey-Length: {subkey_length}\n")
            if subkey_curve:
                params.write(f"Subkey-Curve: {subkey_curve}\n")
            if subkey_usage:
                params.write(f"Subkey-Usage: {','.join(subkey_usage)}\n")
            if passphrase:
                params.write(f"Passphrase: {passphrase}\n")
            if name_real:
                params.write(f"Name-Real: {name_real}\n")
            if name_comment:
                params.write(f"Name-Comment: {name_comment}\n")
            if name_email:
                params.write(f"Name-Email: {name_email}\n")
            if expire_date:
                if issubclass(expire_date, datetime.date):
                    params.write(f"Expire-Date: {expire_date.isoformat()}\n")
                else:
                    params.write(f"Expire-Date: {expire_date}\n")
            if creation_date:
                params.write(f"Creation-Date: {creation_date.isoformat()}\n")
            if preferences:
                params.write(f"Preferences: {preferences}")
            if revoker:
                params.write(f"Revoker: {revoker}\n")
            if keyserver:
                params.write(f"Keyserver: {keyserver}\n")
            if handle:
                params.write(f"Handle: {handle}")

            params.write("%commit\n")
            params.seek(0)
            process = self.session.run_command(
                f"gpg --batch -v --fingerprint --generate-key {params.name}"
            )
            try:
                fingerprint = os.path.splitext(
                    os.path.split(
                        (
                            process.wait_for("revocation certificate stored as")
                            .decode()
                            .strip()
                            .split("'")[1]
                        )
                    )[1]
                )[0]
            except:
                fingerprint = None

            try:
                process.wait(timeout=10)
            except:
                pass

            return KeyGenerationResult(
                fingerprint=fingerprint,
                homedir=os.path.realpath(self.homedir) if self.homedir else None,
                output=process.output.decode(),
                code=process.returncode,
            )
