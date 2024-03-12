from contextlib import contextmanager
import re
from tempfile import NamedTemporaryFile
from typing import Any, ContextManager, Generator, Literal
from .models import GPGError, KeyInfo, PublicKeyAlgorithms as PK
from ..util import SubprocessResult, SubprocessSession
from .edit_key import KeyEditor


class KeyManager:
    def __init__(self, info: KeyInfo, session: SubprocessSession, password: str | None = None):
        self.info = info
        self.session = session
        self.password = password

    @property
    def dict(self) -> dict:
        return self.info.model_dump()

    @property
    def json(self) -> dict:
        return self.info.model_dump(mode="json")

    @property
    def type(self) -> Literal["public", "secret"]:
        if self.info.public_key:
            return "public"
        return "secret"

    def export(self, format: Literal["raw", "ascii", "pem"] = "ascii", password: str = None) -> bytes:
        if format == "ascii":
            proc = self.session.run_command(
                f"gpg --export{'-secret-keys' if self.type == 'secret' else ''} --armor {self.info.fingerprint}"
            )
            proc.wait()
            return proc.output.decode().strip()
        elif format == "raw":
            with NamedTemporaryFile() as tf:
                proc = self.session.run_command(
                    f"gpg --batch --yes --output {tf.name} --export{'-secret-keys' if self.type == 'secret' else ''} {self.info.fingerprint}"
                )
                proc.wait()
                tf.seek(0)
                return tf.read()
        else:
            if not self.info.keygrip:
                raise GPGError("Missing keygrip")

            if self.info.public_key:
                key = self.info.public_key
            elif self.info.secret_key:
                key = self.info.secret_key
            else:
                raise GPGError("Keys missing")

            if not self.info.user_id:
                raise GPGError("User info missing")

            if key.algorithm in [PK.RSA_ENCRYPT_SIGN, PK.RSA_SIGN]:
                algo = "rsa"
            elif key.algorithm == PK.ECDSA:
                algo = "ecdsa"
            elif key.algorithm == PK.DSA:
                algo = "eddsa"
            else:
                raise GPGError(
                    "Invalid algorithm (allowed: RSA_ENCRYPT_SIGN, RSA_SIGN, ECDSA, DSA)"
                )

            email_match = re.findall("<.*>", self.info.user_id.user_id)
            if len(email_match) > 0:
                email = email_match[0].strip("<>")
            else:
                email = None
            name = self.info.user_id.user_id.split("(")[0].strip()

            with NamedTemporaryFile(mode="w+") as tf:
                tf.write(f"Key-Type: {algo}\n")
                tf.write(f"Key-Grip: {self.info.keygrip}\n")
                tf.write(f"Key-Usage: encrypt,sign\n")
                tf.write(f"Name-DN: CN={name}\n")
                if email:
                    tf.write(f"Name-Email: {email}\n")
                tf.write("Serial: random\n")
                if key.creation_date:
                    tf.write(f"Creation-Date: {key.creation_date.isoformat()}\n")
                if key.expiration_date:
                    tf.write(f"Expire-Date: {key.expiration_date.isoformat()}\n")
                tf.write("%commit\n")
                tf.seek(0)
                with NamedTemporaryFile(mode="w+b") as certf:
                    proc = self.session.run_command(f"gpgsm --yes --homedir {self.session.default_options["env"]["GNUPGHOME"]}{f' --passphrase-fd 0' if password else ''} --pinentry-mode loopback --batch --armor -o {certf.name} --gen-key {tf.name}")
                    if password:
                        proc.send(password)
                    proc.wait()
                    if b"certificate created" in proc.output:
                        certf.seek(0)
                        proc = self.session.run_command(f"gpgsm --with-colons --show-certs {certf.name}")
                        proc.wait()
                        try:
                            keyid = [i.split(":")[-1].strip() for i in proc.output.decode().split("\n") if i.strip().startswith("ID:")][0]
                        except:
                            raise GPGError(f"Failed to parse certificate info:\n{proc.output.decode()}")
                        
                        proc = self.session.run_command(f"gpgsm --import {certf.name}")
                        proc.wait()
                        if self.type == "secret":
                            proc = self.session.run_command(f"gpgsm --armor {f' --passphrase-fd 0' if password else ''} --pinentry-mode loopback --batch --export-secret-key-p8 {keyid}")
                            if password:
                                proc.send(password)
                            proc.wait()
                            return proc.output
                        else:
                            proc = self.session.run_command(f"gpgsm --armor --batch --export {keyid}")
                            proc.wait()
                            return proc.output
                    else:
                        raise GPGError(f"Failed to convert (code {proc.returncode}):\n\n{proc.output.decode()}")
                    
                
    def delete(self) -> None:
        self.session.run_command(f"gpg --batch --yes --delete-secret-and-public-key {self.info.fingerprint}").wait()
    
    @contextmanager
    def edit(self) -> Generator[KeyEditor, Any, Any]:
        editor = KeyEditor(self.info, self.session, self.password)
        try:
            editor.activate()
            yield editor
        finally:
            editor.deactivate()
