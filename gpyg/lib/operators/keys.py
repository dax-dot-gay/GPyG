from datetime import date
import subprocess
from typing import Literal
from ..context import GPGMEContext
from ...gpgme import *
from ..models import Key
from ..util import *


class KeyOperator:
    def __init__(self, context: GPGMEContext):
        self.context = context

    @property
    def ctx(self):
        return self.context.context

    def generate_key(
        self,
        common_name: str,
        email: str | None = None,
        comment: str | None = None,
        key_type: str | None = None,
        key_length: int | None = None,
        key_curve: str | None = None,
        key_usage: list[Literal["encrypt", "sign", "auth"]] | None = None,
        subkey_type: str | None = None,
        subkey_length: int | None = None,
        subkey_curve: str | None = None,
        subkey_usage: list[Literal["encrypt", "sign", "auth"]] | None = None,
        expiration: date | None = None,
        passphrase: str | None = None,
    ):
        params: list[str] = []
        params.append(f"Key-Type: {key_type if key_type else 'default'}")
        if key_length:
            params.append(f"Key-Length: {key_length}")
        if key_curve:
            params.append(f"Key-Curve: {key_curve}")

        if key_usage and len(key_usage) > 0 and key_type:
            params.append(f"Key-Usage: {','.join(key_usage)}")

        if subkey_type and key_type:
            params.append(f"Subkey-Type: {subkey_type}")

        if subkey_length and subkey_type and key_type:
            params.append(f"Subkey-Length: {subkey_length}")

        if subkey_type and key_type:
            params.append(
                f"Subkey-Curve: {subkey_curve if subkey_curve else 'default'}"
            )

        if key_type and subkey_type and subkey_usage and len(subkey_usage) > 0:
            params.append(f"Subkey-Usage: {','.join(subkey_usage)}")

        params.append(f"Expire-Date: {expiration.isoformat() if expiration else '0'}")
        params.append(f"Creation-Date: {date.today().isoformat()}")
        params.append(f"Name-Real: {common_name}")

        if email:
            params.append(f"Name-Email: {email}")

        if comment:
            params.append(f"Name-Comment: {comment}")

        if passphrase:
            params.append(f"Passphrase: {passphrase}")

        # params.append(r"%commit")

        param_block = (
            f'<GnupgKeyParms format="internal">\n{"\n".join(params)}\n</GnupgKeyParms>'
        )

        try:
            raise_error(gpgme_op_genkey(self.ctx, param_block, None, None))
        except:
            subprocess.run("killall gpg-agent")
            raise_error(gpgme_op_genkey(self.ctx, param_block, None, None))
        return self.get_key(gpgme_op_genkey_result(self.ctx).fpr)

    def list_keys(
        self,
        pattern: str = None,
        secret: bool = False,
        include_signatures: bool = False,
        include_signature_notations: bool = False,
    ):
        if include_signatures:
            old_keylist_mode = self.context.keylist
            self.context.keylist |= GpgmeKeylist.MODE_SIGS

            if include_signature_notations:
                self.context.keylist |= GpgmeKeylist.MODE_SIG_NOTATIONS

        raise_error(gpgme_op_keylist_start(self.ctx, pattern, int(secret)))
        results = []
        while True:
            ptr = CPointer.new("gpgme_key_t")
            code = translate_error(gpgme_op_keylist_next(self.ctx, ptr.pointer))
            if code == GpgErr.EOF:
                break
            elif code == 0:
                results.append(ptr.value)
            else:
                raise_error(code)

            ptr.delete()

        gpgme_op_keylist_end(self.ctx)

        if include_signatures:
            self.context.keylist = old_keylist_mode

        return [Key.create(k) for k in results]

    def get_key(
        self,
        fingerprint: str,
        secret: bool = False,
        include_signatures: bool = False,
        include_signature_notations: bool = False,
    ) -> Key | None:
        if include_signatures:
            old_keylist_mode = self.context.keylist
            self.context.keylist |= GpgmeKeylist.MODE_SIGS

            if include_signature_notations:
                self.context.keylist |= GpgmeKeylist.MODE_SIG_NOTATIONS

        ptr = CPointer.new("gpgme_key_t")
        code = translate_error(
            gpgme_get_key(self.ctx, fingerprint, ptr.pointer, int(secret))
        )
        if code != 0 and code != GpgErr.EOF:
            raise_error(code)
        value = ptr.value
        ptr.delete()
        if include_signatures:
            self.context.keylist = old_keylist_mode
        if value:
            return Key.create(value)
        else:
            return None
