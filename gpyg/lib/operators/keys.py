from datetime import date
import subprocess
from typing import Any, Literal
from ..context import GPGMEContext
from ...gpgme import *
from ..models import Key, UserID
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
    ) -> "KeyObject":
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
            subprocess.run("killall gpg-agent", shell=True)
            raise_error(gpgme_op_genkey(self.ctx, param_block, None, None))
        return self.get_key(
            gpgme_op_genkey_result(self.ctx).fpr,
            include_signatures=True,
            include_signature_notations=True,
        )

    def list_keys(
        self,
        pattern: str = None,
        secret: bool = False,
        include_signatures: bool = False,
        include_signature_notations: bool = False,
    ) -> list["KeyObject"]:
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

        return [KeyObject.create(k, self) for k in results]

    def get_key(
        self,
        fingerprint: str,
        secret: bool = False,
        include_signatures: bool = False,
        include_signature_notations: bool = False,
    ) -> "KeyObject | None":
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
            return KeyObject.create(value, self)
        else:
            return None


class KeyObject(Key):
    def __init__(self, operator: KeyOperator = None, key_struct: Any = None, **kwargs):
        super().__init__(**kwargs)
        self._operator = operator
        self._key_struct = key_struct

    @property
    def include_signatures(self):
        return GpgmeKeylist.MODE_SIGS in self.keylist_mode

    @property
    def include_signature_notations(self):
        return (
            GpgmeKeylist.MODE_SIG_NOTATIONS in self.keylist_mode
            and self.include_signatures
        )

    @property
    def ctx(self):
        return self._operator.ctx

    @classmethod
    def create(cls, key: Any, operator: KeyOperator) -> "KeyObject":
        base = super().create(key)
        return KeyObject(operator=operator, key_struct=key, **base.model_dump())

    def reload(self) -> "KeyObject":
        result = self._operator.get_key(
            self.fingerprint,
            secret=self.secret,
            include_signatures=self.include_signatures,
            include_signature_notations=self.include_signature_notations,
        )
        for k, v in result.__dict__.items():
            if not k.startswith("_"):
                setattr(self, k, v)

        return self

    def sign(
        self,
        as_key: "KeyObject",
        user_id: str | UserID | list[str | UserID] | None = None,
        passphrase: str | None = None,
        expiration: int | None = None,
        exportable: bool = True,
        force: bool = False,
    ) -> "KeyObject":
        self._operator.context.callback(
            "status", lambda *args, **kwargs: print(args, kwargs)
        )
        self._operator.context.callback(
            "progress", lambda *args, **kwargs: print(args, kwargs)
        )
        gpgme_signers_clear(self.ctx)
        gpgme_signers_add(self.ctx, as_key._key_struct)
        if passphrase:
            old_pmode = self._operator.context.pinentry_mode
            self._operator.context.pinentry_mode = GpgmePinentry.MODE_LOOPBACK
            self._operator.context.callback(
                "passphrase", lambda *args, **kwargs: passphrase
            )

        if type(user_id) == str:
            parsed_uids = user_id

        elif type(user_id) == list:
            parsed_uids = "\n".join(
                [i.uid if isinstance(i, UserID) else i for i in user_id]
            )

        elif isinstance(user_id, UserID):
            parsed_uids = user_id.uid

        else:
            parsed_uids = None

        print(
            gpgme_op_keysign(
                self.ctx,
                self._key_struct,
                parsed_uids,
                expiration if expiration else 0,
                (GpgmeKeysign.LOCAL if not exportable else 0)
                | (GpgmeKeysign.LFSEP if parsed_uids and "\n" in parsed_uids else 0)
                | (
                    GpgmeKeysign.NOEXPIRE
                    if expiration == None or expiration == 0
                    else 0
                )
                | (GpgmeKeysign.FORCE if force else 0),
            )
        )
        gpgme_signers_clear(self.ctx)
        self._operator.context.clear_callback("status")
        self._operator.context.clear_callback("progress")

        if passphrase:
            self._operator.context.pinentry_mode = old_pmode
            self._operator.context.clear_callback("passphrase")
        return self.reload()
