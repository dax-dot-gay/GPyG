from ..context import GPGMEContext
from ...gpgme import *
from ..models import UserID
from ..util import *


class KeyOperator:
    def __init__(self, context: GPGMEContext):
        self.context = context

    @property
    def ctx(self):
        return self.context.context

    def create_key(
        self,
        user_id: str | UserID,
        algorithm: str | None = None,
        expiration: int | None = 0,
        signing: bool = False,
        encryption: bool = False,
        certification: bool = False,
        authentication: bool = False,
        force: bool = False,
        passphrase: str = None,
    ):
        if passphrase:

            def passphrase_cb(hint, desc, prev_bad, hook=None):
                return passphrase

            self.context.set_callback("passphrase", passphrase_cb)
            self.context.pinentry_mode = GpgmePinentry.MODE_LOOPBACK
        print(
            gpgme_op_createkey(
                self.ctx,
                str(user_id),
                algorithm,
                0,
                0 if expiration == None else expiration,
                None,
                (
                    (GpgmeCreate.SIGN if signing else 0)
                    | (GpgmeCreate.ENCR if encryption else 0)
                    | (GpgmeCreate.CERT if certification else 0)
                    | (GpgmeCreate.AUTH if authentication else 0)
                    | (GpgmeCreate.NOPASSWD if passphrase == None else 0)
                    | (GpgmeCreate.NOEXPIRE if expiration == None else 0)
                    | (GpgmeCreate.FORCE if force else 0)
                ),
            )
        )

        if passphrase:
            self.context.clear_callback("passphrase")

        return gpgme_op_genkey_result(self.ctx)
