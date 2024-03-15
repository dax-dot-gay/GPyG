from typing import Any
from ..gpgme import *
from .util import *


class GPGMEContext:
    def __init__(self, version: str | None = None) -> None:
        gpgme_check_version(version)
        self.context_pointer = CPointer[Any].new("gpgme_ctx_t")
        raise_error(gpgme_new(self.context_pointer.pointer))
        self.context = self.context_pointer.value

    @property
    def armor(self) -> bool:
        return bool(gpgme_get_armor(self.context))

    @armor.setter
    def armor(self, value: bool):
        gpgme_set_armor(self.context, int(value))

    @property
    def protocol(self) -> GpgmeProtocol:
        return GpgmeProtocol(gpgme_get_protocol(self.context))

    @protocol.setter
    def protocol(self, value: GpgmeProtocol | int):
        raise_error(gpgme_check_version(str(GpgmeProtocol(value))))
        gpgme_set_protocol(self.context, GpgmeProtocol(value))
