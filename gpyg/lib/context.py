from contextlib import contextmanager
from typing import Any, Callable, Literal
from ..gpgme import *
from .util import *
from .models import *

CONTEXT_FLAGS = Literal[
    "redraw",
    "full-status",
    "raw-description",
    "export-session-key",
    "override-session-key",
    "auto-key-retrieve",
    "auto-key-import",
    "include-key-block",
    "request-origin",
    "no-symkey-cache",
    "ignore-mdc-error",
    "auto-key-locate",
    "trust-model",
    "extended-edit",
    "cert-expire",
    "key-origin",
    "import-filter",
    "no-auto-check-trustdb",
]


class GPGMEContext:

    def __init__(
        self,
        version: str | None = None,
        homedir: str | None = None,
        armor: bool = False,
        textmode: bool = False,
        offline: bool = False,
        flags: dict[CONTEXT_FLAGS, str] = {},
        pinentry_mode: GpgmePinentry = GpgmePinentry.MODE_LOOPBACK,
    ) -> None:
        gpgme_check_version(version)
        self.context_pointer = CPointer[Any].new("gpgme_ctx_t")
        raise_error(gpgme_new(self.context_pointer.pointer))
        self.context = self.context_pointer.value

        self.homedir = homedir
        self.armor = armor
        self.textmode = textmode
        self.offline = offline
        self.pinentry_mode = pinentry_mode

        for flag, value in flags.items():
            self.set_flag(flag, value)

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

    @property
    def engine_info(self) -> EngineInfo:
        proto = self.protocol
        infos = [
            i for i in gpgme_ctx_get_engine_info(self.context) if i.protocol == proto
        ]
        assert len(infos) == 1
        return EngineInfo(**infos[0].__dict__)

    @engine_info.setter
    def engine_info(self, value: EngineInfo) -> None:
        raise_error(
            gpgme_ctx_set_engine_info(
                self.context, value.protocol, value.file_name, value.home_dir
            )
        )

    def set_engine_info(self, file_name: str = None, home_dir: str = None):
        current = self.engine_info
        if file_name:
            current.file_name = file_name
        if home_dir:
            current.home_dir = home_dir

        self.engine_info = current

    @property
    def homedir(self) -> str:
        return self.engine_info.home_dir

    @homedir.setter
    def homedir(self, value: str) -> None:
        raise_error(self.set_engine_info(home_dir=value))

    @property
    def textmode(self) -> bool:
        return bool(gpgme_get_textmode(self.context))

    @textmode.setter
    def textmode(self, value: bool):
        gpgme_set_textmode(self.context, int(value))

    @property
    def offline(self) -> bool:
        return bool(gpgme_get_offline(self.context))

    @offline.setter
    def offline(self, value: bool):
        gpgme_set_offline(self.context, int(value))

    @property
    def pinentry_mode(self) -> GpgmePinentry:
        return GpgmePinentry(gpgme_get_pinentry_mode(self.context))

    @pinentry_mode.setter
    def pinentry_mode(self, value: GpgmePinentry | int):
        raise_error(gpgme_set_pinentry_mode(self.context, value))

    @property
    def included_certs(self) -> int | None:
        result = gpgme_get_include_certs(self.context)
        if result == GPGME_INCLUDE_CERTS_DEFAULT:
            return None
        return result

    @included_certs.setter
    def included_certs(self, value: int | None):
        raise_error(
            gpgme_set_include_certs(
                self.context, GPGME_INCLUDE_CERTS_DEFAULT if value == None else value
            )
        )

    @property
    def keylist(self) -> GpgmeKeylist | None:
        result = gpgme_get_keylist_mode(self.context)
        if result == 0:
            return None
        return GpgmeKeylist(result)

    @keylist.setter
    def keylist(self, value: GpgmeKeylist):
        raise_error(gpgme_set_keylist_mode(self.context, value))

    def set_callback(
        self, name: Literal["passphrase", "progress", "status"], function: Callable
    ):
        getattr(gpgme, f"gpgme_set_{name}_cb")(self.context, function)

    def clear_callback(self, name: Literal["passphrase", "progress", "status"]):
        getattr(gpgme, f"gpgme_set_{name}_cb")(self.context, None)

    @contextmanager
    def callback(
        self, name: Literal["passphrase", "progress", "status"], function: Callable
    ):
        try:
            self.set_callback(name, function)
            yield
        finally:
            self.clear_callback(name)

    def set_flag(self, flag: CONTEXT_FLAGS, value: str):
        raise_error(gpgme_set_ctx_flag(self.context, flag, value))

    def get_flag(self, flag: CONTEXT_FLAGS) -> str:
        return gpgme_get_ctx_flag(self.context, flag)
