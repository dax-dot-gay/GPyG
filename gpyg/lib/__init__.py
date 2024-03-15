from .context import GPGMEContext, CONTEXT_FLAGS, GpgmePinentry, GpgmeKeylist
from .util import CPointer, GPGError, GPGInternalError, raise_error
from .models import *
from .operators import *

OPERATORS = {"key": KeyOperator}


class GPG:
    def activate(self):
        if not self.context:
            self.context = GPGMEContext(**self.options)

    def deactivate(self):
        if self.context:
            self.context.free()
            self.context = None
            self.operators = {}

    def __enter__(self, *args, **kwargs):
        self.activate()
        return self

    def __exit__(self, *args, **kwargs):
        self.deactivate()

    def check(self):
        if self.context == None:
            raise GPGError("GPG instance has not been activated.")

    def get_operator(self, name: str):
        if not name in self.operators.keys():
            self.operators[name] = OPERATORS[name](self.context)

        return self.operators[name]

    def __init__(
        self,
        standalone: bool = False,
        version: str | None = None,
        homedir: str | None = None,
        armor: bool = False,
        textmode: bool = False,
        offline: bool = False,
        flags: dict[CONTEXT_FLAGS, str] = {},
        pinentry_mode: GpgmePinentry = GpgmePinentry.MODE_LOOPBACK,
    ):
        self.options = {
            "version": version,
            "homedir": homedir,
            "armor": armor,
            "textmode": textmode,
            "offline": offline,
            "flags": flags,
            "pinentry_mode": pinentry_mode,
        }
        if standalone:
            self.context = GPGMEContext(**self.options)
        else:
            self.context: GPGMEContext = None

        self.operators = {}

    @property
    def homedir(self) -> str | None:
        self.check()
        return self.context.homedir

    @homedir.setter
    def homedir(self, value: str | None):
        self.check()
        self.context.homedir = value

    @property
    def armor(self) -> bool:
        self.check()
        return self.context.armor

    @armor.setter
    def armor(self, value: bool):
        self.check()
        self.context.armor = value

    @property
    def textmode(self) -> bool:
        self.check()
        return self.context.textmode

    @textmode.setter
    def textmode(self, value: bool):
        self.check()
        self.context.textmode = value

    @property
    def offline(self) -> bool:
        self.check()
        return self.context.offline

    @offline.setter
    def offline(self, value: bool):
        self.check()
        self.context.offline = value

    @property
    def pinentry_mode(self) -> GpgmePinentry:
        self.check()
        return self.context.pinentry_mode

    @pinentry_mode.setter
    def pinentry_mode(self, value: GpgmePinentry):
        self.check()
        self.context.pinentry_mode = value

    @property
    def engine_info(self) -> EngineInfo:
        self.check()
        return self.context.engine_info

    @engine_info.setter
    def engine_info(self, value: EngineInfo) -> None:
        self.check()
        self.context.engine_info = value

    @property
    def included_certs(self) -> int | None:
        self.check()
        return self.context.included_certs

    @included_certs.setter
    def included_certs(self, value: int | None):
        self.check()
        self.context.included_certs = value

    @property
    def keylist(self) -> GpgmeKeylist | None:
        self.check()
        return self.context.keylist

    @keylist.setter
    def keylist(self, value: GpgmeKeylist):
        self.check()
        self.context.keylist = value

    def set_engine_info(self, file_name: str = None, home_dir: str = None):
        self.check()
        self.context.set_engine_info(file_name=file_name, home_dir=home_dir)

    def get_flag(self, flag: CONTEXT_FLAGS) -> str:
        self.check()
        return self.context.get_flag(flag)

    def set_flag(self, flag: CONTEXT_FLAGS, value: str):
        self.check()
        self.context.set_flag(flag, value)

    @property
    def keys(self) -> KeyOperator:
        self.check()
        return self.get_operator("key")
