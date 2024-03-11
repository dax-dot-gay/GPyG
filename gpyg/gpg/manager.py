from .models import KeyInfo
from ..util import SubprocessResult, SubprocessSession


class KeyManager:
    def __init__(self, info: KeyInfo, session: SubprocessSession):
        self._info = info
        self.session = session

    @property
    def info(self) -> dict:
        return self._info.model_dump()

    @property
    def json(self) -> dict:
        return self._info.model_dump(mode="json")
