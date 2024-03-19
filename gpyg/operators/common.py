from typing import Any
from ..util import Process, ProcessSession


class BaseOperator:
    def __init__(self, gpg: Any) -> None:
        self.gpg = gpg
        
    @property
    def session(self) -> ProcessSession:
        return self.gpg.session