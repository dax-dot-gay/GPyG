import subprocess
from .util import *
from .models import *
from .operators import *

class GPG:
    def __init__(self, homedir: str | None = None, kill_existing_agent: bool = False) -> None:
        if kill_existing_agent:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"])
        self.homedir = homedir
        self.session = ProcessSession(environment={"GNUPGHOME": homedir} if homedir else None).activate()
        self._config = None
        
    @property
    def config(self) -> GPGConfig:
        if not self._config:
            proc = self.session.spawn("gpg --with-colons --list-config")
            proc.wait()
            self._config = GPGConfig.from_config_text(proc.output)
        return self._config
    
    @property
    def keys(self) -> KeyOperator:
        return KeyOperator(self)