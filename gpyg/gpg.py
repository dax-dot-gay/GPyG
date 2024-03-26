from contextlib import contextmanager
import subprocess
from tempfile import TemporaryFile
from .util import *
from .models import *
from .operators import *

class GPG:
    """Main GPyG class, provides a context within which to perform all operations.

    Args:
        homedir (str | None, optional): Homedir, or the system's default if None. Defaults to None.
        kill_existing_agent (bool, optional): Whether to attempt to kill running GPG agents. Defaults to False.
    """
    def __init__(self, homedir: str | None = None, kill_existing_agent: bool = False) -> None:

        if kill_existing_agent:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"])
        self.homedir = homedir
        self.session = ProcessSession(environment={"GNUPGHOME": homedir} if homedir else None).activate()
        self._config = None

    @property
    def config(self) -> GPGConfig:
        """Gets the current GPG config

        Returns:
            GPGConfig: Config details
        """
        if not self._config:
            proc = self.session.spawn("gpg --with-colons --list-config")
            proc.wait()
            self._config = GPGConfig.from_config_text(proc.output)
        return self._config

    @property
    def keys(self) -> KeyOperator:
        """Creates a KeyOperator for this instance

        Returns:
            KeyOperator: The KeyOperator
        """
        return KeyOperator(self)

    @property
    def messages(self) -> MessageOperator:
        """Creates a MessageOperator for this instance

        Returns:
            MessageOperator: The MessageOperator
        """
        return MessageOperator(self)

    @contextmanager
    def smart_card(self):
        with TemporaryFile() as passfile:
            with StatusInteractive(
                self.session,
                f"gpg --status-fd 1 --command-fd 0 --pinentry-mode loopback --passphrase-fd {passfile.fileno()} --card-edit",
            ) as interactive:
                interactive.writelines("admin")
                interactive.wait_for_status(StatusCodes.GET_LINE)
                yield CardOperator(self, interactive)
