import re
from pydantic import BaseModel
from .models import KeyInfo
from ..util import SubprocessSession, SubprocessResult


class KeyListItem(BaseModel):
    code: str
    algorithm: str


class KeyEditor:
    def __init__(self, key: KeyInfo, session: SubprocessSession) -> None:
        self.key = key
        self.session = session
        self.process: SubprocessResult = None
        self.output = None

    def check(self):
        if self.process == None or self.process.returncode != None:
            raise RuntimeError("Cannot call function on an inactive Editor")

    def activate(self):
        self.process = self.session.run_command(
            f"gpg --expert --edit-key --command-fd 0 --status-fd 1 --batch {self.key.fingerprint}"
        )
        self.process.wait_for("GET_LINE keyedit.prompt")

    def deactivate(self):
        try:
            self.check()
            self.process.kill()
            self.process = None
        except:
            pass

    def execute(self, command: str) -> str:
        self.check()
        self.process.send(command)
        self.process.wait_for("GET_LINE keyedit.prompt")
        return (
            self.process._output.decode()
            .split("[GNUPG:] GET_LINE keyedit.prompt\n")[-2]
            .replace("[GNUPG:] GOT_IT", "")
            .strip()
        )

    def help(self) -> dict[str, str]:
        result = self.execute("help")
        parts = [
            line.split(maxsplit=1)
            for line in result.split("\n")
            if not line[0] in [" ", "*"]
        ]
        return {k: v for k, v in parts}

    def quit(self, save=True) -> None:
        if save:
            self.execute("save")
        else:
            self.execute("quit")

        self.deactivate()

    def list(self):
        result = self.execute("list")
        lines = result.split("\n")

        segments: list[list[str]] = []
        for line in lines:
            if re.match(r"^\[.*\].*$", line):
                segments.append(["UID", line])
            elif re.match(r"^\s.*$", line):
                segments[-1][1] += "\n" + line
            else:
                segments.append(["KEY", line])

        print(segments)
