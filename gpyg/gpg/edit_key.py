import datetime
from enum import StrEnum
import re
from pydantic import BaseModel
from .models import KeyInfo
from ..util import SubprocessSession, SubprocessResult


class KeyListItem(BaseModel):
    type: str
    algorithm: str
    id: str
    created: datetime.date | None
    expires: datetime.date | None
    usage: str | None
    trust: str | None
    validity: str | None

    @classmethod
    def from_string(cls, string: str) -> "KeyListItem":
        header, info = string.split("\n", maxsplit=1)
        keytype, algo_and_id = header.strip().split(maxsplit=1)
        algo, key_id = algo_and_id.split("/")
        options = {
            field.strip().split(":")[0].strip(): field.strip().split(":")[1].strip()
            for field in info.strip().replace(": ", ":").replace("\n", " ").split()
        }

        try:
            created = datetime.date.fromisoformat(options["created"])
        except:
            created = None

        try:
            expires = datetime.date.fromisoformat(options["expires"])
        except:
            expires = None

        return KeyListItem(
            type=keytype,
            algorithm=algo,
            id=key_id,
            created=created,
            expires=expires,
            usage=options.get("usage"),
            trust=options.get("trust"),
            validity=options.get("validity"),
        )


class UIDListItem(BaseModel):
    status: str
    index: int
    user_id: str
    selected: bool

    @classmethod
    def from_string(cls, string: str) -> "UIDListItem":
        status = re.findall(r"^\[.*\]", string)[0].strip("[]").strip()
        index = re.findall(r"\(.*?\)\.?\*?", string)[0]
        info = string.split(")", maxsplit=1)[1].strip(".*")
        return UIDListItem(
            status=status.strip("[]"), index=int(index.strip("().*")), user_id=info.strip(), selected="*" in index
        )

class RevocationEnum(StrEnum):
    NO_REASON = "0"
    INVALID_UID = "4"

class KeyEditor:
    def __init__(self, key: KeyInfo, session: SubprocessSession, password: str) -> None:
        self.key = key
        self.session = session
        self.process: SubprocessResult = None
        self.password = password

    def check(self):
        if self.process == None or self.process.returncode != None:
            raise RuntimeError("Cannot call function on an inactive Editor")

    def activate(self):
        self.process = self.session.run_command(
            f"gpg --expert --edit-key --command-fd 0 --status-fd 1 --pinentry-mode loopback --batch{f' --passphrase {self.password}' if self.password else ''} {self.key.fingerprint}"
        )
        self.process.wait_for("GET_LINE keyedit.prompt")

    def deactivate(self):
        try:
            self.check()
            self.process.kill()
            self.process = None
        except:
            pass

    def execute(self, command: str, *args: str | None, wait: bool = True) -> str:
        self.check()
        self.process.send(command)
        if len(args) > 0:
            for arg in args:
                self.process.send(arg if arg else "")
        if wait:
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
            self.execute("quit", "n", "y")

        self.deactivate()

    def list(self) -> tuple[list[KeyListItem], list[UIDListItem]]:
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

        keys = [KeyListItem.from_string(seg[1]) for seg in segments if seg[0] == "KEY"]
        users = [UIDListItem.from_string(seg[1]) for seg in segments if seg[0] == "UID"]
        return keys, users
    
    def select_key(self, id: str | None) -> None:
        self.execute(f"key {id if id else "0"}")
        
    def select_user_id(self, index: int | str | None) -> None:
        self.execute(f"uid {index if index else "0"}")
        
    def add_user_id(self, name: str, email: str | None = None, comment: str | None = None) -> None:
        self.execute("adduid", name, email, comment)
        
    def delete_user_id(self, index: int) -> None:
        self.select_user_id(index)
        self.execute("deluid", "y")
        
    def revoke_user_id(self, index: int, reason: RevocationEnum = RevocationEnum.INVALID_UID, description: str | None = None) -> None:
        self.select_user_id(index)
        self.execute("revuid", "y", reason.value, description, "", "y")
        
