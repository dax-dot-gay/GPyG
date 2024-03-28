from collections.abc import Generator
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any

from pydantic import BaseModel, computed_field
from .process import ProcessSession


class StatusLine(BaseModel):
    content: str
    code: str | None = None
    arguments: list[str] | None = None

    @computed_field
    @property
    def is_status(self) -> bool:
        return self.code != None

    @classmethod
    def from_line(cls, line: bytes) -> "StatusLine":
        decoded = line.decode().rstrip("\n")
        if decoded.startswith("[GNUPG:]"):
            return StatusLine(
                content=decoded,
                code=decoded.split(" ")[1].strip(),
                arguments=decoded.split(" ")[2:],
            )
        else:
            return StatusLine(content=decoded)


class Interactive:
    def __init__(
        self,
        session: ProcessSession,
        command: str | list[str],
        shell: bool | None = None,
        environment: dict[str, str] | None = None,
        working_directory: str | None = None,
    ):
        self.session = session
        self.options = self.session.make_kwargs(
            shell=shell, env=environment, cwd=working_directory
        )
        self.parsed_command = self.session.parse_cmd(
            command, shell=bool(self.options.get("shell", False))
        )

        self.output_file = None
        self.output_handle = None
        self.process = None
        self.code = None

    def __enter__(self) -> "Interactive":
        self.output_file = NamedTemporaryFile()
        self.output_handle = open(self.output_file.name, "rb")
        self.process = subprocess.Popen(
            self.parsed_command,
            stdin=subprocess.PIPE,
            stdout=self.output_file,
            stderr=self.output_file,
            **self.options,
        )
        return self

    def __exit__(self, *args, **kwargs):
        if self.process.poll() == None:
            self.process.terminate()
            try:
                self.process.wait(timeout=0)
            except:
                pass
        self.code = self.process.poll()
        self.output_handle.close()
        self.output_file.close()
        del self.process

    def seek(self, position: int = 0):
        self.output_handle.seek(position)

    def read(self, amount: int = -1) -> bytes | None:
        return self.output_handle.read(amount)

    def readline(self) -> bytes | None:
        line = self.output_handle.readline()
        if len(line) == 0:
            return None
        return line

    def readlines(self, yield_empty: bool = True) -> Generator[bytes | None, Any, Any]:
        while True:
            try:
                line = self.readline()
                if line != None or yield_empty:
                    yield line
            except:
                break

    def write(self, content: bytes):
        self.process.stdin.write(content)
        self.process.stdin.flush()

    def writelines(self, *lines: bytes | str):
        concatenated = (
            b"\n".join(
                [
                    i.encode().rstrip(b"\n") if type(i) == str else i.rstrip(b"\n")
                    for i in lines
                ]
            )
            + b"\n"
        )
        self.write(concatenated)


class StatusInteractive(Interactive):
    def readline(self) -> StatusLine | None:
        line = super().readline()
        return StatusLine.from_line(line) if line else None

    def __enter__(self) -> "StatusInteractive":
        return super().__enter__()

    def readlines(
        self, yield_empty: bool = True
    ) -> Generator[StatusLine | None, Any, Any]:
        while True:
            try:
                line = self.readline()
                if line != None or yield_empty:
                    yield line
            except:
                break

    def wait_for_status(self, *code: str):
        lines: list[StatusLine] = []
        for line in self.readlines():
            if line:
                lines.append(line)
                if line.is_status and (len(code) == 0 or line.code in code):
                    return lines
