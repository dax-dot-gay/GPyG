from collections.abc import Generator
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any

from pydantic import BaseModel, computed_field
from .process import ProcessSession


class StatusLine(BaseModel):
    """Representation of a single status line
    See https://github.com/gpg/gnupg/blob/master/doc/DETAILS
    """
    content: str
    code: str | None = None
    arguments: list[str] | None = None

    @computed_field
    @property
    def is_status(self) -> bool:
        """Determines if a line is a status line or not (ie contains a status code)

        Returns:
            bool: Whether this line is status
        """
        return self.code != None

    @classmethod
    def from_line(cls, line: bytes) -> "StatusLine":
        """Creates a StatusLine from raw bytes

        Args:
            line (bytes): Input data

        Returns:
            StatusLine: A constructed StatusLine
        """
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
    """Provides a basic interface for handling interactive CLI menus"""
    def __init__(
        self,
        session: ProcessSession,
        command: str | list[str],
        shell: bool | None = None,
        environment: dict[str, str] | None = None,
        working_directory: str | None = None,
    ):
        """Initializes the Interactive instance

        Args:
            session (ProcessSession): The underlying ProcessSession
            command (str | list[str]): The command to run
            shell (bool | None, optional): Whether to run as shell. Defaults to None.
            environment (dict[str, str] | None, optional): Environment variable overrides. Defaults to None.
            working_directory (str | None, optional): Working directory override. Defaults to None.
        """
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
        """Seeks to a position within the STDOUT

        Args:
            position (int, optional): Position to seek to. Defaults to 0.
        """
        self.output_handle.seek(position)

    def read(self, amount: int = -1) -> bytes | None:
        """Returns up to `amount` bytes of STDOUT

        Args:
            amount (int, optional): Amount to return. Defaults to -1.

        Returns:
            bytes | None: Read bytes
        """
        return self.output_handle.read(amount)

    def readline(self) -> bytes | None:
        """Reads a single line (or until EOF) of STDOUT

        Returns:
            bytes | None: Line data
        """
        line = self.output_handle.readline()
        if len(line) == 0:
            return None
        return line

    def readlines(self, yield_empty: bool = True) -> Generator[bytes | None, Any, Any]:
        """Reads lines as an iterator from STDOUT

        Args:
            yield_empty (bool, optional): Whether to yield None when no line is read. Defaults to True.

        Yields:
            Generator[bytes | None, Any, Any]: The line generator
        """
        while True:
            try:
                line = self.readline()
                if line != None or yield_empty:
                    yield line
            except:
                break

    def write(self, content: bytes):
        """Write some content to STDIN

        Args:
            content (bytes): Content to  write
        """
        self.process.stdin.write(content)
        self.process.stdin.flush()

    def writelines(self, *lines: bytes | str):
        """Write any number of lines to stdin

        Arguments:
            *lines (bytes | str): Lines to write
        """
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
    """Wrapper around Interactive that generates StatusLines instead of bytes"""
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

    def wait_for_status(self, *code: str) -> list[StatusLine]:
        """Waits for status(es) to appear in the output, then returns logs up to that point

        Arguments:
            *code (StatusCode): Any number of StatusCodes to look for

        Returns:
            list[StatusLine]: List of log lines
        """
        lines: list[StatusLine] = []
        for line in self.readlines():
            if line:
                lines.append(line)
                if line.is_status and (len(code) == 0 or line.code in code):
                    return lines
