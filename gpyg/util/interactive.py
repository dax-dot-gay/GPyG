import subprocess
from tempfile import NamedTemporaryFile
from .process import ProcessSession


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

    def seek(self, position: int = 0):
        self.output_handle.seek(position)

    def read(self, amount: int = -1) -> bytes | None:
        return self.output_handle.read(amount)

    def readline(self) -> bytes | None:
        line = self.output_handle.readline()
        if len(line) == 0:
            return None
        return line

    def readlines(self, yield_empty: bool = True):
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
