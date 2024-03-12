import re
import subprocess
import shlex
from typing import Any, Literal


class SubprocessResult:
    def __init__(self, popen: subprocess.Popen):
        self.process = popen
        self._output = b""

    def wait(self, timeout=None):
        try:
            self._output += self.process.communicate(timeout=timeout)[0]
        except subprocess.TimeoutExpired:
            self.process.kill()
            self._output += self.process.communicate()[0]

    def wait_for(
        self, pattern: re.Pattern | str, regex=False, match_line=False, fd: Any = None
    ) -> bytes | None:
        while True:
            line = self.process.stdout.readline() if not fd else fd.readline()
            if line and len(line.strip()) > 0:
                self._output += line
                if match_line and type(pattern) == str and pattern == line:
                    return line

                if regex and re.search(pattern, line):
                    return line

                if not regex and not match_line and pattern in line.decode():
                    return line

            if self.process.poll() != None:
                return None

    def send(self, data: str | bytes) -> None:
        if type(data) == str:
            _data = data.encode("utf-8")
        else:
            _data = data

        if self.process.poll() == None:
            self.process.stdin.write(_data + b"\n")
            self.process.stdin.flush()

        else:
            raise RuntimeError("Process is not running.")

    def kill(self) -> None:
        if self.process.poll() == None:
            self.process.kill()

    @property
    def output(self) -> bytes:
        if self.process.poll() == None:
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
                self._output += line
                self.process.stdout.flush()

        return self._output

    @property
    def returncode(self) -> int | None:
        return self.process.poll()


class SubprocessSession:
    def __init__(
        self,
        environment: dict[str, str] = None,
        working_directory: str = None,
        shell: bool = None,
    ) -> None:
        self.default_options = {
            "env": environment,
            "cwd": working_directory,
            "shell": shell,
        }

    def parse_args(self, args: list[str]) -> list[str]:
        if self.default_options["shell"]:
            return " ".join(args)
        return shlex.split(" ".join(args))

    def run_command(self, *args, **kwargs):
        _args = self.parse_args(args)
        return SubprocessResult(
            subprocess.Popen(
                _args,
                **self.default_options,
                **{
                    k: v
                    for k, v in kwargs.items()
                    if self.default_options.get(k) == None
                },
                **{
                    pipe: (
                        subprocess.PIPE
                        if pipe in ["stdout", "stdin"]
                        else subprocess.STDOUT
                    )
                    for pipe in ["stdout", "stdin", "stderr"]
                    if not pipe in kwargs.keys()
                },
                bufsize=0,
            )
        )
