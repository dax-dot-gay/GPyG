from collections.abc import Generator
from io import BytesIO
import re
import shlex
import subprocess
import threading
import time
from traceback import print_exc
from typing import Any, Literal

class Process:

    def __init__(
        self,
        popen: subprocess.Popen,
        command: str | list[str],
        options: dict[str, Any],
        launch_thread: bool = False,
        decode_output: bool = True,
    ):
        self.popen = popen
        self.options = options
        self.command: str = shlex.join(command) if type(command) == list else command
        self.output = "" if decode_output else b""
        self.code: int | None = None
        self.decode = decode_output
        if launch_thread:
            self.listener = threading.Thread(
                target=self.listen, name=f"listener-{self.command}", daemon=True
            )
            self.listener.start()
        else:
            self.listener = None

    def listen(self):
        while True:
            try:
                data = (
                    self.popen.stdout.read(1).decode()
                    if self.decode
                    else self.popen.stdout.read(1)
                )
            except:
                data = None
            if self.poll() != None and data == None:
                return

            self.output += data
            try:
                self.popen.stdout.flush()
            except:
                pass

    @property
    def pid(self) -> int:
        return self.popen.pid

    def poll(self) -> int | None:
        if self.code == None:
            self.code = self.popen.poll()
        return self.code

    def kill(self):
        try:
            if self.poll() == None:
                self.popen.kill()
        except:
            pass

    def write(self, data: bytes):
        if self.poll() == None:
            self.popen.stdin.write(data)
            self.popen.stdin.flush()

    def lines(
        self, seek: int = 0, strip: bool = True
    ) -> Generator[str | bytes, Any, None]:
        if not self.listener:
            raise RuntimeError("Not in listener mode.")
        if seek < 0:
            pointer = len(self.output) + seek
        else:
            pointer = min(seek, len(self.output))

        chunk = "" if self.decode else b""
        while True:
            if self.code != None:
                yield chunk.strip() if strip else chunk
                return

            try:
                char = self.output[pointer]
                pointer += 1
                if len(char) > 0:
                    chunk += char

                if chunk.endswith("\n"):
                    if strip:
                        yield chunk.strip()
                    else:
                        yield chunk

                    chunk = "" if self.decode else b""
            except IndexError:
                pass

            time.sleep(0)

    def tui(
        self,
        pattern: str,
        match_mode: Literal["contains", "regex", "line"] = "contains",
        seek: int = 0,
    ) -> Generator[list[str | bytes], Any, None]:
        lines = []
        for line in self.lines(seek=seek):
            lines.append(line)
            print(line)
            match match_mode:
                case "contains":
                    if pattern in line:
                        yield lines[:]
                        lines = []
                case "line":
                    if pattern == line:
                        yield lines[:]
                        lines = []
                case "regex":
                    if re.search(pattern, line):
                        yield lines[:]
                        lines = []

    def wait(self, timeout: float | None = None, kill_on_timeout: bool = True) -> int | None:
        if self.code == None:
            try:
                output = (
                    self.popen.communicate(timeout=timeout)[0].decode()
                    if self.decode
                    else self.popen.communicate(timeout=timeout)[0]
                )
                if self.listener == None:
                    self.output = output
            except subprocess.TimeoutExpired:
                if kill_on_timeout:
                    self.kill()

            return self.poll()
        else:
            return self.code

    def send_line(self, line: str):
        if self.poll() == None:
            self.write(line.encode().strip() + b"\n")

class ProcessSession:
    def __init__(self, shell: bool | None = None, environment: dict[str, str] | None = None, working_directory: str | None = None, cleanup_mode: Literal["kill", "wait", "ignore"] = "kill") -> None:
        self.default_options = {
            "shell": shell,
            "env": environment,
            "cwd": working_directory
        }
        self.cleanup = cleanup_mode
        self.processes: dict[int, Process] = {}

    def make_kwargs(self, **passed_kwargs: dict[str, Any]) -> dict[str, Any]:
        result = passed_kwargs.copy()
        for k, v in self.default_options.items():
            if (not k in result.keys() and v != None) or (k in result.keys() and result[k] == None):
                result[k] = v

        return result

    def activate(self):
        self.processes = {}
        return self

    def deactivate(self):
        match self.cleanup:
            case "kill":
                for pid, process in list(self.processes.items()):
                    process.kill()
                    del self.processes[pid]

            case "wait":
                for process in self.processes.values():
                    if process.poll() == None:
                        process.popen.communicate()

            case _:
                pass

    def __enter__(self):
        return self.activate()

    def __exit__(self, *args, **kwargs):
        self.deactivate()

    def parse_cmd(self, cmd: str | list[str], shell: bool) -> str | list[str]:
        if type(cmd) == list:
            result = shlex.join(cmd)
        else:
            result = shlex.join(shlex.split(cmd))

        if not shell:
            result = shlex.split(result)

        return result

    def spawn(
        self,
        command: str | list[str],
        shell: bool | None = None,
        environment: dict[str, str] | None = None,
        working_directory: str | None = None,
        listen: bool = False,
        decode: bool = True,
    ) -> Process:
        options = self.make_kwargs(shell=shell, env=environment, cwd=working_directory)
        parsed_command = self.parse_cmd(command, shell=bool(options.get("shell", False)))

        popen = subprocess.Popen(parsed_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options)
        self.processes[popen.pid] = Process(
            popen, parsed_command, options, launch_thread=listen, decode_output=decode
        )
        return self.processes[popen.pid]

    def run(
        self,
        command: str | list[str],
        shell: bool | None = None,
        environment: dict[str, str] | None = None,
        working_directory: str | None = None,
        timeout: int | None = None,
        decode: bool = True,
        input: str | None = None,
    ) -> Process:
        options = self.make_kwargs(shell=shell, env=environment, cwd=working_directory)
        parsed_command = self.parse_cmd(
            command, shell=bool(options.get("shell", False))
        )

        popen = subprocess.Popen(
            parsed_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            **options,
        )
        self.processes[popen.pid] = Process(
            popen, parsed_command, options, launch_thread=False, decode_output=decode
        )

        if input:
            self.processes[popen.pid].write(input.encode())

        self.processes[popen.pid].wait(timeout=timeout, kill_on_timeout=True)
        return self.processes[popen.pid]

    def __getitem__(self, pid: int) -> Process:
        return self.processes[pid]
