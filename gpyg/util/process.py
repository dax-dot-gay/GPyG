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
    """Wrapper around some of the functionality of Popen"""

    def __init__(
        self,
        popen: subprocess.Popen,
        command: str | list[str],
        options: dict[str, Any],
        decode_output: bool = True,
    ):
        """Initialization routine

        Args:
            popen (subprocess.Popen): Popen object
            command (str | list[str]): The command being run
            options (dict[str, Any]): Options passed to the Popen constructor
            decode_output (bool, optional): Whether to convert the output to str. Defaults to True.
        """
        self.popen = popen
        self.options = options
        self.command: str = shlex.join(command) if type(command) == list else command
        self.output = "" if decode_output else b""
        self.code: int | None = None
        self.decode = decode_output

    @property
    def pid(self) -> int:
        """Returns the PID of the process

        Returns:
            int: Process PID
        """
        return self.popen.pid

    def poll(self) -> int | None:
        """Gets the return code, if available

        Returns:
            int | None: Returncode or None if the process is running
        """
        if self.code == None:
            self.code = self.popen.poll()
        return self.code

    def kill(self):
        """Attempts to kill the Process"""
        try:
            if self.poll() == None:
                self.popen.kill()
        except:
            pass

    def write(self, data: bytes):
        """Writes some bytes to STDIN

        Args:
            data (bytes): Bytes to write
        """
        if self.poll() == None:
            self.popen.stdin.write(data)
            self.popen.stdin.flush()

    def wait(
        self, timeout: float | None = None, kill_on_timeout: bool = True
    ) -> int | None:
        """Waits for a timeout/for the process to stop

        Args:
            timeout (float | None, optional): Time to wait, or no limit. Defaults to None.
            kill_on_timeout (bool, optional): Whether to kill the process on timeout. Defaults to True.

        Returns:
            int | None: The returncode
        """
        if self.code == None:
            try:
                self.output = (
                    self.popen.communicate(timeout=timeout)[0].decode()
                    if self.decode
                    else self.popen.communicate(timeout=timeout)[0]
                )
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
    """A persistent session that creates Processes"""

    def __init__(
        self,
        shell: bool | None = None,
        environment: dict[str, str] | None = None,
        working_directory: str | None = None,
        cleanup_mode: Literal["kill", "wait", "ignore"] = "kill",
    ) -> None:
        """Initialization routine

        Args:
            shell (bool | None, optional): Whether to use shell. Defaults to None.
            environment (dict[str, str] | None, optional): Environment vars. Defaults to None.
            working_directory (str | None, optional): Workding directory path. Defaults to None.
            cleanup_mode (kill | wait | ignore, optional): What to do when deactivated to all child processes. Defaults to "kill".
        """
        self.default_options = {
            "shell": shell,
            "env": environment,
            "cwd": working_directory,
        }
        self.cleanup = cleanup_mode
        self.processes: dict[int, Process] = {}

    def make_kwargs(self, **passed_kwargs: dict[str, Any]) -> dict[str, Any]:
        """Utility function to remove duplicate kwargs from defaults

        Returns:
            dict[str, Any]: Deduplicated kwargs
        """
        result = passed_kwargs.copy()
        for k, v in self.default_options.items():
            if (not k in result.keys() and v != None) or (
                k in result.keys() and result[k] == None
            ):
                result[k] = v

        return result

    def activate(self):
        """Activate (ie as a context manager)

        Returns:
            ProcessSession: The activated session
        """
        self.processes = {}
        return self

    def deactivate(self):
        """Deactivates the Session and cleans up"""
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
        """Parse a command with shlex and return a quoted and escaped version

        Args:
            cmd (str | list[str]): Command to parse
            shell (bool): Whether to run in shell mode or not

        Returns:
            str | list[str]: Parsed command
        """
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
        decode: bool = True,
    ) -> Process:
        """Spawns a process, then returns to the caller

        Args:
            command (str | list[str]): Command to run
            shell (bool | None, optional): Whether to run in shell. Defaults to None.
            environment (dict[str, str] | None, optional): Environment override. Defaults to None.
            working_directory (str | None, optional): Working directory. Defaults to None.
            decode (bool, optional): Whether to decode the output bytes. Defaults to True.

        Returns:
            Process: Running Process
        """
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
            popen, parsed_command, options, decode_output=decode
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
        input: str | bytes | None = None,
    ) -> Process:
        """Runs a Process & waits for it to complete.

        Args:
            command (str | list[str]): Command to run
            shell (bool | None, optional): Whether to run in shell. Defaults to None.
            environment (dict[str, str] | None, optional): Environment var override. Defaults to None.
            working_directory (str | None, optional): Working directory. Defaults to None.
            timeout (int | None, optional): How long to wait, or no wait limit. Defaults to None.
            decode (bool, optional): Whether to decode the output. Defaults to True.
            input (str | bytes | None, optional): String/bytes to send to STDIN. Defaults to None.

        Returns:
            Process: Finished Process
        """
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
            popen, parsed_command, options, decode_output=decode
        )

        if input:
            self.processes[popen.pid].write(
                input.encode() if type(input) == str else input
            )

        self.processes[popen.pid].wait(timeout=timeout, kill_on_timeout=True)
        return self.processes[popen.pid]

    def __getitem__(self, pid: int) -> Process:
        return self.processes[pid]
