from collections.abc import Generator
from io import BytesIO
import re
import shlex
import subprocess
import threading
import time
from typing import Any, Literal

class Process:
    def __init__(self, popen: subprocess.Popen, command: str | list[str], options: dict[str, Any]):
        self.popen = popen
        self.options = options
        self.command: str = shlex.join(command) if type(command) == list else command
        self.output = ""
        self.code: int | None = None
        self.listener = threading.Thread(target=self.listen, name=f"listener-{self.command}", daemon=True)
        self.listener.start()
        
    def listen(self):
        while True:
            if self.poll() != None:
                return
            
            data = self.popen.stdout.read(1).decode()
            self.output += data
            self.popen.stdout.flush()
        
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
            
    def lines(self, seek: int = 0, strip: bool = True) -> Generator[str, Any, None]:
        if seek < 0:
            pointer = len(self.output) + seek
        else:
            pointer = min(seek, len(self.output))
            
        chunk = ""
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
                        
                    chunk = ""
            except IndexError:
                pass
            
            time.sleep(0)
            
    def tui(self, pattern: str, match_mode: Literal["contains", "regex", "line"] = "contains", seek: int = 0) -> Generator[list[str], Any, None]:
        lines = []
        for line in self.lines(seek=seek):
            lines.append(line)
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
                self.popen.communicate(timeout=timeout)
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
    
    def __enter__(self):
        self.processes = {}
        return self
    
    def __exit__(self, *args, **kwargs):
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
            
    def parse_cmd(self, cmd: str | list[str], shell: bool) -> str | list[str]:
        if type(cmd) == list:
            result = shlex.join(cmd)
        else:
            result = shlex.join(shlex.split(cmd))
            
        if not shell:
            result = shlex.split(result)
        
        return result
            
    def spawn(self, command: str | list[str], shell: bool | None = None, environment: dict[str, str] | None = None, working_directory: str | None = None) -> Process:
        options = self.make_kwargs(shell=shell, env=environment, cwd=working_directory)
        parsed_command = self.parse_cmd(command, shell=bool(options.get("shell", False)))
        
        popen = subprocess.Popen(parsed_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options)
        self.processes[popen.pid] = Process(popen, parsed_command, options)
        return self.processes[popen.pid]
    
    def __getitem__(self, pid: int) -> Process:
        return self.processes[pid]
        
        