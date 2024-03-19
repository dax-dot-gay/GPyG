class ExecutionError(Exception):
    def __init__(self, output: str, *args: object) -> None:
        self.output = output
        super().__init__(*args)
        
    def __str__(self) -> str:
        return f"Encountered an error executing a GPG command:\n\n=====\n{self.output}\n====="