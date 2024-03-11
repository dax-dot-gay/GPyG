from pydantic import BaseModel


class KeyGenerationResult(BaseModel):
    fingerprint: str | None = None
    homedir: str | None
    output: str
    code: int
