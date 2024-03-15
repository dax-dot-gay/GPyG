from ...gpgme import GpgmeProtocol
from pydantic import BaseModel


class EngineInfo(BaseModel):
    file_name: str | None = None
    home_dir: str | None = None
    protocol: GpgmeProtocol = GpgmeProtocol.DEFAULT
    req_version: str | None = None
    version: str | None = None
