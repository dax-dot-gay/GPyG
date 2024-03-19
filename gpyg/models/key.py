from pydantic import BaseModel
from .infolines import *
from datetime import datetime


class Key(BaseModel):
    type: Literal["public", "secret"]
    validity: FieldValidity
    length: int
    algorithm: int
    key_id: str
    creation_date: datetime | None
    expiration_date: datetime | None
    owner_trust: str | None
    capabilities: list[KeyCapability]
    overall_capabilities: list[KeyCapability]
    curve_name: str | None
    serial_number: str | None = None
    fingerprint: str | None = None
    keygrip: str | None = None
