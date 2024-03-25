from datetime import datetime
from enum import StrEnum
from itertools import zip_longest
from typing import Any, TypeVar
from typing_extensions import TypedDict
from pydantic import BaseModel, Field, computed_field


class Sex(StrEnum):
    UNSET = "u"
    FEMALE = "f"
    MALE = "m"


TPinData = TypeVar("TPinData")


class PinData[TPinData](TypedDict):
    pin: TPinData
    reset: TPinData
    admin: TPinData


class UIFData(TypedDict):
    sign: bool
    decrypt: bool
    auth: bool


class KeyData(TypedDict):
    fingerprint: str | None
    created: datetime | None
    keygrip: str | None


class SmartCard(BaseModel):
    lines: dict[str, list[str] | dict[int, list[str]]]

    def field(
        self, line: str, index: int | None = None, default: Any = None
    ) -> str | None:
        try:
            val = self.lines[line][index if index != None else 0]
            if len(val) == 0:
                return default
            return val
        except:
            return default

    @classmethod
    def from_status(cls, status: str) -> "SmartCard":
        lines = {}
        for line in status.splitlines():
            key, *fields = line.split(":")
            if key == "keyattr":
                if not "keyattr" in lines.keys():
                    lines["keyattr"] = {}
                lines["keyattr"][int(fields[0])] = fields[1:]
            else:
                lines[key.lower()] = fields[:]

        return SmartCard(lines=lines)

    @computed_field
    def reader(self) -> str | None:
        return self.field("reader")

    @computed_field
    def application_id(self) -> str | None:
        return self.field("reader", index=2)

    @computed_field
    def application_type(self) -> str | None:
        return self.field("reader", index=3)

    @computed_field
    def version(self) -> str | None:
        return self.field("version")

    @computed_field
    def vendor_id(self) -> str | None:
        return self.field("vendor")

    @computed_field
    def vendor(self) -> str | None:
        return self.field("vendor", index=1)

    @computed_field
    def serial_number(self) -> str | None:
        return self.field("serial")

    @computed_field
    def cardholder_name(self) -> str | None:
        return " ".join(self.lines.get("name")) if "name" in self.lines.keys() else None

    @computed_field
    def language_preferences(self) -> str | None:
        return self.field("lang")

    @computed_field
    def cardholder_gender(self) -> Sex:
        result = self.field("sex")
        if result:
            return Sex(result)
        return Sex.UNSET

    @computed_field
    def public_key_url(self) -> str | None:
        return self.field("url")

    @computed_field
    def login_data(self) -> str | None:
        return self.field("login")

    @computed_field
    def forced_signature_pin(self) -> bool:
        return self.field("forcedpin") == "1"

    @computed_field
    def key_attrs(self) -> list[tuple[int, int]]:
        attrs = []
        for attr in sorted(list(self.lines.get("keyattr", {}).keys())):
            item = self.lines.get("keyattr", {})[attr]
            attrs.append((int(item[0]), int(item[1])))

        return attrs

    @computed_field
    def max_pin_lengths(self) -> PinData[int]:
        return {
            "pin": int(self.field("maxpinlen", index=0, default=0)),
            "reset": int(self.field("maxpinlen", index=1, default=0)),
            "admin": int(self.field("maxpinlen", index=2, default=0)),
        }

    @computed_field
    def pin_retries(self) -> PinData[int]:
        return {
            "pin": int(self.field("pinretry", index=0, default=0)),
            "reset": int(self.field("pinretry", index=1, default=0)),
            "admin": int(self.field("pinretry", index=2, default=0)),
        }

    @computed_field
    def signature_count(self) -> int | None:
        return int(self.field("sigcount", default=0))

    @computed_field
    def kdf_setting(self) -> bool:
        return self.field("kdf") == "on"

    @computed_field
    def uif_setting(self) -> UIFData:
        return {
            "sign": bool(int(self.field("uif", index=0, default=0))),
            "decrypt": bool(int(self.field("uif", index=1, default=0))),
            "auth": bool(int(self.field("uif", index=2, default=0))),
        }

    @computed_field
    def stored_keys(self) -> list[KeyData]:
        fprs = self.lines.get("fpr", [])
        fprtimes = self.lines.get("fprtime", [])
        grps = self.lines.get("grp", [])

        results: list[KeyData] = []
        for fpr, ftime, grp in zip_longest(fprs, fprtimes, grps):
            try:
                created = datetime.fromtimestamp(float(ftime)) if ftime else None
            except:
                created = None
            results.append({"fingerprint": fpr, "created": created, "keygrip": grp})

        return results
