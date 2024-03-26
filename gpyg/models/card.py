from datetime import datetime
from enum import StrEnum
from itertools import zip_longest
from typing import Any, TypeVar
from typing_extensions import TypedDict
from pydantic import BaseModel, Field, computed_field


class Sex(StrEnum):
    """Describes a SmartCard's sex marker.

    Members:
        - `UNSET`: No sex
        - `FEMALE`: Sex set to female
        - `MALE`: Sex set to male
    """

    UNSET = "u"
    FEMALE = "f"
    MALE = "m"


TPinData = TypeVar("TPinData")


class PinData[TPinData](TypedDict):
    """Generic container for PIN data"""

    pin: TPinData
    reset: TPinData
    admin: TPinData


class UIFData(TypedDict):
    """Smartcard usage data"""

    sign: bool
    decrypt: bool
    auth: bool


class KeyData(TypedDict):
    """Data about an individual key stored on the card"""

    fingerprint: str | None
    created: datetime | None
    keygrip: str | None


class SmartCard(BaseModel):
    """SmartCard Model. Includes parsing of --card-status output."""
    lines: dict[str, list[str] | dict[int, list[str]]]

    def field(
        self, line: str, index: int | None = None, default: Any = None
    ) -> str | None:
        """Gets the value of a field index in a line, with an optional default

        Args:
            line (str): Line key
            index (int | None, optional): Field index, or 0 if None. Defaults to None.
            default (Any, optional): Default to return if not found. Defaults to None.

        Returns:
            str | None: Value at index in field, or None if nonexistent/empty
        """
        try:
            val = self.lines[line][index if index != None else 0]
            if len(val) == 0:
                return default
            return val
        except:
            return default

    @classmethod
    def from_status(cls, status: str) -> "SmartCard":
        """Parses --card-status output and generates a SmartCard

        Args:
            status (str): Status output string

        Returns:
            SmartCard: Generated SmartCard
        """
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
    @property
    def reader(self) -> str | None:
        """Reader Name & Info

        Returns:
            str | None: Reader name, or None
        """
        return self.field("reader")

    @computed_field
    @property
    def application_id(self) -> str | None:
        """Application ID

        Returns:
            str | None: Application ID, or None
        """
        return self.field("reader", index=2)

    @computed_field
    @property
    def application_type(self) -> str | None:
        """Application Type

        Returns:
            str | None: Application Type, or None
        """
        return self.field("reader", index=3)

    @computed_field
    @property
    def version(self) -> str | None:
        """Reader Version

        Returns:
            str | None: Reader version, or None
        """
        return self.field("version")

    @computed_field
    @property
    def vendor_id(self) -> str | None:
        """ID of Smartcard Vendor

        Returns:
            str | None: Vendor ID, or None
        """
        return self.field("vendor")

    @computed_field
    @property
    def vendor(self) -> str | None:
        """Name of Smartcard Vendor

        Returns:
            str | None: Vendor name, or None
        """
        return self.field("vendor", index=1)

    @computed_field
    @property
    def serial_number(self) -> str | None:
        """Smartcard S/N

        Returns:
            str | None: Serial number, or None
        """
        return self.field("serial")

    @computed_field
    @property
    def cardholder_name(self) -> str | None:
        """Cardholder Name

        Returns:
            str | None: Cardholder name, or None
        """
        return " ".join(self.lines.get("name")) if "name" in self.lines.keys() else None

    @computed_field
    @property
    def language_preferences(self) -> list[str]:
        """Cardholder Language Preferences

        Returns:
            list[str]: List of language preferences
        """
        value = self.field("lang")
        if value:
            return [
                value[i] + value[i + 1]
                for i in range(0, len(value), 2)
                if len(value) > i + 1
            ]
        else:
            return []

    @computed_field
    @property
    def cardholder_gender(self) -> Sex:
        """Cardholder Sex

        Returns:
            Sex: Specified sex, or UNSET if not specified.
        """
        result = self.field("sex")
        if result:
            return Sex(result)
        return Sex.UNSET

    @computed_field
    @property
    def public_key_url(self) -> str | None:
        """Public Key URI

        Returns:
            str | None: URI, or None
        """
        return self.field("url")

    @computed_field
    @property
    def login_data(self) -> str | None:
        """Login Data

        Returns:
            str | None: Login data, or None
        """
        return self.field("login")

    @computed_field
    @property
    def forced_signature_pin(self) -> bool:
        """Whether signature pin is currently forced

        Returns:
            bool: If pin is forced
        """
        return self.field("forcedpin") == "1"

    @computed_field
    @property
    def key_attrs(self) -> list[tuple[int, int]]:
        """Returns a list of key attrs (ID, Value)

        Returns:
            list[tuple[int, int]]: Attrs (ID, Value)
        """
        attrs = []
        for attr in sorted(list(self.lines.get("keyattr", {}).keys())):
            item = self.lines.get("keyattr", {})[attr]
            attrs.append((int(item[0]), int(item[1])))

        return attrs

    @computed_field
    @property
    def max_pin_lengths(self) -> PinData[int]:
        """Max pin length mapping

        Returns:
            PinData[int]: Mapping of pin type: max length
        """
        return {
            "pin": int(self.field("maxpinlen", index=0, default=0)),
            "reset": int(self.field("maxpinlen", index=1, default=0)),
            "admin": int(self.field("maxpinlen", index=2, default=0)),
        }

    @computed_field
    @property
    def pin_retries(self) -> PinData[int]:
        """Remaining pin retry mapping

        Returns:
            PinData[int]: Mapping of pin type: remaining retries
        """
        return {
            "pin": int(self.field("pinretry", index=0, default=0)),
            "reset": int(self.field("pinretry", index=1, default=0)),
            "admin": int(self.field("pinretry", index=2, default=0)),
        }

    @computed_field
    @property
    def signature_count(self) -> int | None:
        """Count of stored signatures

        Returns:
            int | None: Count, or None
        """
        return int(self.field("sigcount", default=0))

    @computed_field
    @property
    def kdf_setting(self) -> bool:
        """Current KDF setting

        Returns:
            bool: KDF State
        """
        return self.field("kdf") == "on"

    @computed_field
    @property
    def uif_setting(self) -> UIFData:
        """UIF Data (usage)

        Returns:
            UIFData: Mapping of usage: enabled
        """
        return {
            "sign": bool(int(self.field("uif", index=0, default=0))),
            "decrypt": bool(int(self.field("uif", index=1, default=0))),
            "auth": bool(int(self.field("uif", index=2, default=0))),
        }

    @computed_field
    @property
    def stored_keys(self) -> list[KeyData]:
        """Information about the stored keys.

        Returns:
            list[KeyData]: List of KeyData.
        """
        fprs = self.lines.get("fpr", [])
        fprtimes = self.lines.get("fprtime", [])
        grps = self.lines.get("grp", [])

        results: list[KeyData] = []
        for fpr, ftime, grp in zip_longest(fprs, fprtimes, grps):
            if len(fpr) == 0:
                continue
            try:
                created = datetime.fromtimestamp(float(ftime)) if ftime else None
            except:
                created = None
            results.append({"fingerprint": fpr, "created": created, "keygrip": grp})

        return results
