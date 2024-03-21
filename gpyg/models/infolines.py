import datetime
from enum import IntEnum, StrEnum
from typing import Any, Literal
from typing_extensions import Literal
from pydantic import BaseModel, computed_field, model_serializer
from pydantic_core import to_jsonable_python


class InfoRecord(StrEnum):
    PUBLIC_KEY = "pub"
    X509_CERTIFICATE = "crt"
    X509_CERTIFICATE_WITH_SECRET = "crs"
    SUBKEY = "sub"
    SECRET_KEY = "sec"
    SECRET_SUBKEY = "ssb"
    USER_ID = "uid"
    USER_ATTRIBUTE = "uat"
    SIGNATURE = "sig"
    REVOCATION_SIGNATURE = "rev"
    REVOCATION_SIGNATURE_STANDALONE = "rvs"
    FINGERPRINT = "fpr"
    SHA256_FINGERPRINT = "fp2"
    PUBLIC_KEY_DATA = "pkd"
    KEYGRIP = "grp"
    REVOCATION_KEY = "rvk"
    TOFU_DATA = "tfs"
    TRUST_INFO = "tru"
    SIGNATURE_SUBPACKET = "spk"
    CONFIG_DATA = "cfg"


class FieldValidity(StrEnum):
    UNKNOWN = "o"
    INVALID = "i"
    DISABLED = "d"
    REVOKED = "r"
    EXPIRED = "e"
    UNKNOWN_VALIDITY = "-"
    UNDEFINED_VALIDITY = "q"
    NOT_VALID = "n"
    MARGINAL_VALID = "m"
    FULLY_VALID = "f"
    ULTIMATELY_VALID = "u"
    WELL_KNOWN = "w"
    SPECIAL = "s"


class SignatureValidity(StrEnum):
    GOOD = "!"
    BAD = "-"
    NO_PUBLIC_KEY = "?"
    UNKNOWN_ERROR = "%"


class KeyCapability(StrEnum):
    ENCRYPT = "e"
    SIGN = "s"
    CERTIFY = "c"
    AUTHENTICATION = "a"
    RESTRICTED_ENCRYPTION = "r"
    TIMESTAMPING = "t"
    GROUP_KEY = "g"
    UNKNOWN = "?"
    DISABLED = "d"


class StaleTrustReason(StrEnum):
    OLD = "o"
    DIFFERENT_MODEL = "t"


class TrustModel(IntEnum):
    CLASSIC = 0
    PGP = 1


class InfoLine(BaseModel):
    record_type: InfoRecord
    field_array: list[str | None]

    def field(self, field: int) -> str | None:
        """Get field value based on indices from https://github.com/gpg/gnupg/blob/master/doc/DETAILS

        Args:
            field (int): Field number (1-21)

        Raises:
            KeyError: If field is unknown

        Returns:
            str | None: Field value or None if empty.
        """
        if field < 1 or field > 21:
            raise KeyError("Unknown field number.")

        if field == 1:
            return self.record_type

        try:
            return self.field_array[field - 2]
        except:
            return None

    @classmethod
    def from_line(cls, line: str) -> "InfoLine":
        parts = line.split(":")
        return cls(
            record_type=parts[0],
            field_array=[i if len(i) > 0 else None for i in parts[1:]],
        )

    @property
    def fields(self) -> list[str | None]:
        return [self.field(i) for i in range(2, 22)]


# pub, sub
class KeyInfo(InfoLine):

    @computed_field
    def validity(self) -> FieldValidity | None:
        return FieldValidity(self.field(2)) if self.field(2) else None

    @computed_field
    def length(self) -> int:
        return int(self.field(3))

    @computed_field
    def algorithm(self) -> int:
        return int(self.field(4))

    @computed_field
    def key_id(self) -> str:
        return self.field(5)

    @computed_field
    def creation_date(self) -> datetime.datetime | None:
        value = self.field(6)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    def expiration_date(self) -> datetime.datetime | None:
        value = self.field(7)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    def owner_trust(self) -> str | None:
        return self.field(9)

    @computed_field
    def capabilities(self) -> list[KeyCapability]:
        value = self.field(12)
        if value == None:
            return []

        return [KeyCapability(i) for i in value if i.lower() == i]

    @computed_field
    def overall_capabilities(self) -> list[KeyCapability]:
        value = self.field(12)
        if value == None:
            return []

        return [KeyCapability(i.lower()) for i in value if i.lower() != i]

    @computed_field
    def curve_name(self) -> str | None:
        return self.field(17)


# fpr, fp2
class FingerprintInfo(InfoLine):

    @computed_field
    def fingerprint(self) -> str:
        return self.field(10)


# grp
class KeygripInfo(InfoLine):

    @computed_field
    def keygrip(self) -> str:
        return self.field(10)


# sec, ssb
class SecretKeyInfo(KeyInfo):

    @computed_field
    def serial_number(self) -> str | None:
        return self.field(15)


# uid
class UserIDInfo(InfoLine):

    @computed_field
    def validity(self) -> FieldValidity | None:
        return FieldValidity(self.field(2)) if self.field(2) else None

    @computed_field
    def creation_date(self) -> datetime.datetime | None:
        value = self.field(6)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    def expiration_date(self) -> datetime.datetime | None:
        value = self.field(7)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    def uid_hash(self) -> str | None:
        return self.field(8)

    @computed_field
    def uid(self) -> str:
        return self.field(10)


# sig, rev
class SignatureInfo(InfoLine):

    @computed_field
    def is_revocation(self) -> bool:
        return self.record_type == InfoRecord.REVOCATION_SIGNATURE

    @computed_field
    def validity(self) -> SignatureValidity | None:
        value = self.field(2)
        if value and len(value) > 0:
            return SignatureValidity(value[0])
        else:
            return None

    @computed_field
    def algorithm(self) -> int:
        return int(self.field(4))

    @computed_field
    def key_id(self) -> str:
        return self.field(5)

    @computed_field
    def creation_date(self) -> datetime.datetime | None:
        value = self.field(6)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    def expiration_date(self) -> datetime.datetime | None:
        value = self.field(7)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    def uid(self) -> str:
        return self.field(10)

    @computed_field
    def signature_class(self) -> str:
        return self.field(11)

    @computed_field
    def signer_fingerprint(self) -> str:
        return self.field(13)


# tru
class TrustInfo(InfoLine):

    @computed_field
    def staleness(self) -> None | StaleTrustReason:
        return StaleTrustReason(self.field(2)) if self.field(2) else None

    @computed_field
    def trust_model(self) -> TrustModel:
        return TrustModel(int(self.field(3)))

    @computed_field
    def creation_date(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(float(self.field(4)))

    @computed_field
    def expiration_date(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(float(self.field(5)))

    @computed_field
    def marginals_needed(self) -> int:
        return int(self.field(6))

    @computed_field
    def completes_needed(self) -> int:
        return int(self.field(7))

    @computed_field
    def max_cert_depth(self) -> int:
        return int(self.field(8))


def parse_infoline(line: str) -> InfoLine:
    initial_parse = InfoLine.from_line(line)
    match initial_parse.record_type:
        case InfoRecord.PUBLIC_KEY:
            return KeyInfo.from_line(line)

        case InfoRecord.SUBKEY:
            return KeyInfo.from_line(line)

        case InfoRecord.SECRET_KEY:
            return SecretKeyInfo.from_line(line)

        case InfoRecord.SECRET_SUBKEY:
            return SecretKeyInfo.from_line(line)

        case InfoRecord.FINGERPRINT:
            return FingerprintInfo.from_line(line)

        case InfoRecord.SHA256_FINGERPRINT:
            return FingerprintInfo.from_line(line)

        case InfoRecord.USER_ID:
            return UserIDInfo.from_line(line)

        case InfoRecord.SIGNATURE:
            return SignatureInfo.from_line(line)

        case InfoRecord.REVOCATION_SIGNATURE:
            return SignatureInfo.from_line(line)

        case InfoRecord.TRUST_INFO:
            return TrustInfo.from_line(line)

        case InfoRecord.KEYGRIP:
            return KeygripInfo.from_line(line)

        case _:
            return initial_parse
