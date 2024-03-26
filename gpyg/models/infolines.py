import datetime
from enum import IntEnum, StrEnum
from pydantic import BaseModel, computed_field


class InfoRecord(StrEnum):
    """Describes the type of an individual record."""
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
    """Describes the validity of a specific record, for instance that of a key or UID"""
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
    """Describes the validity of an individual signature."""
    GOOD = "!"
    BAD = "-"
    NO_PUBLIC_KEY = "?"
    UNKNOWN_ERROR = "%"


class KeyCapability(StrEnum):
    """Describes a capability of a key."""
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
    """Raw information about a single Key record"""

    @computed_field
    @property
    def validity(self) -> FieldValidity | None:
        """Key validity

        Returns:
            FieldValidity | None: Key validity, if available
        """
        return FieldValidity(self.field(2)) if self.field(2) else None

    @computed_field
    @property
    def length(self) -> int:
        """Key length

        Returns:
            int: Key length, or 0 if unavailable
        """
        return int(self.field(3))

    @computed_field
    @property
    def algorithm(self) -> int:
        """The algorithm ID used for this key

        Returns:
            int: Algorithm ID
        """
        return int(self.field(4))

    @computed_field
    @property
    def key_id(self) -> str:
        """The key's ID

        Returns:
            str: Key ID
        """
        return self.field(5)

    @computed_field
    @property
    def creation_date(self) -> datetime.datetime | None:
        """The key's creation date

        Returns:
            datetime.datetime | None: Creation date, if available
        """
        value = self.field(6)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    @property
    def expiration_date(self) -> datetime.datetime | None:
        """The key's expiration date

        Returns:
            datetime.datetime | None: Expiration date, if available
        """
        value = self.field(7)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    @property
    def owner_trust(self) -> str | None:
        """The owner trust value

        Returns:
            str | None: Owner trust, if available
        """
        return self.field(9)

    @computed_field
    @property
    def capabilities(self) -> list[KeyCapability]:
        """Key capabilities

        Returns:
            list[KeyCapability]: A list of all capabilities associated with this key
        """
        value = self.field(12)
        if value == None:
            return []

        return [KeyCapability(i) for i in value if i.lower() == i]

    @computed_field
    @property
    def overall_capabilities(self) -> list[KeyCapability]:
        """Overall key capabilities

        Returns:
            list[KeyCapability]: A list of all capabilities associated with this key and its subkeys
        """
        value = self.field(12)
        if value == None:
            return []

        return [KeyCapability(i.lower()) for i in value if i.lower() != i]

    @computed_field
    @property
    def curve_name(self) -> str | None:
        """The name of this key's ECC curve

        Returns:
            str | None: Curve name, if available
        """
        return self.field(17)


# fpr, fp2
class FingerprintInfo(InfoLine):
    @computed_field
    @property
    def fingerprint(self) -> str:
        return self.field(10)


# grp
class KeygripInfo(InfoLine):

    @computed_field
    @property
    def keygrip(self) -> str:
        return self.field(10)


# sec, ssb
class SecretKeyInfo(KeyInfo):
    """An extension to KeyInfo, adding S/N info"""

    @computed_field
    @property
    def serial_number(self) -> str | None:
        """The serial number of this key

        Returns:
            str | None: S/N, if available
        """
        return self.field(15)


# uid
class UserIDInfo(InfoLine):
    """Info pertaining to a single UID"""

    @computed_field
    @property
    def validity(self) -> FieldValidity | None:
        """This UID's validity

        Returns:
            FieldValidity | None: UID validity, if available
        """
        return FieldValidity(self.field(2)) if self.field(2) else None

    @computed_field
    @property
    def creation_date(self) -> datetime.datetime | None:
        """UID creation date

        Returns:
            datetime.datetime | None: Creation date, if available
        """
        value = self.field(6)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    @property
    def expiration_date(self) -> datetime.datetime | None:
        """UID expiration date

        Returns:
            datetime.datetime | None: Expiration date, if available
        """
        value = self.field(7)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    @property
    def uid_hash(self) -> str | None:
        """The UID hash

        Returns:
            str | None: UID hash, if available
        """
        return self.field(8)

    @computed_field
    @property
    def uid(self) -> str:
        """Full UID string

        Returns:
            str: The UID string
        """
        return self.field(10)


# sig, rev
class SignatureInfo(InfoLine):
    """Info about a single signature (revocation & non-revocation)"""

    @computed_field
    @property
    def is_revocation(self) -> bool:
        """Whether this signature is a revocation signature

        Returns:
            bool: True if revocation, false otherwise
        """
        return self.record_type == InfoRecord.REVOCATION_SIGNATURE

    @computed_field
    @property
    def validity(self) -> SignatureValidity | None:
        """The validity of this signature

        Returns:
            SignatureValidity | None: The signature's validity, if available
        """
        value = self.field(2)
        if value and len(value) > 0:
            return SignatureValidity(value[0])
        else:
            return None

    @computed_field
    @property
    def algorithm(self) -> int:
        """The signature's algorithm

        Returns:
            int: Algorithm ID
        """
        return int(self.field(4))

    @computed_field
    @property
    def key_id(self) -> str:
        """The signer's key ID

        Returns:
            str: Key ID
        """
        return self.field(5)

    @computed_field
    @property
    def creation_date(self) -> datetime.datetime | None:
        """Signature creation date

        Returns:
            datetime.datetime | None: Creation date, if available
        """
        value = self.field(6)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    @property
    def expiration_date(self) -> datetime.datetime | None:
        """The signature's expiration date

        Returns:
            datetime.datetime | None: Expiration date, if available
        """
        value = self.field(7)
        if value:
            if "T" in value:
                return datetime.datetime.fromisoformat(value)
            else:
                return datetime.datetime.fromtimestamp(float(value))
        return None

    @computed_field
    @property
    def uid(self) -> str:
        """The UID of the signature

        Returns:
            str: Signature UID
        """
        return self.field(10)

    @computed_field
    @property
    def signature_class(self) -> str:
        """The signature class

        Returns:
            str: Signature class info
        """
        return self.field(11)

    @computed_field
    @property
    def signer_fingerprint(self) -> str:
        """The fingerprint of the signer's key

        Returns:
            str: Key fingerprint
        """
        return self.field(13)


# tru
class TrustInfo(InfoLine):

    @computed_field
    @property
    def staleness(self) -> None | StaleTrustReason:
        return StaleTrustReason(self.field(2)) if self.field(2) else None

    @computed_field
    @property
    def trust_model(self) -> TrustModel:
        return TrustModel(int(self.field(3)))

    @computed_field
    @property
    def creation_date(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(float(self.field(4)))

    @computed_field
    @property
    def expiration_date(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(float(self.field(5)))

    @computed_field
    @property
    def marginals_needed(self) -> int:
        return int(self.field(6))

    @computed_field
    @property
    def completes_needed(self) -> int:
        return int(self.field(7))

    @computed_field
    @property
    def max_cert_depth(self) -> int:
        return int(self.field(8))


def parse_infoline(line: str) -> InfoLine:
    """Parses a raw infoline into either a generic InfoLine or one of the specific types

    Args:
        line (str): Line to parse

    Returns:
        InfoLine: InfoLine or a subclass
    """
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
