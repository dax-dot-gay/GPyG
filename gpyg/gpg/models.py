from datetime import date, datetime
from pydantic import BaseModel
from enum import IntEnum, StrEnum

InfoLine = tuple[str, list[str | None]]

class KeyGenerationResult(BaseModel):
    fingerprint: str | None = None
    homedir: str | None
    output: str
    code: int


class Validity(StrEnum):
    UNKNOWN_KEY = "o"
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
    WELL_KNOWN_PRIVATE = "w"
    SPECIAL = "s"

    @classmethod
    def from_character(cls, character: str) -> "Validity | None":
        try:
            return Validity(character)
        except:
            return None


class PublicKeyAlgorithms(IntEnum):
    UNKNOWN = -1
    RSA_ENCRYPT_SIGN = 1
    RSA_ENCRYPT = 2
    RSA_SIGN = 3
    ELGAMAL = 16
    DSA = 17
    ELLIPTIC_CURVE = 18
    ECDSA = 19
    DIFFIE_HELLMAN = 21

    @classmethod
    def from_id(cls, id: int) -> "PublicKeyAlgorithms":
        try:
            return PublicKeyAlgorithms(id)
        except:
            return PublicKeyAlgorithms.UNKNOWN


class SymmetricKeyAlgorithms(IntEnum):
    UNKNOWN = -1
    PLAINTEXT = 0
    IDEA = 1
    TRIPLE_DES = 2
    CAST5 = 3
    BLOWFISH = 4
    AES_128 = 7
    AES_192 = 8
    AES_256 = 9
    TWOFISH_256 = 10

    @classmethod
    def from_id(cls, id: int) -> "SymmetricKeyAlgorithms":
        try:
            return SymmetricKeyAlgorithms(id)
        except:
            return SymmetricKeyAlgorithms.UNKNOWN


class CompressionAlgorithms(IntEnum):
    UNKNOWN = -1
    UNCOMPRESSED = 0
    ZIP = 1
    ZLIB = 2
    BZIP2 = 3

    @classmethod
    def from_id(cls, id: int) -> "CompressionAlgorithms":
        try:
            return CompressionAlgorithms(id)
        except:
            return CompressionAlgorithms.UNKNOWN


class HashAlgorithms(IntEnum):
    UNKNOWN = -1
    MD5 = 1
    SHA1 = 2
    RIPE_MD = 3
    SHA256 = 8
    SHA384 = 9
    SHA512 = 10
    SHA224 = 11

    @classmethod
    def from_id(cls, id: int) -> "HashAlgorithms":
        try:
            return HashAlgorithms(id)
        except:
            return HashAlgorithms.UNKNOWN


class KeyInfo_PK(BaseModel):
    validity: Validity | None = None
    length: int | None = None
    algorithm: PublicKeyAlgorithms = PublicKeyAlgorithms.UNKNOWN
    key_id: str | None = None
    creation_date: date | None = None
    expiration_date: date | None = None
    owner_trust: str | None = None
    capabilities: str | None = None
    secret_key: bool = False
    last_update: datetime | None = None
    origin: str | None = None
    comment: str | None = None

    @classmethod
    def from_line(cls, line: InfoLine) -> "KeyInfo_PK":
        fields = line[1]
        while len(fields) < 22:
            fields.append(None)
        return KeyInfo_PK(
            validity=Validity.from_character(fields[0]),
            length=fields[1],
            algorithm=(
                PublicKeyAlgorithms.from_id(int(fields[2])) if fields[2] else None
            ),
            key_id=fields[3],
            creation_date=(
                (
                    date.fromisoformat(fields[4])
                    if "T" in fields[4]
                    else date.fromtimestamp(int(fields[4]))
                )
                if fields[4]
                else None
            ),
            expiration_date=(
                (
                    date.fromisoformat(fields[5])
                    if "T" in fields[5]
                    else date.fromtimestamp(int(fields[5]))
                )
                if fields[5]
                else None
            ),
            owner_trust=fields[7],
            capabilities=fields[10],
            secret_key=fields[13] == "+",
            last_update=fields[17],
            origin=fields[18],
            comment=fields[19],
        )


class KeyInfo_SK(BaseModel):
    validity: Validity | None = None
    length: int | None = None
    algorithm: PublicKeyAlgorithms = PublicKeyAlgorithms.UNKNOWN
    key_id: str | None = None
    creation_date: date | None = None
    expiration_date: date | None = None
    owner_trust: str | None = None
    capabilities: str | None = None
    last_update: datetime | None = None
    origin: str | None = None
    comment: str | None = None

    @classmethod
    def from_line(cls, line: InfoLine) -> "KeyInfo_SK":
        fields = line[1]
        while len(fields) < 22:
            fields.append(None)
        return KeyInfo_SK(
            validity=Validity.from_character(fields[0]),
            length=fields[1],
            algorithm=(
                PublicKeyAlgorithms.from_id(int(fields[2])) if fields[2] else None
            ),
            key_id=fields[3],
            creation_date=(
                (
                    date.fromisoformat(fields[4])
                    if "T" in fields[4]
                    else date.fromtimestamp(int(fields[4]))
                )
                if fields[4]
                else None
            ),
            expiration_date=(
                (
                    date.fromisoformat(fields[5])
                    if "T" in fields[5]
                    else date.fromtimestamp(int(fields[5]))
                )
                if fields[5]
                else None
            ),
            owner_trust=fields[7],
            capabilities=fields[10],
            last_update=fields[17],
            origin=fields[18],
            comment=fields[19],
        )


class KeyInfo_UID(BaseModel):
    validity: Validity | None = None
    creation_date: date | None = None
    expiration_date: date | None = None
    user_hash: str | None = None
    user_id: str | None = None
    last_update: datetime | None = None
    origin: str | None = None
    comment: str | None = None

    @classmethod
    def from_line(cls, line: InfoLine) -> "KeyInfo_UID":
        fields = line[1]
        while len(fields) < 22:
            fields.append(None)
        return KeyInfo_UID(
            validity=Validity.from_character(fields[0]),
            key_id=fields[3],
            creation_date=(
                (
                    date.fromisoformat(fields[4])
                    if "T" in fields[4]
                    else date.fromtimestamp(int(fields[4]))
                )
                if fields[4]
                else None
            ),
            expiration_date=(
                (
                    date.fromisoformat(fields[5])
                    if "T" in fields[5]
                    else date.fromtimestamp(int(fields[5]))
                )
                if fields[5]
                else None
            ),
            user_hash=fields[6],
            user_id=fields[8],
            last_update=fields[17],
            origin=fields[18],
            comment=fields[19],
        )


class KeyInfo(BaseModel):
    public_key: KeyInfo_PK | None = None
    secret_key: KeyInfo_SK | None = None
    fingerprint: str | None = None
    user_id: KeyInfo_UID | None = None
    keygrip: str | None = None

    @classmethod
    def from_lines(cls, lines: list[InfoLine]) -> "KeyInfo":
        result = KeyInfo()
        for line in lines:
            if line[0] == "pub":
                result.public_key = KeyInfo_PK.from_line(line)
            if line[0] == "fpr":
                result.fingerprint = line[1][8]
            if line[0] == "uid":
                result.user_id = KeyInfo_UID.from_line(line)
            if line[0] == "sec":
                result.secret_key = KeyInfo_SK.from_line(line)
            if line[0] == "grp":
                result.keygrip = line[1][8]
        return result


class GPGError(Exception):
    pass
