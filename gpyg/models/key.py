from pydantic import BaseModel
from .infolines import *
from datetime import datetime


class SubkeyModel(BaseModel):
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
    signatures: list[SignatureInfo] = []
    user_ids: list[UserIDInfo] = []


class KeyModel(BaseModel):
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
    signatures: list[SignatureInfo] = []
    user_ids: list[UserIDInfo] = []
    subkeys: list[SubkeyModel] = []

    @staticmethod
    def get_subkeys(
        key: "KeyModel", subkey_map: dict[str, list["KeyModel"]]
    ) -> list["KeyModel"]:
        if key.fingerprint and key.fingerprint in subkey_map.keys():
            key.subkeys = subkey_map[key.fingerprint]
            return key.subkeys
        else:
            return []

    @classmethod
    def from_infolines(cls, lines: list[InfoLine]) -> list["KeyModel"]:
        key_mapping: dict[str, list[KeyModel | SubkeyModel]] = {"root": []}
        context: KeyModel = None
        for line in lines:
            if line.record_type in [
                InfoRecord.PUBLIC_KEY,
                InfoRecord.SECRET_KEY,
                InfoRecord.SUBKEY,
                InfoRecord.SECRET_SUBKEY,
            ]:
                if context:
                    initial_sigs = [
                        i
                        for i in context.signatures
                        if i.creation_date == context.creation_date
                    ]
                    if (
                        len(initial_sigs) == 0
                        or initial_sigs[0].signer_fingerprint == context.fingerprint
                    ):
                        key_mapping["root"].append(context)
                    else:
                        if not initial_sigs[0].signer_fingerprint in key_mapping.keys():
                            key_mapping[initial_sigs[0].signer_fingerprint] = []
                        key_mapping[initial_sigs[0].signer_fingerprint].append(context)

                context = (
                    KeyModel(
                        type=(
                            "public"
                            if line.record_type == InfoRecord.PUBLIC_KEY
                            else "secret"
                        ),
                        **line.as_dict(),
                    )
                    if line.record_type
                    in [InfoRecord.PUBLIC_KEY, InfoRecord.SECRET_KEY]
                    else SubkeyModel(
                        type=(
                            "public"
                            if line.record_type == InfoRecord.SUBKEY
                            else "secret"
                        ),
                        **line.as_dict(),
                    )
                )
            elif (
                line.record_type
                in [InfoRecord.FINGERPRINT, InfoRecord.SHA256_FINGERPRINT]
                and context
            ):
                context.fingerprint = line.fingerprint
            elif line.record_type == InfoRecord.KEYGRIP and context:
                context.keygrip = line.keygrip
            elif line.record_type == InfoRecord.USER_ID and context:
                context.user_ids.append(line)
            elif line.record_type == InfoRecord.SIGNATURE and context:
                context.signatures.append(line)

        if context:
            initial_sigs = [
                i
                for i in context.signatures
                if i.creation_date == context.creation_date
            ]
            if (
                len(initial_sigs) == 0
                or initial_sigs[0].signer_fingerprint == context.fingerprint
            ):
                key_mapping["root"].append(context)
            else:
                if not initial_sigs[0].signer_fingerprint in key_mapping.keys():
                    key_mapping[initial_sigs[0].signer_fingerprint] = []
                key_mapping[initial_sigs[0].signer_fingerprint].append(context)

        results = key_mapping["root"][:]
        for key in results:
            key.subkeys = KeyModel.get_subkeys(key, key_mapping)

        return results
