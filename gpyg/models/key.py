from typing import Literal
from pydantic import BaseModel, Field, computed_field
from .infolines import *
from datetime import datetime


class KeyModel(BaseModel):
    """The base KeyModel, containing all relevant information about a key.

    Attributes:
        is_subkey (bool): Whether the key is a subkey
        type (public | secret): What kind of key this is
        validity (FieldValidity): The validity status of the key
        length (int): The key's length
        algorithm (int): The ID of the algorithm used to generate the key
        key_id (str): The key's ID
        creation_date (datetime | None): When the key was created
        expiration_date (datetime | None): When the key will expire
        owner_trust (str | None): The trust value of the key owner
        capabilities (list[KeyCapability]): A list of the key's capabilities
        overall_capabilities (list[KeyCapability]): A list of the key's capabilities, including those of its subkeys.
        curve_name (str | None): ECC curve name
        serial_number (str | None): Key S/N
        fingerprint (str | None): Key fingerprint
        keygrip (str | None): Key keygrip
        all_signatures (list[SignatureInfo]): List of all signatures (revocation & non-revocation)
        user_ids (list[UserIDInfo]): List of this key's user IDs
    """

    is_subkey: bool = False
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
    all_signatures: list[SignatureInfo] = []
    user_ids: list[UserIDInfo] = []
    internal_subkeys: list["KeyModel"] = Field(exclude=True, default_factory=list)

    @computed_field
    @property
    def subkeys(self) -> list["KeyModel"] | None:
        """A list of all subkeys, or None if the key is a subkey.

        Returns:
            list[KeyModel] | None: List of subkeys
        """
        if self.is_subkey:
            return None
        return self.internal_subkeys

    @computed_field
    @property
    def signatures(self) -> list[SignatureInfo]:
        """Gets all non-revocation signatures attached to this key

        Returns:
            list[SignatureInfo]: List of signatures
        """
        return [i for i in self.all_signatures if not i.is_revocation]

    @computed_field
    @property
    def revocation_signatures(self) -> list[SignatureInfo]:
        """Gets all revocation signatures attached to this key

        Returns:
            list[SignatureInfo]: List of revocation signatures
        """
        return [i for i in self.all_signatures if i.is_revocation]

    @staticmethod
    def get_subkeys(
        key: "KeyModel", subkey_map: dict[str, list["KeyModel"]]
    ) -> list["KeyModel"]:
        if key.fingerprint and key.fingerprint in subkey_map.keys():
            for subkey in subkey_map[key.fingerprint]:
                subkey.internal_subkeys = KeyModel.get_subkeys(subkey, subkey_map)
                key.internal_subkeys.append(subkey)
            return key.internal_subkeys
        else:
            return []

    @classmethod
    def from_infolines(cls, lines: list[InfoLine]) -> list["KeyModel"]:
        key_mapping: dict[str, list[KeyModel]] = {"root": []}
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
                        **line.model_dump(),
                    )
                    if line.record_type
                    in [InfoRecord.PUBLIC_KEY, InfoRecord.SECRET_KEY]
                    else KeyModel(
                        type=(
                            "public"
                            if line.record_type == InfoRecord.SUBKEY
                            else "secret"
                        ),
                        is_subkey=True,
                        **line.model_dump(),
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
                context.all_signatures.append(line)
            elif line.record_type == InfoRecord.REVOCATION_SIGNATURE and context:
                context.all_signatures.append(line)

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
            key.internal_subkeys = KeyModel.get_subkeys(key, key_mapping)

        return results
