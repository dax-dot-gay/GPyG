from pydantic import BaseModel

class GPGConfig(BaseModel):
    """A class describing the configuration of the underlying GPG instance.

    Attributes:
        version (str): The version of GPG on the host system
        public_key_algorithms (dict[str, int]): A mapping of {algorithm name: algorithm ID} for all PK algorithms supported by the local GPG implementation.
        symmetric_algorithms (dict[str, int]): A mapping of {algorithm name: algorithm ID} for all symmetric algorithms supported by the local GPG implementation.
        digest_algorithms (dict[str, int]): A mapping of {algorithm name: algorithm ID} for all digest algorithms supported by the local GPG implementation.
        compression_algorithms (dict[str, int]): A mapping of {algorithm name: algorithm ID} for all compression algorithms supported by the local GPG implementation.
        ecc_curves (list[str]): A list of all ECC curve names supported by the local GPG implementation
    """

    version: str
    public_key_algorithms: dict[str, int]
    symmetric_algorithms: dict[str, int]
    digest_algorithms: dict[str, int]
    compression_algorithms: dict[str, int]
    ecc_curves: list[str]

    @classmethod
    def from_config_text(cls, data: str) -> "GPGConfig":
        fields = {line.split(":")[1]: line.split(":")[2].split(";") if ";" in line else line.split(":")[2] for line in data.splitlines() if line.startswith("cfg:")}

        return GPGConfig(
            version=fields["version"],
            public_key_algorithms={name: int(id) for name, id in zip(fields["pubkeyname"], fields["pubkey"])},
            symmetric_algorithms={name: int(id) for name, id in zip(fields["ciphername"], fields["cipher"])},
            digest_algorithms={name: int(id) for name, id in zip(fields["digestname"], fields["digest"])},
            compression_algorithms={name: int(id) for name, id in zip(fields["compressname"], fields["compress"])},
            ecc_curves=fields["curve"]
        )
