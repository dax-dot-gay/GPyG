from pydantic import BaseModel

class GPGConfig(BaseModel):
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