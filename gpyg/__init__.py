import json
import os

try:
    from .lib import *
except:
    from .bootstrap import bootstrap

    bootstrap(
        os.path.join(os.path.dirname(__file__), "gpgme.prefix"),
        os.path.join(os.path.dirname(__file__), "gpgme"),
    )
    from .lib import *

from .gpgme import (
    GpgErr,
    GpgmeAttr,
    GpgmeAuditlog,
    GpgmeConf,
    GpgmeCreate,
    GpgmeData,
    GpgmeDecrypt,
    GpgmeDelete,
    GpgmeEncrypt,
    GpgmeEvent,
    GpgmeExport,
    GpgmeImport,
    GpgmeKeylist,
    GpgmeKeyorg,
    GpgmeKeysign,
    GpgmeMd,
    GpgmePinentry,
    GpgmePk,
    GpgmeProtocol,
    GpgmeSig,
    GpgmeSigsum,
    GpgmeSpawn,
    GpgmeStatus,
    GpgmeTofu,
    GpgmeValidity,
)
