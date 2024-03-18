from typing import Any
from pydantic import BaseModel
from ...gpgme import GpgmeKeylist, GpgmeProtocol, GpgmeValidity, GpgmePk, GpgmeSig


class SignatureNotation(BaseModel):
    name: str | None
    value: str | None
    human_readable: bool
    critical: bool

    @classmethod
    def create(cls, notation: Any) -> "SignatureNotation":
        return SignatureNotation(
            name=notation.name,
            value=notation.value,
            human_readable=notation.human_readable,
            critical=notation.critical,
        )


class Signature(BaseModel):
    revoked: bool
    expired: bool
    invalid: bool
    exportable: bool
    trust_value: int
    pubkey_algo: GpgmePk
    keyid: str
    timestamp: int
    expires: int
    trust_scope: str | None
    status: int | None
    signature_class: int | None
    uid: str
    name: str | None
    comment: str | None
    email: str | None
    notations: list[SignatureNotation]

    @classmethod
    def create(cls, sig: Any) -> "Signature":
        return Signature(
            revoked=sig.revoked,
            expired=sig.expired,
            invalid=sig.invalid,
            exportable=sig.exportable,
            trust_value=sig.trust_value,
            pubkey_algo=sig.pubkey_algo,
            keyid=sig.keyid,
            timestamp=sig.timestamp,
            expires=sig.expires,
            trust_scope=sig.trust_scope,
            status=sig.status,
            signature_class=sig.sig_class,
            uid=sig.uid,
            name=sig.name,
            comment=sig.comment,
            email=sig.email,
            notations=[SignatureNotation.create(i) for i in sig.notations],
        )


class TOFUInfo(BaseModel):
    validity: int
    policy: int
    sign_count: int
    encr_count: int
    first_sign: int
    last_sign: int
    first_encr: int
    last_encr: int
    description: str | None

    @classmethod
    def create(cls, tofu: Any) -> "TOFUInfo":
        return TOFUInfo(
            validity=tofu.validity,
            policy=tofu.policy,
            sign_count=tofu.signcount,
            encr_count=tofu.encrcount,
            first_sign=tofu.signfirst,
            last_sign=tofu.signlast,
            first_encr=tofu.encrfirst,
            last_encr=tofu.encrlast,
            description=tofu.description,
        )


class UserID(BaseModel):
    revoked: bool
    invalid: bool
    validity: GpgmeValidity
    uid: str
    name: str | None
    comment: str | None
    email: str | None
    address: str | None
    origin: int
    last_update: float | int
    uid_hash: str
    tofu: list[TOFUInfo]
    signatures: list[Signature]

    @classmethod
    def create(cls, uid: Any) -> "UserID":
        return UserID(
            revoked=uid.revoked,
            invalid=uid.invalid,
            validity=uid.validity,
            uid=uid.uid,
            name=uid.name,
            comment=uid.comment,
            email=uid.email,
            address=uid.address,
            origin=uid.origin,
            last_update=uid.last_update,
            uid_hash=uid.uidhash,
            tofu=[TOFUInfo.create(i) for i in uid.tofu],
            signatures=[Signature.create(i) for i in uid.signatures],
        )


class Subkey(BaseModel):
    revoked: bool
    expired: bool
    disabled: bool
    invalid: bool
    can_encrypt: bool
    can_sign: bool
    can_certify: bool
    can_authenticate: bool
    is_qualified: bool
    is_de_vs: bool
    secret: bool
    pubkey_algo: GpgmePk
    length: int
    keyid: str
    fingerprint: str | None
    keygrip: str | None
    timestamp: int
    expires: int
    is_cardkey: bool
    card_number: str | None
    curve: str | None

    @classmethod
    def create(cls, key: Any) -> "Subkey":
        return Subkey(
            revoked=key.revoked,
            expired=key.expired,
            disabled=key.disabled,
            invalid=key.invalid,
            can_encrypt=key.can_encrypt,
            can_sign=key.can_sign,
            can_certify=key.can_certify,
            can_authenticate=key.can_authenticate,
            is_qualified=key.is_qualified,
            is_de_vs=key.is_de_vs,
            secret=key.secret,
            pubkey_algo=key.pubkey_algo,
            length=key.length,
            keyid=key.keyid,
            fingerprint=key.fpr,
            keygrip=key.keygrip,
            timestamp=key.timestamp,
            expires=key.expires,
            is_cardkey=key.is_cardkey,
            card_number=key.card_number,
            curve=key.curve,
        )


class Key(BaseModel):
    keylist_mode: GpgmeKeylist
    revoked: bool
    expired: bool
    disabled: bool
    invalid: bool
    can_encrypt: bool
    can_sign: bool
    can_certify: bool
    can_authenticate: bool
    has_encrypt: bool
    has_sign: bool
    has_certify: bool
    has_authenticate: bool
    is_qualified: bool
    secret: bool
    origin: int
    protocol: GpgmeProtocol
    issuer_serial: str | None
    issuer_name: str | None
    chain_id: str | None
    owner_trust: GpgmeValidity | None
    subkeys: list[Subkey]
    uids: list[UserID]
    fingerprint: str
    last_update: float | int

    @classmethod
    def create(cls, key: Any) -> "Key":
        return Key(
            keylist_mode=key.keylist_mode,
            revoked=key.revoked,
            expired=key.expired,
            disabled=key.disabled,
            invalid=key.invalid,
            can_encrypt=key.can_encrypt,
            can_sign=key.can_sign,
            can_certify=key.can_certify,
            can_authenticate=key.can_authenticate,
            has_encrypt=key.has_encrypt,
            has_sign=key.has_sign,
            has_certify=key.has_certify,
            has_authenticate=key.has_authenticate,
            is_qualified=key.is_qualified,
            secret=key.secret,
            origin=key.origin,
            protocol=key.protocol,
            issuer_serial=key.issuer_serial,
            issuer_name=key.issuer_name,
            chain_id=key.chain_id,
            owner_trust=key.owner_trust,
            subkeys=[Subkey.create(i) for i in key.subkeys],
            uids=[UserID.create(i) for i in key.uids],
            fingerprint=key.fpr,
            last_update=key.last_update,
        )
