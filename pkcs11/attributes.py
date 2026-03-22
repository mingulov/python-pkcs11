from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from struct import Struct
from typing import Any, Callable, Final

from pkcs11.constants import (
    Attribute,
    CertificateType,
    MechanismFlag,
    ObjectClass,
    Trust,
    ValidationAuthorityType,
    ValidationType,
)
from pkcs11.mechanisms import KeyType, Mechanism

# Type aliases for pack/unpack function pairs
PackFunc = Callable[[Any], Any]
UnpackFunc = Callable[[Any], Any]
Handler = tuple[PackFunc, UnpackFunc]

# (Pack Function, Unpack Function) functions
_bool_struct = Struct("?")
_ulong_struct = Struct("L")
_version_struct = Struct("BB")

handle_bool: Handler = (
    _bool_struct.pack,
    lambda v: False if len(v) == 0 else _bool_struct.unpack(v)[0],
)
handle_ulong: Handler = (_ulong_struct.pack, lambda v: _ulong_struct.unpack(v)[0])
handle_version: Handler = (lambda v: _version_struct.pack(*v), lambda v: _version_struct.unpack(v))
handle_str: Handler = (lambda s: s.encode("utf-8"), lambda b: b.decode("utf-8"))
def _parse_ck_date(s: bytes):
    """Parse CK_DATE bytes to datetime.date, or None if empty/invalid.

    Per OASIS spec, empty CK_DATE has ulValueLen=0, but older implementations
    may use 8 null bytes or spaces. Applications must be flexible.
    """
    if not s or len(s) < 8:
        return None
    text = s.decode("ascii", errors="replace").strip().strip("\x00")
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y%m%d").date()
    except ValueError:
        return None

handle_date: Handler = (
    lambda s: s.strftime("%Y%m%d").encode("ascii") if s is not None else b"",
    _parse_ck_date,
)
handle_bytes: Handler = (bytes, bytes)
# The PKCS#11 biginteger type is an array of bytes in network byte order.
# If you have an int type, wrap it in biginteger()
handle_biginteger: Handler = handle_bytes


def _enum(type_: type[IntEnum]) -> Handler:
    """Factory to pack/unpack ints into IntEnums."""
    pack, unpack = handle_ulong

    return (lambda v: pack(int(v)), lambda v: type_(unpack(v)))


def _mechanism_from_ulong(value: int) -> Mechanism | int:
    try:
        return Mechanism(value)
    except ValueError:
        return value


def _pack_ulong_array(values: Any) -> bytes:
    return b"".join(_ulong_struct.pack(int(value)) for value in values)


def _unpack_ulong_array(data: bytes) -> list[int]:
    width = _ulong_struct.size
    if len(data) % width:
        raise ValueError("attribute value length is not aligned to CK_ULONG")
    return [_ulong_struct.unpack(data[ix : ix + width])[0] for ix in range(0, len(data), width)]


handle_ulong_array: Handler = (_pack_ulong_array, _unpack_ulong_array)
handle_mechanism_array: Handler = (
    _pack_ulong_array,
    lambda data: [_mechanism_from_ulong(value) for value in _unpack_ulong_array(data)],
)
handle_attribute_template: Handler = (lambda value: dict(value), lambda value: dict(value))


ATTRIBUTE_TYPES: dict[Attribute, Handler] = {
    Attribute.ALWAYS_AUTHENTICATE: handle_bool,
    Attribute.ALWAYS_SENSITIVE: handle_bool,
    Attribute.APPLICATION: handle_str,
    Attribute.BASE: handle_biginteger,
    Attribute.CERTIFICATE_TYPE: _enum(CertificateType),
    Attribute.CHECK_VALUE: handle_bytes,
    Attribute.CLASS: _enum(ObjectClass),
    Attribute.COEFFICIENT: handle_biginteger,
    Attribute.DECAPSULATE: handle_bool,
    Attribute.DECRYPT: handle_bool,
    Attribute.DERIVE: handle_bool,
    Attribute.EC_PARAMS: handle_bytes,
    Attribute.EC_POINT: handle_bytes,
    Attribute.ENCAPSULATE: handle_bool,
    Attribute.ENCRYPT: handle_bool,
    Attribute.END_DATE: handle_date,
    Attribute.EXPONENT_1: handle_biginteger,
    Attribute.EXPONENT_2: handle_biginteger,
    Attribute.EXTRACTABLE: handle_bool,
    Attribute.HASH_OF_ISSUER_PUBLIC_KEY: handle_bytes,
    Attribute.HASH_OF_SUBJECT_PUBLIC_KEY: handle_bytes,
    Attribute.ID: handle_bytes,
    Attribute.PUBLIC_KEY_INFO: handle_bytes,
    Attribute.ISSUER: handle_bytes,
    Attribute.KEY_GEN_MECHANISM: _enum(Mechanism),
    Attribute.KEY_TYPE: _enum(KeyType),
    Attribute.LABEL: handle_str,
    Attribute.LOCAL: handle_bool,
    Attribute.MODIFIABLE: handle_bool,
    Attribute.COPYABLE: handle_bool,
    Attribute.DESTROYABLE: handle_bool,
    Attribute.MODULUS: handle_biginteger,
    Attribute.MODULUS_BITS: handle_ulong,
    Attribute.NEVER_EXTRACTABLE: handle_bool,
    Attribute.OBJECT_ID: handle_bytes,
    Attribute.WRAP_TEMPLATE: handle_attribute_template,
    Attribute.UNWRAP_TEMPLATE: handle_attribute_template,
    Attribute.DERIVE_TEMPLATE: handle_attribute_template,
    Attribute.ALLOWED_MECHANISMS: handle_mechanism_array,
    Attribute.HSS_LEVELS: handle_ulong,
    Attribute.HSS_LMS_TYPE: handle_ulong,
    Attribute.HSS_LMOTS_TYPE: handle_ulong,
    Attribute.HSS_LMS_TYPES: handle_ulong_array,
    Attribute.HSS_LMOTS_TYPES: handle_ulong_array,
    Attribute.HSS_KEYS_REMAINING: handle_ulong,
    Attribute.PARAMETER_SET: handle_ulong,
    Attribute.MECHANISM_TYPE: handle_ulong,
    Attribute.PROFILE_ID: handle_ulong,
    Attribute.OBJECT_VALIDATION_FLAGS: handle_ulong,
    Attribute.VALIDATION_TYPE: _enum(ValidationType),
    Attribute.VALIDATION_VERSION: handle_version,
    Attribute.VALIDATION_LEVEL: handle_ulong,
    Attribute.VALIDATION_MODULE_ID: handle_str,
    Attribute.VALIDATION_FLAG: handle_ulong,
    Attribute.VALIDATION_AUTHORITY_TYPE: _enum(ValidationAuthorityType),
    Attribute.VALIDATION_COUNTRY: handle_str,
    Attribute.VALIDATION_CERTIFICATE_IDENTIFIER: handle_str,
    Attribute.VALIDATION_CERTIFICATE_URI: handle_str,
    Attribute.VALIDATION_VENDOR_URI: handle_str,
    Attribute.VALIDATION_PROFILE: handle_str,
    Attribute.ENCAPSULATE_TEMPLATE: handle_attribute_template,
    Attribute.DECAPSULATE_TEMPLATE: handle_attribute_template,
    Attribute.HASH_OF_CERTIFICATE: handle_bytes,
    Attribute.PUBLIC_CRC64_VALUE: handle_bytes,
    Attribute.SEED: handle_bytes,
    Attribute.PRIME: handle_biginteger,
    Attribute.PRIME_BITS: handle_ulong,
    Attribute.PRIME_1: handle_biginteger,
    Attribute.PRIME_2: handle_biginteger,
    Attribute.PRIVATE: handle_bool,
    Attribute.PRIVATE_EXPONENT: handle_biginteger,
    Attribute.PUBLIC_EXPONENT: handle_biginteger,
    Attribute.SENSITIVE: handle_bool,
    Attribute.SERIAL_NUMBER: handle_bytes,
    Attribute.SIGN: handle_bool,
    Attribute.SIGN_RECOVER: handle_bool,
    Attribute.START_DATE: handle_date,
    Attribute.SUBJECT: handle_bytes,
    Attribute.SUBPRIME: handle_biginteger,
    Attribute.SUBPRIME_BITS: handle_ulong,
    Attribute.TOKEN: handle_bool,
    Attribute.TRUSTED: handle_bool,
    Attribute.UNIQUE_ID: handle_str,
    Attribute.UNWRAP: handle_bool,
    Attribute.URL: handle_str,
    Attribute.VALUE: handle_biginteger,
    Attribute.VALUE_BITS: handle_ulong,
    Attribute.VALUE_LEN: handle_ulong,
    Attribute.VERIFY: handle_bool,
    Attribute.VERIFY_RECOVER: handle_bool,
    Attribute.WRAP: handle_bool,
    Attribute.WRAP_WITH_TRUSTED: handle_bool,
    Attribute.TRUST_SERVER_AUTH: _enum(Trust),
    Attribute.TRUST_CLIENT_AUTH: _enum(Trust),
    Attribute.TRUST_CODE_SIGNING: _enum(Trust),
    Attribute.TRUST_EMAIL_PROTECTION: _enum(Trust),
    Attribute.TRUST_IPSEC_IKE: _enum(Trust),
    Attribute.TRUST_TIME_STAMPING: _enum(Trust),
    Attribute.TRUST_OCSP_SIGNING: _enum(Trust),
    Attribute.GOSTR3410_PARAMS: handle_bytes,
    Attribute.GOSTR3411_PARAMS: handle_bytes,
}
"""
Map of attributes to (serialize, deserialize) functions.
"""

ALL_CAPABILITIES: Final[tuple[Attribute, ...]] = (
    Attribute.ENCRYPT,
    Attribute.DECRYPT,
    Attribute.WRAP,
    Attribute.UNWRAP,
    Attribute.SIGN,
    Attribute.VERIFY,
    Attribute.DERIVE,
    # NOTE: ENCAPSULATE and DECAPSULATE are intentionally excluded here.
    # They are only valid on asymmetric key objects (ML-KEM), not on secret
    # keys.  Passing CKA_ENCAPSULATE=False to C_GenerateKey causes
    # CKR_ATTRIBUTE_VALUE_INVALID on tokens that enforce the restriction.
    # Keypair templates handle them via public_key_template/private_key_template.
)


def _apply_common(
    template: dict[Attribute, Any],
    id_: bytes | None,
    label: str | None,
    store: bool,
) -> None:
    if id_:
        template[Attribute.ID] = id_
    if label:
        template[Attribute.LABEL] = label
    template[Attribute.TOKEN] = bool(store)


def _apply_capabilities(
    template: dict[Attribute, Any],
    possible_capas: tuple[Attribute, ...],
    capabilities: MechanismFlag | int,
) -> None:
    for attr in possible_capas:
        flag = _capa_attr_to_mechanism_flag[attr]
        if attr in _OPT_IN_CAPABILITIES:
            # Opt-in attributes (e.g. ENCAPSULATE/DECAPSULATE) are only
            # added when the caller explicitly requests them.  Setting
            # them to False on modules that don't recognize the attribute
            # causes CKR_ATTRIBUTE_TYPE_INVALID.
            if flag & capabilities:
                template[attr] = True
        else:
            template[attr] = bool(flag & capabilities)


# Capability attributes that are only added to templates when the caller
# explicitly sets the corresponding flag.  Never set to False, preventing
# CKR_ATTRIBUTE_TYPE_INVALID on modules that don't recognize them.
_OPT_IN_CAPABILITIES: Final[frozenset[Attribute]] = frozenset({
    Attribute.ENCAPSULATE,
    Attribute.DECAPSULATE,
})

_capa_attr_to_mechanism_flag: Final[dict[Attribute, MechanismFlag]] = {
    Attribute.ENCRYPT: MechanismFlag.ENCRYPT,
    Attribute.DECRYPT: MechanismFlag.DECRYPT,
    Attribute.WRAP: MechanismFlag.WRAP,
    Attribute.UNWRAP: MechanismFlag.UNWRAP,
    Attribute.SIGN: MechanismFlag.SIGN,
    Attribute.VERIFY: MechanismFlag.VERIFY,
    Attribute.DERIVE: MechanismFlag.DERIVE,
    Attribute.ENCAPSULATE: MechanismFlag.ENCAPSULATE,
    Attribute.DECAPSULATE: MechanismFlag.DECAPSULATE,
}


class AttributeMapper:
    """
    Class mapping PKCS#11 attributes to and from Python values.
    """

    attribute_types: dict[Attribute, Handler]
    default_secret_key_template: dict[Attribute, Any]
    default_public_key_template: dict[Attribute, Any]
    default_private_key_template: dict[Attribute, Any]

    def __init__(self) -> None:
        self.attribute_types = dict(ATTRIBUTE_TYPES)
        self.default_secret_key_template = {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.ID: b"",
            Attribute.LABEL: "",
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
        }
        self.default_public_key_template = {
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.ID: b"",
            Attribute.LABEL: "",
        }
        self.default_private_key_template = {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.ID: b"",
            Attribute.LABEL: "",
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
        }

    def register_handler(self, key: Attribute, pack: PackFunc, unpack: UnpackFunc) -> None:
        self.attribute_types[key] = (pack, unpack)

    def _handler(self, key: Attribute) -> Handler:
        try:
            return self.attribute_types[key]
        except KeyError as e:
            raise NotImplementedError(f"Can't handle attribute type {hex(key)}.") from e

    def pack_attribute(self, key: Attribute, value: Any) -> Any:
        """Pack an attribute value into the low-level form expected by the wrapper."""
        pack, _ = self._handler(key)
        return pack(value)

    def unpack_attributes(self, key: Attribute, value: Any) -> Any:
        """Unpack a low-level attribute value into a Python value."""
        _, unpack = self._handler(key)
        return unpack(value)

    def public_key_template(
        self,
        *,
        capabilities: MechanismFlag | int,
        id_: bytes | None,
        label: str | None,
        store: bool,
    ) -> dict[Attribute, Any]:
        template = self.default_public_key_template.copy()
        _apply_capabilities(
            template,
            (Attribute.ENCRYPT, Attribute.WRAP, Attribute.VERIFY, Attribute.ENCAPSULATE),
            capabilities,
        )
        _apply_common(template, id_, label, store)
        return template

    def private_key_template(
        self,
        *,
        capabilities: MechanismFlag | int,
        id_: bytes | None,
        label: str | None,
        store: bool,
    ) -> dict[Attribute, Any]:
        template = self.default_private_key_template.copy()
        _apply_capabilities(
            template,
            (Attribute.DECRYPT, Attribute.UNWRAP, Attribute.SIGN, Attribute.DERIVE, Attribute.DECAPSULATE),
            capabilities,
        )
        _apply_common(template, id_, label, store)
        return template

    def secret_key_template(
        self,
        *,
        capabilities: MechanismFlag | int,
        id_: bytes | None,
        label: str | None,
        store: bool,
    ) -> dict[Attribute, Any]:
        return self.generic_key_template(
            self.default_secret_key_template,
            capabilities=capabilities,
            id_=id_,
            label=label,
            store=store,
        )

    def generic_key_template(
        self,
        base_template: dict[Attribute, Any],
        *,
        capabilities: MechanismFlag | int,
        id_: bytes | None,
        label: str | None,
        store: bool,
    ) -> dict[Attribute, Any]:
        template = dict(base_template)
        _apply_capabilities(template, ALL_CAPABILITIES, capabilities)
        _apply_common(template, id_, label, store)
        return template
