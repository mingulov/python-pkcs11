"""
PKCS#11 constants.

See the Python :mod:`enum` documentation for more information on how to
use these classes.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag, unique
from typing import Final

DEFAULT: Final[object] = object()
"""Sentinel value used in templates.

Not all pkcs11 attribute sets are accepted by HSMs.
Use this value to remove the attribute from the template
sent to the HSM or to use the HSM default value.
"""


@unique
class UserType(IntEnum):
    """PKCS#11 user types."""

    NOBODY = 999
    """
    Not officially in the PKCS#11 spec. Used to represent a session that is not
    logged in.
    """
    SO = 0
    """Security officer."""
    USER = 1
    CONTEXT_SPECIFIC = 2
    """Context-specific login for PIN re-authentication (CKU_CONTEXT_SPECIFIC)."""


class ObjectClass(IntEnum):
    """
    PKCS#11 :class:`Object` class.

    This is the type of object we have.
    """

    DATA = 0x00000000
    CERTIFICATE = 0x00000001
    """See :class:`pkcs11.Certificate`."""
    PUBLIC_KEY = 0x00000002
    """See :class:`pkcs11.PublicKey`."""
    PRIVATE_KEY = 0x00000003
    """See :class:`pkcs11.PrivateKey`."""
    SECRET_KEY = 0x00000004
    """See :class:`pkcs11.SecretKey`."""
    HW_FEATURE = 0x00000005
    DOMAIN_PARAMETERS = 0x00000006
    """See :class:`pkcs11.DomainParameters`."""
    MECHANISM = 0x00000007
    OTP_KEY = 0x00000008
    PROFILE = 0x00000009
    VALIDATION = 0x0000000A
    """Validation object (PKCS#11 v3.2)."""
    TRUST = 0x0000000B
    """Trust object (PKCS#11 v3.2)."""

    _VENDOR_DEFINED = 0x80000000

    def __repr__(self) -> str:
        return "<ObjectClass.%s>" % self.name


_ARRAY_ATTRIBUTE: Final[int] = 0x40000000
"""Attribute consists of an array of values."""


class Attribute(IntEnum):
    """
    PKCS#11 object attributes.

    Not all attributes are relevant to all objects.
    Relevant attributes for each object type are given in `PKCS #11
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_.
    """

    CLASS = 0x00000000
    """Object type (:class:`ObjectClass`)."""
    TOKEN = 0x00000001
    """
    If True object will be stored to token.
    Otherwise has session lifetime (:class:`bool`).
    """
    PRIVATE = 0x00000002
    """
    True if user must be authenticated to access this object (:class:`bool`).
    """
    LABEL = 0x00000003
    """Object label (:class:`str`)."""
    UNIQUE_ID = 0x00000004
    """Unique identifier (:class:`str`)."""
    APPLICATION = 0x00000010
    VALUE = 0x00000011
    """
    Object value. Usually represents a secret or private key.
    For certificates this is the complete certificate in the certificate's
    native format (e.g. BER-encoded X.509 or WTLS encoding).

    May be `SENSITIVE` (:class:`bytes`).
    """
    OBJECT_ID = 0x00000012
    CERTIFICATE_TYPE = 0x00000080
    """
    Certificate type (:class:`CertificateType`).
    """
    ISSUER = 0x00000081
    """
    Certificate issuer in certificate's native format
    (e.g. X.509 DER-encoding or WTLS encoding) (:class:`bytes`).
    """
    SERIAL_NUMBER = 0x00000082
    """
    Certificate serial number in certificate's native format
    (e.g. X.509 DER-encoding) (:class:`bytes`).
    """
    AC_ISSUER = 0x00000083
    """
    Attribute Certificate Issuer. Different from `ISSUER` because the
    encoding is different (:class:`bytes`).
    """
    OWNER = 0x00000084
    """
    Attribute Certificate Owner. Different from `SUBJECT` because the
    encoding is different (:class:`bytes`).
    """
    ATTR_TYPES = 0x00000085
    """
    BER-encoding of a sequence of object identifier values corresponding to the
    attribute types contained in the certificate. When present, this field
    offers an opportunity for applications to search for a particular attribute
    certificate without fetching and parsing the certificate itself.
    """
    TRUSTED = 0x00000086
    """
    This key can be used to wrap keys with `WRAP_WITH_TRUSTED` set;
    or this certificate can be trusted.
    (:class:`bool`).
    """
    CERTIFICATE_CATEGORY = 0x00000087
    """
    Certificate category (:class:`CertificateCategory`).
    """
    JAVA_MIDP_SECURITY_DOMAIN = 0x00000088
    URL = 0x00000089
    """URL where the complete certificate can be obtained."""
    HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008A
    """Hash of the certificate subject's public key."""
    HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008B
    """Hash of the certificate issuer's public key."""
    CHECK_VALUE = 0x00000090
    """`VALUE` checksum. Key Check Value (:class:`bytes`)."""

    KEY_TYPE = 0x00000100
    """Key type (:class:`KeyType`)."""
    SUBJECT = 0x00000101
    """
    Certificate subject in certificate's native format
    (e.g. X.509 DER-encoding or WTLS encoding) (:class:`bytes`).
    """
    ID = 0x00000102
    """Key ID (bytes)."""
    SENSITIVE = 0x00000103
    """
    Sensitive attributes cannot be retrieved from the HSM
    (e.g. `VALUE` or `PRIVATE_EXPONENT`) (:class:`bool`).
    """
    ENCRYPT = 0x00000104
    """Key supports encryption (:class:`bool`)."""
    DECRYPT = 0x00000105
    """Key supports decryption (:class:`bool`)."""
    WRAP = 0x00000106
    """Key supports wrapping (:class:`bool`)."""
    UNWRAP = 0x00000107
    """Key supports unwrapping (:class:`bool`)."""
    SIGN = 0x00000108
    """Key supports signing (:class:`bool`)."""
    SIGN_RECOVER = 0x00000109
    VERIFY = 0x0000010A
    """Key supports signature verification (:class:`bool`)."""
    VERIFY_RECOVER = 0x0000010B
    DERIVE = 0x0000010C
    """Key supports key derivation (:class:`bool`)."""
    ENCAPSULATE = 0x00000633
    """Key supports KEM encapsulation (PKCS#11 v3.2, :class:`bool`)."""
    DECAPSULATE = 0x00000634
    """Key supports KEM decapsulation (PKCS#11 v3.2, :class:`bool`)."""
    HSS_LEVELS = 0x00000617
    """Number of LMS levels in an HSS hierarchy (PKCS#11 v3.2, :class:`int`)."""
    HSS_LMS_TYPE = 0x00000618
    """Top-level LMS tree encoding for HSS keys (PKCS#11 v3.2, :class:`int`)."""
    HSS_LMOTS_TYPE = 0x00000619
    """Top-level LM-OTS encoding for HSS keys (PKCS#11 v3.2, :class:`int`)."""
    HSS_LMS_TYPES = 0x0000061A
    """LMS tree encodings for each HSS level (PKCS#11 v3.2, :class:`list`)."""
    HSS_LMOTS_TYPES = 0x0000061B
    """LM-OTS encodings for each HSS level (PKCS#11 v3.2, :class:`list`)."""
    HSS_KEYS_REMAINING = 0x0000061C
    """Remaining signatures available on an HSS private key (PKCS#11 v3.2, :class:`int`)."""
    PARAMETER_SET = 0x0000061D
    """PQC algorithm parameter set (e.g. ML-KEM-512/768/1024, PKCS#11 v3.2, :class:`int`)."""
    PROFILE_ID = 0x00000601
    """Profile identifier on a CKO_PROFILE object (PKCS#11 v3.0, :class:`int`)."""
    OBJECT_VALIDATION_FLAGS = 0x0000061E
    """Validation flags applied to this object (PKCS#11 v3.2, :class:`int`)."""
    VALIDATION_TYPE = 0x0000061F
    """Validation type on a validation object (PKCS#11 v3.2, :class:`ValidationType`)."""
    VALIDATION_VERSION = 0x00000620
    """Validation version on a validation object (PKCS#11 v3.2, :class:`tuple`)."""
    VALIDATION_LEVEL = 0x00000621
    """Validation level on a validation object (PKCS#11 v3.2, :class:`int`)."""
    VALIDATION_MODULE_ID = 0x00000622
    """Validation module identifier (PKCS#11 v3.2, :class:`str`)."""
    VALIDATION_FLAG = 0x00000623
    """Validation flag value exposed by a validation object (PKCS#11 v3.2, :class:`int`)."""
    VALIDATION_AUTHORITY_TYPE = 0x00000624
    """Validation authority type (PKCS#11 v3.2, :class:`ValidationAuthorityType`)."""
    VALIDATION_COUNTRY = 0x00000625
    """Two-letter validation country code (PKCS#11 v3.2, :class:`str`)."""
    VALIDATION_CERTIFICATE_IDENTIFIER = 0x00000626
    """Validation certificate identifier (PKCS#11 v3.2, :class:`str`)."""
    VALIDATION_CERTIFICATE_URI = 0x00000627
    """Validation certificate URI (PKCS#11 v3.2, :class:`str`)."""
    VALIDATION_VENDOR_URI = 0x00000628
    """Validation vendor URI (PKCS#11 v3.2, :class:`str`)."""
    VALIDATION_PROFILE = 0x00000629
    """Validation profile string (PKCS#11 v3.2, :class:`str`)."""
    ENCAPSULATE_TEMPLATE = 0x0000062A
    """Template applied when encapsulating a key (PKCS#11 v3.2)."""
    DECAPSULATE_TEMPLATE = 0x0000062B
    """Template applied when decapsulating a key (PKCS#11 v3.2)."""
    TRUST_SERVER_AUTH = 0x0000062C
    """Trust value for server authentication (PKCS#11 v3.2, :class:`Trust`)."""
    TRUST_CLIENT_AUTH = 0x0000062D
    """Trust value for client authentication (PKCS#11 v3.2, :class:`Trust`)."""
    TRUST_CODE_SIGNING = 0x0000062E
    """Trust value for code signing (PKCS#11 v3.2, :class:`Trust`)."""
    TRUST_EMAIL_PROTECTION = 0x0000062F
    """Trust value for email protection (PKCS#11 v3.2, :class:`Trust`)."""
    TRUST_IPSEC_IKE = 0x00000630
    """Trust value for IPsec/IKE usage (PKCS#11 v3.2, :class:`Trust`)."""
    TRUST_TIME_STAMPING = 0x00000631
    """Trust value for time stamping (PKCS#11 v3.2, :class:`Trust`)."""
    TRUST_OCSP_SIGNING = 0x00000632
    """Trust value for OCSP signing (PKCS#11 v3.2, :class:`Trust`)."""
    HASH_OF_CERTIFICATE = 0x00000635
    """Digest of a certificate referenced by a trust object (PKCS#11 v3.2, :class:`bytes`)."""
    PUBLIC_CRC64_VALUE = 0x00000636
    """CRC64 linking a public key to its matching private key (PKCS#11 v3.2, :class:`bytes`)."""
    SEED = 0x00000637
    """Seed value for seed-bearing PQC private keys (PKCS#11 v3.2, :class:`bytes`)."""
    START_DATE = 0x00000110
    """Start date for the object's validity (:class:`datetime.date`)."""
    END_DATE = 0x00000111
    """End date for the object's validity (:class:`datetime.date`)."""
    MODULUS = 0x00000120
    """RSA private key modulus (n) (`biginteger` as :class:`bytes`)."""
    MODULUS_BITS = 0x00000121
    """
    RSA private key modulus length. Use this for private key generation
    (:class:`int`).
    """
    PUBLIC_EXPONENT = 0x00000122
    """
    RSA public exponent (e) (`biginteger` as :class:`bytes`).

    Default is b'\1\0\1' (65537).
    """
    PRIVATE_EXPONENT = 0x00000123
    """RSA private exponent (d) (`biginteger` as :class:`bytes`)."""
    PRIME_1 = 0x00000124
    """
    RSA private key prime #1 (p). May not be stored.
    (`biginteger` as :class:`bytes`).
    """
    PRIME_2 = 0x00000125
    """
    RSA private key prime #2 (q). May not be stored.
    (`biginteger` as :class:`bytes`).
    """
    EXPONENT_1 = 0x00000126
    """
    RSA private key exponent #1 (d mod p-1). May not be stored.
    (`biginteger` as :class:`bytes`).
    """
    EXPONENT_2 = 0x00000127
    """
    RSA private key exponent #2 (d mod q-1). May not be stored.
    (`biginteger` as :class:`bytes`).
    """
    COEFFICIENT = 0x00000128
    """
    RSA private key CRT coefficient (q^-1 mod p). May not be stored.
    (`biginteger` as :class:`bytes`).
    """
    PRIME = 0x00000130
    """
    Prime number 'q' (used for DH).
    (`biginteger` as :class:`bytes`).
    """
    SUBPRIME = 0x00000131
    """
    Subprime number 'q' (used for DH).
    (`biginteger` as :class:`bytes`).
    """
    BASE = 0x00000132
    """
    Base number 'g' (used for DH).
    (`biginteger` as :class:`bytes`).
    """

    PRIME_BITS = 0x00000133
    SUBPRIME_BITS = 0x00000134

    VALUE_BITS = 0x00000160
    VALUE_LEN = 0x00000161
    """
    `VALUE` length in bytes. Use this for secret key generation
    (:class:`int`).
    """
    EXTRACTABLE = 0x00000162
    """Key can be extracted wrapped."""
    LOCAL = 0x00000163
    """True if generated on the token, False if imported."""
    NEVER_EXTRACTABLE = 0x00000164
    """`EXTRACTABLE` has always been False."""
    ALWAYS_SENSITIVE = 0x00000165
    """`SENSITIVE` has always been True."""
    KEY_GEN_MECHANISM = 0x00000166
    """Key generation mechanism (:class:`pkcs11.mechanisms.Mechanism`)."""

    MODIFIABLE = 0x00000170
    """Object can be modified (:class:`bool`)."""
    COPYABLE = 0x00000171
    """Object can be copied (:class:`bool`)."""
    DESTROYABLE = 0x00000172
    """Object can be destroyed (:class:`bool`)."""

    EC_PARAMS = 0x00000180
    """
    DER-encoded ANSI X9.62 Elliptic-Curve domain parameters (:class:`bytes`).

    These can packed using :mod:`pkcs11.util.ec.encode_named_curve_parameters`:

    ::

        from pkcs11.util.ec import encode_named_curve_parameters

        ecParams = encode_named_curve_parameters('secp256r1')

    Or output by OpenSSL:

    ::

        openssl ecparam -outform der -name <curve name> | base64

    """

    EC_POINT = 0x00000181
    """
    DER-encoded ANSI X9.62 Public key for :attr:`KeyType.EC` (:class:`bytes`).
    """

    SECONDARY_AUTH = 0x00000200
    AUTH_PIN_FLAGS = 0x00000201

    ALWAYS_AUTHENTICATE = 0x00000202
    """
    User has to provide pin with each use (sign or decrypt) (:class:`bool`).
    """

    WRAP_WITH_TRUSTED = 0x00000210
    """Key can only be wrapped with a `TRUSTED` key."""
    WRAP_TEMPLATE = _ARRAY_ATTRIBUTE | 0x00000211
    UNWRAP_TEMPLATE = _ARRAY_ATTRIBUTE | 0x00000212
    DERIVE_TEMPLATE = _ARRAY_ATTRIBUTE | 0x00000213

    OTP_FORMAT = 0x00000220
    OTP_LENGTH = 0x00000221
    OTP_TIME_INTERVAL = 0x00000222
    OTP_USER_FRIENDLY_MODE = 0x00000223
    OTP_CHALLENGE_REQUIREMENT = 0x00000224
    OTP_TIME_REQUIREMENT = 0x00000225
    OTP_COUNTER_REQUIREMENT = 0x00000226
    OTP_PIN_REQUIREMENT = 0x00000227
    OTP_COUNTER = 0x0000022E
    OTP_TIME = 0x0000022F
    OTP_USER_IDENTIFIER = 0x0000022A
    OTP_SERVICE_IDENTIFIER = 0x0000022B
    OTP_SERVICE_LOGO = 0x0000022C
    OTP_SERVICE_LOGO_TYPE = 0x0000022D

    GOSTR3410_PARAMS = 0x00000250
    GOSTR3411_PARAMS = 0x00000251
    GOST28147_PARAMS = 0x00000252

    HW_FEATURE_TYPE = 0x00000300
    RESET_ON_INIT = 0x00000301
    HAS_RESET = 0x00000302

    PIXEL_X = 0x00000400
    PIXEL_Y = 0x00000401
    RESOLUTION = 0x00000402
    CHAR_ROWS = 0x00000403
    CHAR_COLUMNS = 0x00000404
    COLOR = 0x00000405
    BITS_PER_PIXEL = 0x00000406
    CHAR_SETS = 0x00000480
    ENCODING_METHODS = 0x00000481
    MIME_TYPES = 0x00000482
    MECHANISM_TYPE = 0x00000500
    REQUIRED_CMS_ATTRIBUTES = 0x00000501
    DEFAULT_CMS_ATTRIBUTES = 0x00000502
    SUPPORTED_CMS_ATTRIBUTES = 0x00000503
    ALLOWED_MECHANISMS = _ARRAY_ATTRIBUTE | 0x00000600

    _VENDOR_DEFINED = 0x80000000

    def __repr__(self) -> str:
        return "<Attribute.%s>" % self.name


class CertificateType(IntEnum):
    """
    Certificate type of a :class:`pkcs11.Certificate`.
    """

    X_509 = 0x00000000
    X_509_ATTR_CERT = 0x00000001
    WTLS = 0x00000002
    _VENDOR_DEFINED = 0x80000000


@unique
class MechanismFlag(IntFlag):
    """
    Describes the capabilities of a :class:`pkcs11.mechanisms.Mechanism`
    or :class:`pkcs11.Object`.

    Some objects and mechanisms are symmetric (i.e. can be used for encryption
    and decryption), some are asymmetric (e.g. public key cryptography).
    """

    HW = 0x00000001
    """Mechanism is performed in hardware."""

    MESSAGE_ENCRYPT = 0x00000002
    """Can be used with message-based encryption APIs (PKCS#11 v3.0+)."""
    MESSAGE_DECRYPT = 0x00000004
    """Can be used with message-based decryption APIs (PKCS#11 v3.0+)."""
    MESSAGE_SIGN = 0x00000008
    """Can be used with message-based signing APIs (PKCS#11 v3.0+)."""
    MESSAGE_VERIFY = 0x00000010
    """Can be used with message-based verification APIs (PKCS#11 v3.0+)."""
    MULTI_MESSAGE = 0x00000020
    """Mechanism supports multi-message processing (PKCS#11 v3.0+)."""
    FIND_OBJECTS = 0x00000040
    """Can be used to cancel an active object search via C_SessionCancel."""

    ENCRYPT = 0x00000100
    """Can be used for encryption."""
    DECRYPT = 0x00000200
    """Can be used for decryption."""
    DIGEST = 0x00000400
    """Can make a message digest (hash)."""
    SIGN = 0x00000800
    """Can calculate digital signature."""
    SIGN_RECOVER = 0x00001000
    VERIFY = 0x00002000
    """Can verify digital signature."""
    VERIFY_RECOVER = 0x00004000
    GENERATE = 0x00008000
    """Can generate key/object."""
    GENERATE_KEY_PAIR = 0x00010000
    """Can generate key pair."""
    WRAP = 0x00020000
    """Can wrap a key for export."""
    UNWRAP = 0x00040000
    """Can unwrap a key for import."""
    DERIVE = 0x00080000
    """Can derive a key from another key."""
    ENCAPSULATE = 0x10000000
    """Can encapsulate a key (KEM, PKCS#11 v3.2)."""
    DECAPSULATE = 0x20000000
    """Can decapsulate a key (KEM, PKCS#11 v3.2)."""

    EC_F_P = 0x00100000
    EC_F_2M = 0x00200000
    EC_ECPARAMETERS = 0x00400000
    EC_NAMEDCURVE = 0x00800000
    EC_UNCOMPRESS = 0x01000000
    EC_COMPRESS = 0x02000000

    EXTENSION = 0x80000000


@unique
class MessageFlag(IntFlag):
    """Flags for PKCS#11 message-based update calls."""

    END_OF_MESSAGE = 0x00000001
    """Marks the final part of a multi-part message operation."""


@unique
class GeneratorFunction(IntEnum):
    """Generator selection for message/wrap parameter structures."""

    NO_GENERATE = 0x00000000
    GENERATE = 0x00000001
    GENERATE_COUNTER = 0x00000002
    GENERATE_RANDOM = 0x00000003
    GENERATE_COUNTER_XOR = 0x00000004


@unique
class SlotFlag(IntFlag):
    """:class:`pkcs11.Slot` flags."""

    TOKEN_PRESENT = 0x00000001
    """
    A token is present in the slot
    (N.B. some hardware known not to set this for soft-tokens.)
    """
    REMOVABLE_DEVICE = 0x00000002
    """Removable devices."""
    HW_SLOT = 0x00000004
    """Hardware slot."""


@unique
class TokenFlag(IntFlag):
    """:class:`pkcs11.Token` flags."""

    RNG = 0x00000001
    """Has random number generator."""
    WRITE_PROTECTED = 0x00000002
    """Token is write protected."""
    LOGIN_REQUIRED = 0x00000004
    """User must login."""
    USER_PIN_INITIALIZED = 0x00000008
    """Normal user's pin is set."""
    ASYNC_SESSION_SUPPORTED = 0x04000000
    """Token supports asynchronous sessions (PKCS#11 v3.2)."""

    RESTORE_KEY_NOT_NEEDED = 0x00000020
    """
    If it is set, that means that *every* time the state of cryptographic
    operations of a session is successfully saved, all keys needed to continue
    those operations are stored in the state.
    """

    CLOCK_ON_TOKEN = 0x00000040
    """
    If it is set, that means that the token has some sort of clock.  The time
    on that clock is returned in the token info structure.
    """

    PROTECTED_AUTHENTICATION_PATH = 0x00000100
    """
    If it is set, that means that there is some way for the user to login
    without sending a PIN through the Cryptoki library itself.
    """

    DUAL_CRYPTO_OPERATIONS = 0x00000200
    """
    If it is true, that means that a single session with the token can perform
    dual simultaneous cryptographic operations (digest and encrypt; decrypt and
    digest; sign and encrypt; and decrypt and sign).
    """

    TOKEN_INITIALIZED = 0x00000400
    """
    If it is true, the token has been initialized using C_InitializeToken or an
    equivalent mechanism outside the scope of PKCS #11.  Calling
    C_InitializeToken when this flag is set will cause the token to be
    reinitialized.
    """

    USER_PIN_COUNT_LOW = 0x00010000
    """
    If it is true, an incorrect user login PIN has been entered at least once
    since the last successful authentication.
    """

    USER_PIN_FINAL_TRY = 0x00020000
    """
    If it is true, supplying an incorrect user PIN will it to become locked.
    """

    USER_PIN_LOCKED = 0x00040000
    """
    If it is true, the user PIN has been locked. User login to the token is not
    possible.
    """

    USER_PIN_TO_BE_CHANGED = 0x00080000
    """
    If it is true, the user PIN value is the default value set by token
    initialization or manufacturing, or the PIN has been expired by the card.
    """

    SO_PIN_COUNT_LOW = 0x00100000
    """
    If it is true, an incorrect SO (security officer) login PIN has been
    entered at least once since the last successful authentication.
    """

    SO_PIN_FINAL_TRY = 0x00200000
    """
    If it is true, supplying an incorrect SO (security officer) PIN will it to
    become locked.
    """

    SO_PIN_LOCKED = 0x00400000
    """
    If it is true, the SO (security officer) PIN has been locked. SO login to
    the token is not possible.
    """

    SO_PIN_TO_BE_CHANGED = 0x00800000
    """
    If it is true, the SO PIN value is the default value set by token
    initialization or manufacturing, or the PIN has been expired by the card.
    """

    ERROR_STATE = 0x01000000


@unique
class CancelStrategy(IntEnum):
    """
    Strategy to cancel cryptographic operations
    """

    DEFAULT = 0
    """
    Default strategy: attempt to cancel by finalising the operation using dummy data,
    regardless of whether the operation is successful or not.
    This approach should work universally, but is semantically difficult to identify
    as a cancellation.
    """

    CANCEL_WITH_INIT = 1
    """
    Attempt to cancel by calling the ``C_XYZInit`` function of the running operation
    with a ``NULL`` mechanism.

    This usage is defined in PKCS#11 3.0 but not universally implemented.
    """

    CANCEL_WITH_SESSION_CANCEL = 2
    """
    Attempt to cancel by calling ``C_SessionCancel`` with the active operation flags.

    This is the explicit PKCS#11 3.0+ cancellation path and is the preferred
    strategy when the module implements it correctly.
    """


@unique
class MLKemParameterSet(IntEnum):
    """
    ML-KEM (CRYSTALS-Kyber / FIPS 203) parameter sets (PKCS#11 v3.2).

    Specify via ``CKA_PARAMETER_SET`` (Attribute.PARAMETER_SET) in the key
    generation template to select the desired security level.
    """

    ML_KEM_512 = 0x00000001
    """ML-KEM-512 — NIST security category 1 (128-bit classical)."""
    ML_KEM_768 = 0x00000002
    """ML-KEM-768 — NIST security category 3 (192-bit classical, default)."""
    ML_KEM_1024 = 0x00000003
    """ML-KEM-1024 — NIST security category 5 (256-bit classical)."""


@unique
class MLDsaParameterSet(IntEnum):
    """
    ML-DSA (CRYSTALS-Dilithium / FIPS 204) parameter sets (PKCS#11 v3.2).

    Specify via ``Attribute.PARAMETER_SET`` in the key generation template.
    """

    ML_DSA_44 = 0x00000001
    """ML-DSA-44 — NIST security category 2."""
    ML_DSA_65 = 0x00000002
    """ML-DSA-65 — NIST security category 3 (recommended default)."""
    ML_DSA_87 = 0x00000003
    """ML-DSA-87 — NIST security category 5."""


@unique
class SlhDsaParameterSet(IntEnum):
    """
    SLH-DSA (SPHINCS+ / FIPS 205) parameter sets (PKCS#11 v3.2).

    Specify via ``Attribute.PARAMETER_SET`` in the key generation template.
    Parameter names follow the FIPS 205 naming convention (hash-security-type).
    """

    SHA2_128S = 0x00000001
    """SLH-DSA-SHA2-128s — small/slow, security category 1."""
    SHAKE_128S = 0x00000002
    """SLH-DSA-SHAKE-128s — security category 1."""
    SHA2_128F = 0x00000003
    """SLH-DSA-SHA2-128f — fast, security category 1."""
    SHAKE_128F = 0x00000004
    """SLH-DSA-SHAKE-128f — security category 1."""
    SHA2_192S = 0x00000005
    """SLH-DSA-SHA2-192s — security category 3."""
    SHAKE_192S = 0x00000006
    SHA2_192F = 0x00000007
    SHAKE_192F = 0x00000008
    SHA2_256S = 0x00000009
    """SLH-DSA-SHA2-256s — security category 5."""
    SHAKE_256S = 0x0000000A
    SHA2_256F = 0x0000000B
    SHAKE_256F = 0x0000000C
    """SLH-DSA-SHAKE-256f — fast, security category 5."""


@unique
class ProfileID(IntEnum):
    """
    PKCS#11 v3.0 profile identifiers (CKP_*).

    Used as the value of ``CKA_PROFILE_ID`` (``Attribute.PROFILE_ID``) on
    ``CKO_PROFILE`` (``ObjectClass.PROFILE``) objects.  Enumerate these objects
    via :meth:`pkcs11.Session.get_objects` with ``{Attribute.CLASS: ObjectClass.PROFILE}``.
    """

    INVALID_ID = 0x00000000
    """Invalid or unspecified profile identifier."""
    BASELINE_PROVIDER = 0x00000001
    """Baseline Provider profile — minimum conformance."""
    EXTENDED_PROVIDER = 0x00000002
    """Extended Provider profile — full PKCS#11 conformance."""
    AUTHENTICATION_TOKEN = 0x00000003
    """Authentication Token profile."""
    PUBLIC_CERTIFICATES_TOKEN = 0x00000004
    """Public Certificates Token profile."""
    COMPLETE_PROVIDER = 0x00000005
    """Complete Provider profile."""
    HKDF_TLS_TOKEN = 0x00000006
    """HKDF-TLS Token profile."""
    VENDOR_DEFINED = 0x80000000
    """Vendor-defined profile base."""


@unique
class SessionValidationFlagsType(IntEnum):
    """
    Session validation flag selectors (PKCS#11 v3.2).

    These values select which validation-state flags are returned by
    ``C_GetSessionValidationFlags``.
    """

    LAST_VALIDATION_OK = 0x00000001
    """Flags describing the most recent successful validation state."""


@unique
class ValidationType(IntEnum):
    """
    Validation types (PKCS#11 v3.2).

    The published 3.2 header uses inconsistent macro names for these values.
    This enum follows the attribute semantics from the specification.
    """

    UNSPECIFIED = 0x00000000
    SOFTWARE = 0x00000001
    HARDWARE = 0x00000002
    FIRMWARE = 0x00000003
    HYBRID = 0x00000004


@unique
class ValidationAuthorityType(IntEnum):
    """
    Validation authority types (PKCS#11 v3.2).

    The published 3.2 header uses inconsistent macro names for these values.
    This enum follows the attribute semantics from the specification.
    """

    UNSPECIFIED = 0x00000000
    NIST_CMVP = 0x00000001
    COMMON_CRITERIA = 0x00000002


@unique
class Trust(IntEnum):
    """Trust values for ``CKA_TRUST_*`` attributes (PKCS#11 v3.2)."""

    UNKNOWN = 0x00000000
    TRUSTED = 0x00000001
    ANCHOR = 0x00000002
    NOT_TRUSTED = 0x00000003
    MUST_VERIFY_TRUST = 0x00000004
