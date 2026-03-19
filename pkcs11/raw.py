"""Raw PKCS#11 ctypes wrapper — full CK_FUNCTION_LIST access.

Pure Python. No dependencies on python-pkcs11 internals.
Self-contained — can be moved to a separate package.

Usage with python-pkcs11 fork:
    import pkcs11
    from pkcs11.raw import RawPKCS11

    lib = pkcs11.lib("/path/to/module.so")
    raw = RawPKCS11(lib._raw_funclist_ptr)
    rv = raw.C_EncryptInit(session_handle, mechanism_ptr, key_handle)

Standalone usage:
    from pkcs11.raw import RawPKCS11
    raw = RawPKCS11.from_lib("/path/to/module.so")
    raw.C_Initialize()
    ...
"""

from __future__ import annotations

import ctypes
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
    c_ubyte,
    c_ulong,
    c_void_p,
    cast,
)
from typing import Any

# ---------------------------------------------------------------------------
# CK type aliases
# ---------------------------------------------------------------------------

CK_RV = c_ulong
CK_ULONG = c_ulong
CK_ULONG_PTR = POINTER(c_ulong)
CK_BYTE = c_ubyte
CK_BYTE_PTR = POINTER(c_ubyte)
CK_VOID_PTR = c_void_p
CK_BBOOL = c_ubyte
CK_FLAGS = c_ulong
CK_SLOT_ID = c_ulong
CK_SESSION_HANDLE = c_ulong
CK_OBJECT_HANDLE = c_ulong
CK_OBJECT_CLASS = c_ulong
CK_ATTRIBUTE_TYPE = c_ulong
CK_MECHANISM_TYPE = c_ulong
CK_USER_TYPE = c_ulong
CK_NOTIFY = c_void_p  # callback function pointer

# ---------------------------------------------------------------------------
# CKR constants
# ---------------------------------------------------------------------------

CKR_OK = 0x00000000
CKR_CANCEL = 0x00000001
CKR_HOST_MEMORY = 0x00000002
CKR_SLOT_ID_INVALID = 0x00000003
CKR_GENERAL_ERROR = 0x00000005
CKR_FUNCTION_FAILED = 0x00000006
CKR_ARGUMENTS_BAD = 0x00000007
CKR_NO_EVENT = 0x00000008
CKR_ATTRIBUTE_READ_ONLY = 0x00000010
CKR_ATTRIBUTE_SENSITIVE = 0x00000011
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013
CKR_ACTION_PROHIBITED = 0x0000001B
CKR_DATA_INVALID = 0x00000020
CKR_DATA_LEN_RANGE = 0x00000021
CKR_DEVICE_ERROR = 0x00000030
CKR_DEVICE_MEMORY = 0x00000031
CKR_DEVICE_REMOVED = 0x00000032
CKR_ENCRYPTED_DATA_INVALID = 0x00000040
CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041
CKR_KEY_HANDLE_INVALID = 0x00000060
CKR_KEY_SIZE_RANGE = 0x00000062
CKR_KEY_TYPE_INCONSISTENT = 0x00000063
CKR_KEY_NOT_NEEDED = 0x00000064
CKR_KEY_CHANGED = 0x00000065
CKR_KEY_NEEDED = 0x00000066
CKR_KEY_INDIGESTIBLE = 0x00000067
CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068
CKR_KEY_NOT_WRAPPABLE = 0x00000069
CKR_KEY_UNEXTRACTABLE = 0x0000006A
CKR_MECHANISM_INVALID = 0x00000070
CKR_MECHANISM_PARAM_INVALID = 0x00000071
CKR_OBJECT_HANDLE_INVALID = 0x00000082
CKR_OPERATION_ACTIVE = 0x00000090
CKR_OPERATION_NOT_INITIALIZED = 0x00000091
CKR_PIN_INCORRECT = 0x000000A0
CKR_PIN_INVALID = 0x000000A1
CKR_PIN_LEN_RANGE = 0x000000A2
CKR_PIN_EXPIRED = 0x000000A3
CKR_PIN_LOCKED = 0x000000A4
CKR_SESSION_CLOSED = 0x000000B0
CKR_SESSION_COUNT = 0x000000B1
CKR_SESSION_HANDLE_INVALID = 0x000000B3
CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4
CKR_SESSION_READ_ONLY = 0x000000B5
CKR_SESSION_EXISTS = 0x000000B6
CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7
CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8
CKR_SIGNATURE_INVALID = 0x000000C0
CKR_SIGNATURE_LEN_RANGE = 0x000000C1
CKR_TEMPLATE_INCOMPLETE = 0x000000D0
CKR_TEMPLATE_INCONSISTENT = 0x000000D1
CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1
CKR_TOKEN_WRITE_PROTECTED = 0x000000E2
CKR_USER_ALREADY_LOGGED_IN = 0x00000100
CKR_USER_NOT_LOGGED_IN = 0x00000101
CKR_USER_PIN_NOT_INITIALIZED = 0x00000102
CKR_USER_TYPE_INVALID = 0x00000103
CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104
CKR_USER_TOO_MANY_TYPES = 0x00000105
CKR_WRAPPED_KEY_INVALID = 0x00000110
CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112
CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113
CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114
CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115
CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120
CKR_RANDOM_NO_RNG = 0x00000121
CKR_DOMAIN_PARAMS_INVALID = 0x00000130
CKR_CURVE_NOT_SUPPORTED = 0x00000140
CKR_BUFFER_TOO_SMALL = 0x00000150
CKR_SAVED_STATE_INVALID = 0x00000160
CKR_INFORMATION_SENSITIVE = 0x00000170
CKR_STATE_UNSAVEABLE = 0x00000180
CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKR_MUTEX_BAD = 0x000001A0
CKR_MUTEX_NOT_LOCKED = 0x000001A1
CKR_FUNCTION_REJECTED = 0x00000200
CKR_KEY_EXHAUSTED = 0x00000201

# CKF constants
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKF_DONT_BLOCK = 0x00000001

# CKU constants
CKU_SO = 0
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2

# ---------------------------------------------------------------------------
# CK_MECHANISM struct
# ---------------------------------------------------------------------------


class CK_MECHANISM(Structure):
    """PKCS#11 CK_MECHANISM structure."""

    _fields_ = [
        ("mechanism", CK_MECHANISM_TYPE),
        ("pParameter", CK_VOID_PTR),
        ("ulParameterLen", CK_ULONG),
    ]


class CK_ATTRIBUTE(Structure):
    """PKCS#11 CK_ATTRIBUTE structure."""

    _fields_ = [
        ("type", CK_ATTRIBUTE_TYPE),
        ("pValue", CK_VOID_PTR),
        ("ulValueLen", CK_ULONG),
    ]


# ---------------------------------------------------------------------------
# CK_VERSION struct (at start of CK_FUNCTION_LIST)
# ---------------------------------------------------------------------------


class CK_VERSION(Structure):
    _fields_ = [("major", c_ubyte), ("minor", c_ubyte)]


# ---------------------------------------------------------------------------
# Function pointer type definitions
# ---------------------------------------------------------------------------

# All PKCS#11 functions return CK_RV. We define types per-function for
# correct argtypes. Using generic c_void_p for pointer args to keep it simple.

_FP = CFUNCTYPE  # shorthand

# v2.40 function pointer types (index order in CK_FUNCTION_LIST)
_FP_TYPES = {
    # Index: (name, CFUNCTYPE definition)
    0: ("C_Initialize", _FP(CK_RV, CK_VOID_PTR)),
    1: ("C_Finalize", _FP(CK_RV, CK_VOID_PTR)),
    2: ("C_GetInfo", _FP(CK_RV, CK_VOID_PTR)),
    3: ("C_GetFunctionList", _FP(CK_RV, CK_VOID_PTR)),
    4: ("C_GetSlotList", _FP(CK_RV, CK_BBOOL, CK_VOID_PTR, CK_ULONG_PTR)),
    5: ("C_GetSlotInfo", _FP(CK_RV, CK_SLOT_ID, CK_VOID_PTR)),
    6: ("C_GetTokenInfo", _FP(CK_RV, CK_SLOT_ID, CK_VOID_PTR)),
    7: ("C_GetMechanismList", _FP(CK_RV, CK_SLOT_ID, CK_VOID_PTR, CK_ULONG_PTR)),
    8: ("C_GetMechanismInfo", _FP(CK_RV, CK_SLOT_ID, CK_MECHANISM_TYPE, CK_VOID_PTR)),
    9: ("C_InitToken", _FP(CK_RV, CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR)),
    10: ("C_InitPIN", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    11: ("C_SetPIN", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    12: ("C_OpenSession", _FP(CK_RV, CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, POINTER(CK_SESSION_HANDLE))),
    13: ("C_CloseSession", _FP(CK_RV, CK_SESSION_HANDLE)),
    14: ("C_CloseAllSessions", _FP(CK_RV, CK_SLOT_ID)),
    15: ("C_GetSessionInfo", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR)),
    16: ("C_GetOperationState", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG_PTR)),
    17: ("C_SetOperationState", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)),
    18: ("C_Login", _FP(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG)),
    19: ("C_Logout", _FP(CK_RV, CK_SESSION_HANDLE)),
    20: ("C_CreateObject", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, POINTER(CK_OBJECT_HANDLE))),
    21: ("C_CopyObject", _FP(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG, POINTER(CK_OBJECT_HANDLE))),
    22: ("C_DestroyObject", _FP(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)),
    23: ("C_GetObjectSize", _FP(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR)),
    24: ("C_GetAttributeValue", _FP(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG)),
    25: ("C_SetAttributeValue", _FP(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG)),
    26: ("C_FindObjectsInit", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG)),
    27: ("C_FindObjects", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_ULONG_PTR)),
    28: ("C_FindObjectsFinal", _FP(CK_RV, CK_SESSION_HANDLE)),
    29: ("C_EncryptInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    30: ("C_Encrypt", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    31: ("C_EncryptUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    32: ("C_EncryptFinal", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)),
    33: ("C_DecryptInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    34: ("C_Decrypt", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    35: ("C_DecryptUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    36: ("C_DecryptFinal", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)),
    37: ("C_DigestInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM))),
    38: ("C_Digest", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    39: ("C_DigestUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    40: ("C_DigestKey", _FP(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)),
    41: ("C_DigestFinal", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)),
    42: ("C_SignInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    43: ("C_Sign", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    44: ("C_SignUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    45: ("C_SignFinal", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)),
    46: ("C_SignRecoverInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    47: ("C_SignRecover", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    48: ("C_VerifyInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    49: ("C_Verify", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    50: ("C_VerifyUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    51: ("C_VerifyFinal", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    52: ("C_VerifyRecoverInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    53: ("C_VerifyRecover", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    54: ("C_DigestEncryptUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    55: ("C_DecryptDigestUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    56: ("C_SignEncryptUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    57: ("C_DecryptVerifyUpdate", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    58: ("C_GenerateKey", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_VOID_PTR, CK_ULONG, POINTER(CK_OBJECT_HANDLE))),
    59: ("C_GenerateKeyPair", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_VOID_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, POINTER(CK_OBJECT_HANDLE), POINTER(CK_OBJECT_HANDLE))),
    60: ("C_WrapKey", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)),
    61: ("C_UnwrapKey", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, POINTER(CK_OBJECT_HANDLE))),
    62: ("C_DeriveKey", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG, POINTER(CK_OBJECT_HANDLE))),
    63: ("C_SeedRandom", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    64: ("C_GenerateRandom", _FP(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)),
    65: ("C_GetFunctionStatus", _FP(CK_RV, CK_SESSION_HANDLE)),
    66: ("C_CancelFunction", _FP(CK_RV, CK_SESSION_HANDLE)),
    67: ("C_WaitForSlotEvent", _FP(CK_RV, CK_FLAGS, POINTER(CK_SLOT_ID), CK_VOID_PTR)),
}

# v3.0 additional function pointer types (indices 68+ in CK_FUNCTION_LIST_3_0)
_FP_TYPES_V30 = {
    68: ("C_GetInterfaceList", _FP(CK_RV, CK_VOID_PTR, CK_ULONG_PTR)),
    69: ("C_GetInterface", _FP(CK_RV, CK_BYTE_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_FLAGS)),
    70: ("C_LoginUser", _FP(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    71: ("C_SessionCancel", _FP(CK_RV, CK_SESSION_HANDLE, CK_FLAGS)),
    72: ("C_MessageEncryptInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    73: ("C_EncryptMessage", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    74: ("C_EncryptMessageBegin", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    75: ("C_EncryptMessageNext", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_FLAGS)),
    76: ("C_MessageEncryptFinal", _FP(CK_RV, CK_SESSION_HANDLE)),
    77: ("C_MessageDecryptInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    78: ("C_DecryptMessage", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    79: ("C_DecryptMessageBegin", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    80: ("C_DecryptMessageNext", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_FLAGS)),
    81: ("C_MessageDecryptFinal", _FP(CK_RV, CK_SESSION_HANDLE)),
    82: ("C_MessageSignInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    83: ("C_SignMessage", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    84: ("C_SignMessageBegin", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG)),
    85: ("C_SignMessageNext", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)),
    86: ("C_MessageSignFinal", _FP(CK_RV, CK_SESSION_HANDLE)),
    87: ("C_MessageVerifyInit", _FP(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)),
    88: ("C_VerifyMessage", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    89: ("C_VerifyMessageBegin", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG)),
    90: ("C_VerifyMessageNext", _FP(CK_RV, CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    91: ("C_MessageVerifyFinal", _FP(CK_RV, CK_SESSION_HANDLE)),
}

_PTR_SIZE = ctypes.sizeof(c_void_p)
# CK_FUNCTION_LIST starts with CK_VERSION (2 bytes) padded to pointer alignment
_VERSION_SIZE = _PTR_SIZE  # CK_VERSION padded to pointer boundary


class RawPKCS11:
    """Raw ctypes access to all PKCS#11 C_* functions.

    Pure Python, no dependencies on python-pkcs11 internals.
    """

    def __init__(
        self,
        funclist_ptr: int = 0,
        lib_path: str | None = None,
        funclist3_ptr: int = 0,
        funclist32_ptr: int = 0,
    ):
        """Initialize from funclist pointer or library path.

        Args:
            funclist_ptr: CK_FUNCTION_LIST* as int (from lib._raw_funclist_ptr)
            lib_path: Path to .so — loads module independently if funclist_ptr=0
            funclist3_ptr: CK_FUNCTION_LIST_3_0* for v3.0+ (0 = not available)
            funclist32_ptr: CK_FUNCTION_LIST_3_2* for v3.2 KEM (0 = not available)
        """
        self._funcs: dict[str, Any] = {}
        self._lib = None

        if funclist_ptr:
            self._load_from_ptr(funclist_ptr)
        elif lib_path:
            self._load_from_lib(lib_path)
        else:
            raise ValueError("Provide funclist_ptr or lib_path")

        # Load v3.0+ functions if pointer available
        if funclist3_ptr:
            self._load_v30_from_ptr(funclist3_ptr)
        # Load v3.2+ functions if pointer available
        if funclist32_ptr:
            self._load_v32_from_ptr(funclist32_ptr)

    def _load_from_ptr(self, ptr: int) -> None:
        """Extract function pointers from CK_FUNCTION_LIST at ptr."""
        for idx, (name, fp_type) in _FP_TYPES.items():
            offset = _VERSION_SIZE + (idx * _PTR_SIZE)
            addr_ptr = cast(ptr + offset, POINTER(c_void_p))
            addr = addr_ptr.contents.value
            if addr:
                self._funcs[name] = fp_type(addr)

    def _load_v30_from_ptr(self, ptr: int) -> None:
        """Extract v3.0+ function pointers from CK_FUNCTION_LIST_3_0."""
        for idx, (name, fp_type) in _FP_TYPES_V30.items():
            offset = _VERSION_SIZE + (idx * _PTR_SIZE)
            addr_ptr = cast(ptr + offset, POINTER(c_void_p))
            addr = addr_ptr.contents.value
            if addr:
                self._funcs[name] = fp_type(addr)

    def _load_v32_from_ptr(self, ptr: int) -> None:
        """Extract v3.2+ function pointers (KEM etc) — uses same layout as v3.0."""
        # v3.2 extends v3.0 with additional functions at higher indices
        # For now, the v3.0 functions at indices 68-91 are the same
        # Additional v3.2 functions would be at 92+
        pass  # KEM functions already in v2.40 funclist for Kryoptic

    def _load_from_lib(self, lib_path: str) -> None:
        """Load module via CDLL and C_GetFunctionList."""
        self._lib = ctypes.CDLL(lib_path)
        get_fl = self._lib.C_GetFunctionList
        get_fl.restype = CK_RV
        get_fl.argtypes = [POINTER(c_void_p)]
        fl_ptr = c_void_p()
        rv = get_fl(byref(fl_ptr))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetFunctionList failed: 0x{rv:08x}")
        self._load_from_ptr(fl_ptr.value)

    @classmethod
    def from_lib(cls, lib_path: str) -> "RawPKCS11":
        """Create from library path (standalone mode)."""
        return cls(lib_path=lib_path)

    def _call(self, name: str, *args: Any) -> int:
        """Call a C_* function by name. Returns CK_RV as int."""
        func = self._funcs.get(name)
        if func is None:
            raise AttributeError(f"{name} not available in this module")
        return func(*args)

    # --- Convenience methods for all 68 v2.40 functions ---

    def C_Initialize(self, pInitArgs: Any = None) -> int:
        return self._call("C_Initialize", pInitArgs)

    def C_Finalize(self, pReserved: Any = None) -> int:
        return self._call("C_Finalize", pReserved)

    def C_GetInfo(self, pInfo: Any) -> int:
        return self._call("C_GetInfo", pInfo)

    def C_GetSlotList(self, tokenPresent: int, pSlotList: Any, pulCount: Any) -> int:
        return self._call("C_GetSlotList", tokenPresent, pSlotList, pulCount)

    def C_GetSlotInfo(self, slotID: int, pInfo: Any) -> int:
        return self._call("C_GetSlotInfo", slotID, pInfo)

    def C_GetTokenInfo(self, slotID: int, pInfo: Any) -> int:
        return self._call("C_GetTokenInfo", slotID, pInfo)

    def C_OpenSession(self, slotID: int, flags: int, pApp: Any, notify: Any, phSession: Any) -> int:
        return self._call("C_OpenSession", slotID, flags, pApp, notify, phSession)

    def C_CloseSession(self, hSession: int) -> int:
        return self._call("C_CloseSession", hSession)

    def C_CloseAllSessions(self, slotID: int) -> int:
        return self._call("C_CloseAllSessions", slotID)

    def C_Login(self, hSession: int, userType: int, pPin: Any, ulPinLen: int) -> int:
        return self._call("C_Login", hSession, userType, pPin, ulPinLen)

    def C_Logout(self, hSession: int) -> int:
        return self._call("C_Logout", hSession)

    def C_EncryptInit(self, hSession: int, pMechanism: Any, hKey: int) -> int:
        return self._call("C_EncryptInit", hSession, pMechanism, hKey)

    def C_Encrypt(self, hSession: int, pData: Any, ulDataLen: int, pEncrypted: Any, pulEncryptedLen: Any) -> int:
        return self._call("C_Encrypt", hSession, pData, ulDataLen, pEncrypted, pulEncryptedLen)

    def C_EncryptUpdate(self, hSession: int, pPart: Any, ulPartLen: int, pEncPart: Any, pulEncPartLen: Any) -> int:
        return self._call("C_EncryptUpdate", hSession, pPart, ulPartLen, pEncPart, pulEncPartLen)

    def C_EncryptFinal(self, hSession: int, pLastEncPart: Any, pulLastEncPartLen: Any) -> int:
        return self._call("C_EncryptFinal", hSession, pLastEncPart, pulLastEncPartLen)

    def C_DecryptInit(self, hSession: int, pMechanism: Any, hKey: int) -> int:
        return self._call("C_DecryptInit", hSession, pMechanism, hKey)

    def C_Decrypt(self, hSession: int, pEncData: Any, ulEncDataLen: int, pData: Any, pulDataLen: Any) -> int:
        return self._call("C_Decrypt", hSession, pEncData, ulEncDataLen, pData, pulDataLen)

    def C_DecryptUpdate(self, hSession: int, pEncPart: Any, ulEncPartLen: int, pPart: Any, pulPartLen: Any) -> int:
        return self._call("C_DecryptUpdate", hSession, pEncPart, ulEncPartLen, pPart, pulPartLen)

    def C_DecryptFinal(self, hSession: int, pLastPart: Any, pulLastPartLen: Any) -> int:
        return self._call("C_DecryptFinal", hSession, pLastPart, pulLastPartLen)

    def C_DigestInit(self, hSession: int, pMechanism: Any) -> int:
        return self._call("C_DigestInit", hSession, pMechanism)

    def C_Digest(self, hSession: int, pData: Any, ulDataLen: int, pDigest: Any, pulDigestLen: Any) -> int:
        return self._call("C_Digest", hSession, pData, ulDataLen, pDigest, pulDigestLen)

    def C_DigestUpdate(self, hSession: int, pPart: Any, ulPartLen: int) -> int:
        return self._call("C_DigestUpdate", hSession, pPart, ulPartLen)

    def C_DigestKey(self, hSession: int, hKey: int) -> int:
        return self._call("C_DigestKey", hSession, hKey)

    def C_DigestFinal(self, hSession: int, pDigest: Any, pulDigestLen: Any) -> int:
        return self._call("C_DigestFinal", hSession, pDigest, pulDigestLen)

    def C_SignInit(self, hSession: int, pMechanism: Any, hKey: int) -> int:
        return self._call("C_SignInit", hSession, pMechanism, hKey)

    def C_Sign(self, hSession: int, pData: Any, ulDataLen: int, pSig: Any, pulSigLen: Any) -> int:
        return self._call("C_Sign", hSession, pData, ulDataLen, pSig, pulSigLen)

    def C_SignUpdate(self, hSession: int, pPart: Any, ulPartLen: int) -> int:
        return self._call("C_SignUpdate", hSession, pPart, ulPartLen)

    def C_SignFinal(self, hSession: int, pSig: Any, pulSigLen: Any) -> int:
        return self._call("C_SignFinal", hSession, pSig, pulSigLen)

    def C_VerifyInit(self, hSession: int, pMechanism: Any, hKey: int) -> int:
        return self._call("C_VerifyInit", hSession, pMechanism, hKey)

    def C_Verify(self, hSession: int, pData: Any, ulDataLen: int, pSig: Any, ulSigLen: int) -> int:
        return self._call("C_Verify", hSession, pData, ulDataLen, pSig, ulSigLen)

    def C_VerifyUpdate(self, hSession: int, pPart: Any, ulPartLen: int) -> int:
        return self._call("C_VerifyUpdate", hSession, pPart, ulPartLen)

    def C_VerifyFinal(self, hSession: int, pSig: Any, ulSigLen: int) -> int:
        return self._call("C_VerifyFinal", hSession, pSig, ulSigLen)

    def C_GenerateKey(self, hSession: int, pMech: Any, pTemplate: Any, ulCount: int, phKey: Any) -> int:
        return self._call("C_GenerateKey", hSession, pMech, pTemplate, ulCount, phKey)

    def C_GenerateRandom(self, hSession: int, pRandomData: Any, ulRandomLen: int) -> int:
        return self._call("C_GenerateRandom", hSession, pRandomData, ulRandomLen)

    def C_SeedRandom(self, hSession: int, pSeed: Any, ulSeedLen: int) -> int:
        return self._call("C_SeedRandom", hSession, pSeed, ulSeedLen)

    def C_WrapKey(self, hSession: int, pMech: Any, hWrappingKey: int, hKey: int, pWrappedKey: Any, pulWrappedKeyLen: Any) -> int:
        return self._call("C_WrapKey", hSession, pMech, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen)

    def C_UnwrapKey(self, hSession: int, pMech: Any, hUnwrappingKey: int, pWrappedKey: Any, ulWrappedKeyLen: int, pTemplate: Any, ulAttrCount: int, phKey: Any) -> int:
        return self._call("C_UnwrapKey", hSession, pMech, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttrCount, phKey)

    def C_DeriveKey(self, hSession: int, pMech: Any, hBaseKey: int, pTemplate: Any, ulAttrCount: int, phKey: Any) -> int:
        return self._call("C_DeriveKey", hSession, pMech, hBaseKey, pTemplate, ulAttrCount, phKey)

    def C_WaitForSlotEvent(self, flags: int, pSlot: Any, pReserved: Any = None) -> int:
        return self._call("C_WaitForSlotEvent", flags, pSlot, pReserved)

    def C_DestroyObject(self, hSession: int, hObject: int) -> int:
        return self._call("C_DestroyObject", hSession, hObject)

    def C_CreateObject(self, hSession: int, pTemplate: Any, ulCount: int, phObject: Any) -> int:
        return self._call("C_CreateObject", hSession, pTemplate, ulCount, phObject)

    def C_GetAttributeValue(self, hSession: int, hObject: int, pTemplate: Any, ulCount: int) -> int:
        return self._call("C_GetAttributeValue", hSession, hObject, pTemplate, ulCount)

    def C_SetAttributeValue(self, hSession: int, hObject: int, pTemplate: Any, ulCount: int) -> int:
        return self._call("C_SetAttributeValue", hSession, hObject, pTemplate, ulCount)

    def C_FindObjectsInit(self, hSession: int, pTemplate: Any, ulCount: int) -> int:
        return self._call("C_FindObjectsInit", hSession, pTemplate, ulCount)

    def C_FindObjects(self, hSession: int, phObject: Any, ulMaxCount: int, pulCount: Any) -> int:
        return self._call("C_FindObjects", hSession, phObject, ulMaxCount, pulCount)

    def C_FindObjectsFinal(self, hSession: int) -> int:
        return self._call("C_FindObjectsFinal", hSession)

    def C_GetSessionInfo(self, hSession: int, pInfo: Any) -> int:
        return self._call("C_GetSessionInfo", hSession, pInfo)

    def C_GetOperationState(self, hSession: int, pState: Any, pulStateLen: Any) -> int:
        return self._call("C_GetOperationState", hSession, pState, pulStateLen)

    def C_SetOperationState(self, hSession: int, pState: Any, ulStateLen: int, hEncKey: int, hAuthKey: int) -> int:
        return self._call("C_SetOperationState", hSession, pState, ulStateLen, hEncKey, hAuthKey)

    def C_CopyObject(self, hSession: int, hObject: int, pTemplate: Any, ulCount: int, phNewObject: Any) -> int:
        return self._call("C_CopyObject", hSession, hObject, pTemplate, ulCount, phNewObject)

    def C_GetObjectSize(self, hSession: int, hObject: int, pulSize: Any) -> int:
        return self._call("C_GetObjectSize", hSession, hObject, pulSize)

    def C_InitToken(self, slotID: int, pPin: Any, ulPinLen: int, pLabel: Any) -> int:
        return self._call("C_InitToken", slotID, pPin, ulPinLen, pLabel)

    def C_InitPIN(self, hSession: int, pPin: Any, ulPinLen: int) -> int:
        return self._call("C_InitPIN", hSession, pPin, ulPinLen)

    def C_SetPIN(self, hSession: int, pOldPin: Any, ulOldLen: int, pNewPin: Any, ulNewLen: int) -> int:
        return self._call("C_SetPIN", hSession, pOldPin, ulOldLen, pNewPin, ulNewLen)

    def C_GetMechanismList(self, slotID: int, pMechList: Any, pulCount: Any) -> int:
        return self._call("C_GetMechanismList", slotID, pMechList, pulCount)

    def C_GetMechanismInfo(self, slotID: int, mechType: int, pInfo: Any) -> int:
        return self._call("C_GetMechanismInfo", slotID, mechType, pInfo)

    def C_SignRecoverInit(self, hSession: int, pMech: Any, hKey: int) -> int:
        return self._call("C_SignRecoverInit", hSession, pMech, hKey)

    def C_SignRecover(self, hSession: int, pData: Any, ulDataLen: int, pSig: Any, pulSigLen: Any) -> int:
        return self._call("C_SignRecover", hSession, pData, ulDataLen, pSig, pulSigLen)

    def C_VerifyRecoverInit(self, hSession: int, pMech: Any, hKey: int) -> int:
        return self._call("C_VerifyRecoverInit", hSession, pMech, hKey)

    def C_VerifyRecover(self, hSession: int, pSig: Any, ulSigLen: int, pData: Any, pulDataLen: Any) -> int:
        return self._call("C_VerifyRecover", hSession, pSig, ulSigLen, pData, pulDataLen)

    def C_GenerateKeyPair(self, hSession: int, pMech: Any, pPubTemplate: Any, ulPubCount: int, pPrivTemplate: Any, ulPrivCount: int, phPubKey: Any, phPrivKey: Any) -> int:
        return self._call("C_GenerateKeyPair", hSession, pMech, pPubTemplate, ulPubCount, pPrivTemplate, ulPrivCount, phPubKey, phPrivKey)
