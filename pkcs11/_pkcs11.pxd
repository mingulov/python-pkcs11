"""
Definitions imported from PKCS11 C headers.
"""

from cython.view cimport array

from pkcs11.exceptions import *

cdef extern from '../extern/cryptoki.h':

    ctypedef unsigned char CK_BYTE
    ctypedef CK_BYTE CK_BBOOL
    ctypedef CK_BYTE CK_UTF8CHAR
    ctypedef unsigned char CK_CHAR
    ctypedef unsigned long int CK_ULONG
    ctypedef CK_ULONG CK_ATTRIBUTE_TYPE
    ctypedef CK_ULONG CK_EC_KDF_TYPE
    ctypedef CK_ULONG CK_FLAGS
    ctypedef CK_ULONG CK_GENERATOR_FUNCTION
    ctypedef CK_ULONG CK_MECHANISM_TYPE
    ctypedef CK_ULONG CK_OBJECT_HANDLE
    ctypedef CK_ULONG CK_RSA_PKCS_MGF_TYPE
    ctypedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE
    ctypedef CK_ULONG CK_SESSION_HANDLE
    ctypedef CK_ULONG CK_SESSION_VALIDATION_FLAGS_TYPE
    ctypedef CK_ULONG CK_SLOT_ID
    ctypedef CK_ULONG CK_STATE

    ctypedef enum CK_RV:
        CKR_OK,
        CKR_CANCEL,
        CKR_HOST_MEMORY,
        CKR_SLOT_ID_INVALID,

        CKR_GENERAL_ERROR,
        CKR_FUNCTION_FAILED,

        CKR_ARGUMENTS_BAD,
        CKR_NO_EVENT,
        CKR_NEED_TO_CREATE_THREADS,
        CKR_CANT_LOCK,

        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_DATA_INVALID,
        CKR_DATA_LEN_RANGE,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_MEMORY,
        CKR_DEVICE_REMOVED,
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_ENCRYPTED_DATA_LEN_RANGE,
        CKR_FUNCTION_CANCELED,
        CKR_FUNCTION_NOT_PARALLEL,

        CKR_FUNCTION_NOT_SUPPORTED,

        CKR_KEY_HANDLE_INVALID,

        CKR_KEY_SIZE_RANGE,
        CKR_KEY_TYPE_INCONSISTENT,

        CKR_KEY_NOT_NEEDED,
        CKR_KEY_CHANGED,
        CKR_KEY_NEEDED,
        CKR_KEY_INDIGESTIBLE,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_UNEXTRACTABLE,

        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,

        CKR_OBJECT_HANDLE_INVALID,
        CKR_OPERATION_ACTIVE,
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_PIN_INCORRECT,
        CKR_PIN_INVALID,
        CKR_PIN_LEN_RANGE,

        CKR_PIN_EXPIRED,
        CKR_PIN_LOCKED,

        CKR_SESSION_CLOSED,
        CKR_SESSION_COUNT,
        CKR_SESSION_HANDLE_INVALID,
        CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        CKR_SESSION_READ_ONLY,
        CKR_SESSION_EXISTS,

        CKR_SESSION_READ_ONLY_EXISTS,
        CKR_SESSION_READ_WRITE_SO_EXISTS,

        CKR_SIGNATURE_INVALID,
        CKR_SIGNATURE_LEN_RANGE,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_TOKEN_NOT_PRESENT,
        CKR_TOKEN_NOT_RECOGNIZED,
        CKR_TOKEN_WRITE_PROTECTED,
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        CKR_UNWRAPPING_KEY_SIZE_RANGE,
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_USER_ALREADY_LOGGED_IN,
        CKR_USER_NOT_LOGGED_IN,
        CKR_USER_PIN_NOT_INITIALIZED,
        CKR_USER_TYPE_INVALID,

        CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        CKR_USER_TOO_MANY_TYPES,

        CKR_WRAPPED_KEY_INVALID,
        CKR_WRAPPED_KEY_LEN_RANGE,
        CKR_WRAPPING_KEY_HANDLE_INVALID,
        CKR_WRAPPING_KEY_SIZE_RANGE,
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_RANDOM_SEED_NOT_SUPPORTED,

        CKR_RANDOM_NO_RNG,

        CKR_DOMAIN_PARAMS_INVALID,

        CKR_BUFFER_TOO_SMALL,
        CKR_SAVED_STATE_INVALID,
        CKR_INFORMATION_SENSITIVE,
        CKR_STATE_UNSAVEABLE,

        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_CRYPTOKI_ALREADY_INITIALIZED,
        CKR_MUTEX_BAD,
        CKR_MUTEX_NOT_LOCKED,

        CKR_NEW_PIN_MODE,
        CKR_NEXT_OTP,
        CKR_EXCEEDED_MAX_ITERATIONS,
        CKR_FIPS_SELF_TEST_FAILED,
        CKR_LIBRARY_LOAD_FAILED,
        CKR_PIN_TOO_WEAK,
        CKR_PUBLIC_KEY_INVALID,
        CKR_PENDING,
        CKR_SESSION_ASYNC_NOT_SUPPORTED,

        CKR_FUNCTION_REJECTED,

        CKR_OPERATION_CANCEL_FAILED,

        CKR_ACTION_PROHIBITED,
        CKR_CURVE_NOT_SUPPORTED,
        CKR_OPERATION_NOT_VALIDATED,
        CKR_TOKEN_NOT_INITIALIZED,
        CKR_PARAMETER_SET_NOT_SUPPORTED,

        CKR_VENDOR_DEFINED,


    ctypedef enum CK_USER_TYPE:
        CKU_SO,
        CKU_USER,
        CKU_CONTEXT_SPECIFIC,
        CKU_USER_NOBODY,

    cdef enum:
        CK_TRUE,
        CK_FALSE,

    cdef enum:
        CK_UNAVAILABLE_INFORMATION,
        CK_EFFECTIVELY_INFINITE,

    cdef enum:  # CK_FLAGS
        CKF_END_OF_MESSAGE,
        CKF_DONT_BLOCK,
        CKF_RW_SESSION,
        CKF_SERIAL_SESSION,
        CKF_ASYNC_SESSION,
        CKF_ASYNC_SESSION_SUPPORTED,

    cdef enum:  # CKG
        CKG_NO_GENERATE,
        CKG_GENERATE,
        CKG_GENERATE_COUNTER,
        CKG_GENERATE_RANDOM,
        CKG_GENERATE_COUNTER_XOR,

    cdef enum:  # CKZ
        CKZ_DATA_SPECIFIED,

    cdef enum: # CK_STATE
        CKS_RO_PUBLIC_SESSION,
        CKS_RO_USER_FUNCTIONS,
        CKS_RW_PUBLIC_SESSION,
        CKS_RW_USER_FUNCTIONS,
        CKS_RW_SO_FUNCTIONS

    ctypedef struct CK_VERSION:
        CK_BYTE major
        CK_BYTE minor

    ctypedef struct CK_INFO:
        CK_VERSION cryptokiVersion;
        CK_UTF8CHAR manufacturerID[32]
        CK_FLAGS flags

        CK_UTF8CHAR libraryDescription[32]
        CK_VERSION libraryVersion;

    ctypedef struct CK_SLOT_INFO:
        CK_UTF8CHAR slotDescription[64]
        CK_UTF8CHAR manufacturerID[32]
        CK_FLAGS flags

        CK_VERSION hardwareVersion
        CK_VERSION firmwareVersion

    ctypedef struct CK_MECHANISM_INFO:
        CK_ULONG ulMinKeySize
        CK_ULONG ulMaxKeySize
        CK_FLAGS flags

    ctypedef struct CK_TOKEN_INFO:
        CK_UTF8CHAR label[32]
        CK_UTF8CHAR manufacturerID[32]
        CK_UTF8CHAR model[16]
        CK_CHAR serialNumber[16]
        CK_FLAGS flags

        CK_ULONG ulMaxSessionCount
        CK_ULONG ulSessionCount
        CK_ULONG ulMaxRwSessionCount
        CK_ULONG ulRwSessionCount
        CK_ULONG ulMaxPinLen
        CK_ULONG ulMinPinLen
        CK_ULONG ulTotalPublicMemory
        CK_ULONG ulFreePublicMemory
        CK_ULONG ulTotalPrivateMemory
        CK_ULONG ulFreePrivateMemory
        CK_VERSION hardwareVersion
        CK_VERSION firmwareVersion
        CK_CHAR utcTime[16]

    ctypedef struct CK_SESSION_INFO:
        CK_SLOT_ID slotID
        CK_STATE state
        CK_FLAGS flags
        CK_ULONG ulDeviceError

    ctypedef struct CK_MECHANISM:
        CK_MECHANISM_TYPE mechanism
        void *pParameter
        CK_ULONG ulParameterLen

    ctypedef struct CK_ATTRIBUTE:
        CK_ATTRIBUTE_TYPE type
        void *pValue
        CK_ULONG ulValueLen

    ctypedef struct CK_RSA_PKCS_OAEP_PARAMS:
        CK_MECHANISM_TYPE hashAlg
        CK_RSA_PKCS_MGF_TYPE mgf
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source
        void *pSourceData
        CK_ULONG ulSourceDataLen

    ctypedef struct CK_RSA_PKCS_PSS_PARAMS:
        CK_MECHANISM_TYPE hashAlg
        CK_RSA_PKCS_MGF_TYPE mgf
        CK_ULONG sLen

    ctypedef struct CK_ECDH1_DERIVE_PARAMS:
        CK_EC_KDF_TYPE kdf
        CK_ULONG ulSharedDataLen
        CK_BYTE *pSharedData
        CK_ULONG ulPublicDataLen
        CK_BYTE *pPublicData

    ctypedef struct CK_AES_CTR_PARAMS:
        CK_ULONG ulCounterBits
        CK_BYTE[16] cb

    ctypedef struct CK_GCM_PARAMS:
        CK_BYTE *pIv
        CK_ULONG ulIvLen
        CK_ULONG ulIvBits
        CK_BYTE *pAAD
        CK_ULONG ulAADLen
        CK_ULONG ulTagBits

    ctypedef struct CK_GCM_MESSAGE_PARAMS:
        CK_BYTE *pIv
        CK_ULONG ulIvLen
        CK_ULONG ulIvFixedBits
        CK_GENERATOR_FUNCTION ivGenerator
        CK_BYTE *pTag
        CK_ULONG ulTagBits

    ctypedef struct CK_GCM_WRAP_PARAMS:
        CK_BYTE *pIv
        CK_ULONG ulIvLen
        CK_ULONG ulIvFixedBits
        CK_GENERATOR_FUNCTION ivGenerator
        CK_BYTE *pAAD
        CK_ULONG ulAADLen
        CK_ULONG ulTagBits

    ctypedef struct CK_KEY_DERIVATION_STRING_DATA:
        CK_BYTE *pData
        CK_ULONG ulLen

    ctypedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS:
        CK_BYTE iv[16]
        CK_BYTE *pData
        CK_ULONG length

    ctypedef CK_ULONG CK_PRF_DATA_TYPE
    ctypedef CK_MECHANISM_TYPE CK_SP800_108_PRF_TYPE

    cdef enum:
        CK_SP800_108_ITERATION_VARIABLE = 0x00000001
        CK_SP800_108_OPTIONAL_COUNTER = 0x00000002
        CK_SP800_108_DKM_LENGTH = 0x00000003
        CK_SP800_108_BYTE_ARRAY = 0x00000004
        CK_SP800_108_COUNTER = 0x00000002
        CK_SP800_108_KEY_HANDLE = 0x00000005

    ctypedef struct CK_PRF_DATA_PARAM:
        CK_PRF_DATA_TYPE type
        void *pValue
        CK_ULONG ulValueLen

    ctypedef struct CK_SP800_108_COUNTER_FORMAT:
        CK_BBOOL bLittleEndian
        CK_ULONG ulWidthInBits

    ctypedef CK_ULONG CK_SP800_108_DKM_LENGTH_METHOD

    cdef enum:
        CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS = 0x00000001
        CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS = 0x00000002

    ctypedef struct CK_SP800_108_DKM_LENGTH_FORMAT:
        CK_SP800_108_DKM_LENGTH_METHOD dkmLengthMethod
        CK_BBOOL bLittleEndian
        CK_ULONG ulWidthInBits

    ctypedef struct CK_DERIVED_KEY:
        CK_ATTRIBUTE *pTemplate
        CK_ULONG ulAttributeCount
        CK_OBJECT_HANDLE *phKey

    ctypedef struct CK_SP800_108_KDF_PARAMS:
        CK_SP800_108_PRF_TYPE prfType
        CK_ULONG ulNumberOfDataParams
        CK_PRF_DATA_PARAM *pDataParams
        CK_ULONG ulAdditionalDerivedKeys
        CK_DERIVED_KEY *pAdditionalDerivedKeys

    ctypedef struct CK_SP800_108_FEEDBACK_KDF_PARAMS:
        CK_SP800_108_PRF_TYPE prfType
        CK_ULONG ulNumberOfDataParams
        CK_PRF_DATA_PARAM *pDataParams
        CK_ULONG ulIVLen
        CK_BYTE *pIV
        CK_ULONG ulAdditionalDerivedKeys
        CK_DERIVED_KEY *pAdditionalDerivedKeys

    ctypedef struct CK_EDDSA_PARAMS:
       CK_BBOOL phFlag
       CK_ULONG ulContextDataLen
       CK_BYTE *pContextData

    ctypedef struct CK_CCM_PARAMS:
        CK_ULONG ulDataLen
        CK_BYTE *pNonce
        CK_ULONG ulNonceLen
        CK_BYTE *pAAD
        CK_ULONG ulAADLen
        CK_ULONG ulMACLen

    ctypedef struct CK_CCM_MESSAGE_PARAMS:
        CK_ULONG ulDataLen
        CK_BYTE *pNonce
        CK_ULONG ulNonceLen
        CK_ULONG ulNonceFixedBits
        CK_GENERATOR_FUNCTION nonceGenerator
        CK_BYTE *pMAC
        CK_ULONG ulMACLen

    ctypedef struct CK_CCM_WRAP_PARAMS:
        CK_ULONG ulDataLen
        CK_BYTE *pNonce
        CK_ULONG ulNonceLen
        CK_ULONG ulNonceFixedBits
        CK_GENERATOR_FUNCTION nonceGenerator
        CK_BYTE *pAAD
        CK_ULONG ulAADLen
        CK_ULONG ulMACLen

    ctypedef struct CK_SALSA20_CHACHA20_POLY1305_PARAMS:
        CK_BYTE *pNonce
        CK_ULONG ulNonceLen
        CK_BYTE *pAAD
        CK_ULONG ulAADLen

    # CK_HKDF salt type constants (PKCS#11 v3.0, pkcs11t.h)
    cdef enum:
        CKF_HKDF_SALT_NULL = 0x00000001
        CKF_HKDF_SALT_DATA = 0x00000002
        CKF_HKDF_SALT_KEY  = 0x00000004

    # PKCS5 PBKDF2 salt source type (pkcs11t.h)
    cdef enum:
        CKZ_SALT_SPECIFIED = 0x00000001

    # PKCS5 PBKDF2 pseudo-random function types (pkcs11t.h)
    cdef enum:
        CKP_PKCS5_PBKD2_HMAC_SHA1       = 0x00000001
        CKP_PKCS5_PBKD2_HMAC_GOSTR3411  = 0x00000002
        CKP_PKCS5_PBKD2_HMAC_SHA224     = 0x00000003
        CKP_PKCS5_PBKD2_HMAC_SHA256     = 0x00000004
        CKP_PKCS5_PBKD2_HMAC_SHA384     = 0x00000005
        CKP_PKCS5_PBKD2_HMAC_SHA512     = 0x00000006
        CKP_PKCS5_PBKD2_HMAC_SHA512_224 = 0x00000007
        CKP_PKCS5_PBKD2_HMAC_SHA512_256 = 0x00000008

    # CK_PKCS5_PBKD2_PARAMS2 — corrected form (v2.40 errata / v3.0+).
    # Uses CK_ULONG for ulPasswordLen (not CK_ULONG_PTR as in the
    # original CK_PKCS5_PBKD2_PARAMS which had a spec bug).
    ctypedef struct CK_PKCS5_PBKD2_PARAMS2:
        CK_ULONG saltSource
        CK_BYTE *pSaltSourceData
        CK_ULONG ulSaltSourceDataLen
        CK_ULONG iterations
        CK_ULONG prf
        CK_BYTE *pPrfData
        CK_ULONG ulPrfDataLen
        CK_UTF8CHAR *pPassword
        CK_ULONG ulPasswordLen

    ctypedef struct CK_HKDF_PARAMS:
        CK_BBOOL bExtract
        CK_BBOOL bExpand
        CK_MECHANISM_TYPE prfHashMechanism
        CK_ULONG ulSaltType
        CK_BYTE *pSalt
        CK_ULONG ulSaltLen
        CK_OBJECT_HANDLE hSaltKey
        CK_BYTE *pInfo
        CK_ULONG ulInfoLen

    # CK_XEDDSA_PARAMS — XEdDSA signing (PKCS#11 v3.0+)
    ctypedef CK_ULONG CK_XEDDSA_HASH_TYPE

    ctypedef struct CK_XEDDSA_PARAMS:
        CK_XEDDSA_HASH_TYPE hash

    # CK_ECDH_AES_KEY_WRAP_PARAMS — ECDH-based AES key wrap
    ctypedef struct CK_ECDH_AES_KEY_WRAP_PARAMS:
        CK_ULONG ulAESKeyBits
        CK_EC_KDF_TYPE kdf
        CK_ULONG ulSharedDataLen
        CK_BYTE *pSharedData

    # CK_RSA_AES_KEY_WRAP_PARAMS — RSA+AES key wrap
    ctypedef struct CK_RSA_AES_KEY_WRAP_PARAMS:
        CK_ULONG ulAESKeyBits
        CK_RSA_PKCS_OAEP_PARAMS *pOAEPParams

    # CK_CHACHA20_PARAMS — ChaCha20 bare stream cipher
    ctypedef struct CK_CHACHA20_PARAMS:
        CK_BYTE *pBlockCounter
        CK_ULONG blockCounterBits
        CK_BYTE *pNonce
        CK_ULONG ulNonceBits

    # CK_SALSA20_PARAMS — Salsa20 bare stream cipher
    ctypedef struct CK_SALSA20_PARAMS:
        CK_BYTE *pBlockCounter
        CK_BYTE *pNonce
        CK_ULONG ulNonceBits

    # CK_DES_CBC_ENCRYPT_DATA_PARAMS — DES/3DES CBC key derivation (8-byte IV)
    ctypedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS:
        CK_BYTE iv[8]
        CK_BYTE *pData
        CK_ULONG length

    ctypedef struct CK_ASYNC_DATA:
        CK_ULONG ulVersion
        CK_BYTE *pValue
        CK_ULONG ulValue
        CK_OBJECT_HANDLE hObject
        CK_OBJECT_HANDLE hAdditionalObject

    cdef struct CK_FUNCTION_LIST:
        CK_VERSION version
        ## pointers to library functions are stored here
        ## caution: order matters!

        ## general purpose
        CK_RV C_Initialize(void *) nogil

        CK_RV C_Finalize(void *) nogil

        CK_RV C_GetInfo(CK_INFO *info) nogil

        CK_RV C_GetFunctionList(CK_FUNCTION_LIST **) nogil

        ## slot and token management
        CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                            CK_SLOT_ID *slotList,
                            CK_ULONG *count) nogil

        CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                            CK_SLOT_INFO *info) nogil

        CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
                             CK_TOKEN_INFO *info) nogil

        CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE *mechanismList,
                                 CK_ULONG *count) nogil

        CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE mechanism,
                                 CK_MECHANISM_INFO *info) nogil

        CK_RV C_InitToken(CK_SLOT_ID slotID,
                          CK_UTF8CHAR *pPin,
                          CK_ULONG ulPinLen,
                          CK_UTF8CHAR *pLabel) nogil

        CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
                        CK_UTF8CHAR *pPin,
                        CK_ULONG ulPinLen) nogil

        CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
                       CK_UTF8CHAR *pOldPin,
                       CK_ULONG ulOldLen,
                       CK_UTF8CHAR *pNewPin,
                       CK_ULONG ulNewLen) nogil

        ## session management
        CK_RV C_OpenSession(CK_SLOT_ID slotID,
                            CK_FLAGS flags,
                            void *application,
                            void *notify,
                            CK_SESSION_HANDLE *handle) nogil

        CK_RV C_CloseSession(CK_SESSION_HANDLE session) nogil

        CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) nogil

        CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                               CK_SESSION_INFO *pInfo) nogil

        CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                                  CK_BYTE *pOperationState,
                                  CK_ULONG *pulOperationStateLen) nogil

        CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                                  CK_BYTE *pOperationState,
                                  CK_ULONG ulOperationStateLen,
                                  CK_OBJECT_HANDLE hEncryptionKey,
                                  CK_OBJECT_HANDLE hAuthenticationKey) nogil

        CK_RV C_Login(CK_SESSION_HANDLE session,
                      CK_USER_TYPE userType,
                      CK_UTF8CHAR *pin,
                      CK_ULONG pinLen) nogil

        CK_RV C_Logout(CK_SESSION_HANDLE session) nogil

        ## object management
        CK_RV C_CreateObject(CK_SESSION_HANDLE session,
                             CK_ATTRIBUTE *template,
                             CK_ULONG count,
                             CK_OBJECT_HANDLE *key) nogil

        CK_RV C_CopyObject(CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE key,
                           CK_ATTRIBUTE *template,
                           CK_ULONG count,
                           CK_OBJECT_HANDLE *new_key) nogil

        CK_RV C_DestroyObject(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE key) nogil

        CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
                              CK_OBJECT_HANDLE hObject,
                              CK_ULONG *pulSize) nogil

        CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key,
                                  CK_ATTRIBUTE *template,
                                  CK_ULONG count) nogil

        CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key,
                                  CK_ATTRIBUTE *template,
                                  CK_ULONG count) nogil

        CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE *template,
                                CK_ULONG count) nogil

        CK_RV C_FindObjects(CK_SESSION_HANDLE session,
                            CK_OBJECT_HANDLE *objects,
                            CK_ULONG objectsMax,
                            CK_ULONG *objectsLength) nogil

        CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session) nogil

        ## encryption and decryption
        CK_RV C_EncryptInit(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE key) nogil

        CK_RV C_Encrypt(CK_SESSION_HANDLE session,
                        CK_BYTE *plaintext,
                        CK_ULONG plaintext_len,
                        CK_BYTE *ciphertext,
                        CK_ULONG *ciphertext_len) nogil

        CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session,
                              CK_BYTE *part_in,
                              CK_ULONG part_in_len,
                              CK_BYTE *part_out,
                              CK_ULONG *part_out_len) nogil

        CK_RV C_EncryptFinal(CK_SESSION_HANDLE session,
                             CK_BYTE *part_out,
                             CK_ULONG *part_out_len) nogil

        CK_RV C_DecryptInit(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE key) nogil

        CK_RV C_Decrypt(CK_SESSION_HANDLE session,
                        CK_BYTE *ciphertext,
                        CK_ULONG ciphertext_len,
                        CK_BYTE *plaintext,
                        CK_ULONG *plaintext_len) nogil

        CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session,
                              CK_BYTE *part_in,
                              CK_ULONG part_in_len,
                              CK_BYTE *part_out,
                              CK_ULONG *part_out_len) nogil

        CK_RV C_DecryptFinal(CK_SESSION_HANDLE session,
                             CK_BYTE *part_out,
                             CK_ULONG *part_out_len) nogil

        ## Message digests
        CK_RV C_DigestInit(CK_SESSION_HANDLE session,
                           CK_MECHANISM *mechanism) nogil

        CK_RV C_Digest(CK_SESSION_HANDLE session,
                       CK_BYTE *data,
                       CK_ULONG data_len,
                       CK_BYTE *digest,
                       CK_ULONG *digest_len) nogil

        CK_RV C_DigestUpdate(CK_SESSION_HANDLE session,
                             CK_BYTE *data,
                             CK_ULONG data_len) nogil

        CK_RV C_DigestKey(CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE key) nogil

        CK_RV C_DigestFinal(CK_SESSION_HANDLE session,
                            CK_BYTE *digest,
                            CK_ULONG *digest_len) nogil

        ## Signing and MACing
        CK_RV C_SignInit(CK_SESSION_HANDLE session,
                         CK_MECHANISM *mechanism,
                         CK_OBJECT_HANDLE key) nogil

        CK_RV C_Sign(CK_SESSION_HANDLE session,
                     CK_BYTE *text,
                     CK_ULONG text_len,
                     CK_BYTE *signature,
                     CK_ULONG *sig_len) nogil

        CK_RV C_SignUpdate(CK_SESSION_HANDLE session,
                           CK_BYTE *part,
                           CK_ULONG part_len) nogil

        CK_RV C_SignFinal(CK_SESSION_HANDLE session,
                          CK_BYTE *signature,
                          CK_ULONG *sig_len) nogil

        CK_RV C_SignRecoverInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key) nogil

        CK_RV C_SignRecover(CK_SESSION_HANDLE session,
                            CK_BYTE *text,
                            CK_ULONG text_len,
                            CK_BYTE *signature,
                            CK_ULONG *sig_len) nogil


        ## Verifying signatures and MACs
        CK_RV C_VerifyInit(CK_SESSION_HANDLE session,
                           CK_MECHANISM *mechanism,
                           CK_OBJECT_HANDLE key) nogil

        CK_RV C_Verify(CK_SESSION_HANDLE session,
                       CK_BYTE *text,
                       CK_ULONG text_len,
                       CK_BYTE *signature,
                       CK_ULONG sig_len) nogil

        CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session,
                             CK_BYTE *text,
                             CK_ULONG text_len) nogil

        CK_RV C_VerifyFinal(CK_SESSION_HANDLE session,
                            CK_BYTE *signature,
                            CK_ULONG sig_len) nogil

        CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE session,
                                  CK_MECHANISM *mechanism,
                                  CK_OBJECT_HANDLE key) nogil

        CK_RV C_VerifyRecover(CK_SESSION_HANDLE session,
                              CK_BYTE *text,
                              CK_ULONG text_len,
                              CK_BYTE *signature,
                              CK_ULONG sig_len) nogil

        ## dual-function crypto operations
        CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *data,
                                    CK_ULONG data_len,
                                    CK_BYTE *encrypted,
                                    CK_ULONG *encrypted_len) nogil

        CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *encrypted,
                                    CK_ULONG encrypted_len,
                                    CK_BYTE *data,
                                    CK_ULONG *data_len) nogil

        CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE *part,
                                  CK_ULONG part_len) nogil

        CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *text,
                                    CK_ULONG text_len) nogil

        ## key management
        CK_RV C_GenerateKey(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_ATTRIBUTE *template,
                            CK_ULONG count,
                            CK_OBJECT_HANDLE *key) nogil

        CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_ATTRIBUTE *public_template,
                                CK_ULONG public_count,
                                CK_ATTRIBUTE *private_template,
                                CK_ULONG private_count,
                                CK_OBJECT_HANDLE *public_key,
                                CK_OBJECT_HANDLE *private_key) nogil

        CK_RV C_WrapKey(CK_SESSION_HANDLE session,
                        CK_MECHANISM *mechanism,
                        CK_OBJECT_HANDLE wrapping_key,
                        CK_OBJECT_HANDLE key_to_wrap,
                        CK_BYTE *wrapped_key,
                        CK_ULONG *wrapped_key_len) nogil

        CK_RV C_UnwrapKey(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mechanism,
                          CK_OBJECT_HANDLE unwrapping_key,
                          CK_BYTE *wrapped_key,
                          CK_ULONG wrapped_key_len,
                          CK_ATTRIBUTE *attrs,
                          CK_ULONG attr_len,
                          CK_OBJECT_HANDLE *unwrapped_key) nogil

        CK_RV C_DeriveKey(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mechanism,
                          CK_OBJECT_HANDLE src_key,
                          CK_ATTRIBUTE *template,
                          CK_ULONG count,
                          CK_OBJECT_HANDLE *new_key) nogil

        ## random number generation
        CK_RV C_SeedRandom(CK_SESSION_HANDLE session,
                           CK_BYTE *seed,
                           CK_ULONG length) nogil

        CK_RV C_GenerateRandom(CK_SESSION_HANDLE session,
                               CK_BYTE *random,
                               CK_ULONG length) nogil


        ## parallel processing
        CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE session) nogil

        CK_RV C_CancelFunction(CK_SESSION_HANDLE session) nogil

        ## smart card events
        CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
                                 CK_SLOT_ID *slot,
                                 void *pRserved) nogil

    # PKCS#11 v3.0+ interface negotiation structures
    cdef struct CK_INTERFACE:
        CK_UTF8CHAR *pInterfaceName
        void *pFunctionList
        CK_FLAGS flags

    # PKCS#11 v3.0 extended function list — complete layout matching the spec.
    # Mirrors struct CK_FUNCTION_LIST_3_0 from the public domain pkcs11_v32.h.
    # Must include all fields in order to get correct offsets for v3.0 additions.
    cdef struct CK_FUNCTION_LIST_3_0:
        CK_VERSION version
        ## v2.40 base (same layout as CK_FUNCTION_LIST)
        CK_RV C_Initialize(void *) nogil
        CK_RV C_Finalize(void *) nogil
        CK_RV C_GetInfo(CK_INFO *info) nogil
        CK_RV C_GetFunctionList(CK_FUNCTION_LIST **) nogil
        CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                            CK_SLOT_ID *slotList,
                            CK_ULONG *count) nogil
        CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                            CK_SLOT_INFO *info) nogil
        CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
                             CK_TOKEN_INFO *info) nogil
        CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE *mechanismList,
                                 CK_ULONG *count) nogil
        CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE mechanism,
                                 CK_MECHANISM_INFO *info) nogil
        CK_RV C_InitToken(CK_SLOT_ID slotID,
                          CK_UTF8CHAR *pin, CK_ULONG pinLen,
                          CK_UTF8CHAR *label) nogil
        CK_RV C_InitPIN(CK_SESSION_HANDLE session,
                        CK_UTF8CHAR *pin, CK_ULONG pinLen) nogil
        CK_RV C_SetPIN(CK_SESSION_HANDLE session,
                       CK_UTF8CHAR *oldPin, CK_ULONG oldPinLen,
                       CK_UTF8CHAR *newPin, CK_ULONG newPinLen) nogil
        CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                            void *application, void *notify,
                            CK_SESSION_HANDLE *session) nogil
        CK_RV C_CloseSession(CK_SESSION_HANDLE session) nogil
        CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) nogil
        CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session,
                               CK_SESSION_INFO *info) nogil
        CK_RV C_GetOperationState(CK_SESSION_HANDLE session,
                                  CK_BYTE *state, CK_ULONG *stateLen) nogil
        CK_RV C_SetOperationState(CK_SESSION_HANDLE session,
                                  CK_BYTE *state, CK_ULONG stateLen,
                                  CK_OBJECT_HANDLE encKey,
                                  CK_OBJECT_HANDLE authKey) nogil
        CK_RV C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE userType,
                      CK_UTF8CHAR *pin, CK_ULONG pinLen) nogil
        CK_RV C_Logout(CK_SESSION_HANDLE session) nogil
        CK_RV C_CreateObject(CK_SESSION_HANDLE session,
                             CK_ATTRIBUTE *templ, CK_ULONG count,
                             CK_OBJECT_HANDLE *object) nogil
        CK_RV C_CopyObject(CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE *templ, CK_ULONG count,
                           CK_OBJECT_HANDLE *newObject) nogil
        CK_RV C_DestroyObject(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE object) nogil
        CK_RV C_GetObjectSize(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE object,
                              CK_ULONG *size) nogil
        CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE object,
                                  CK_ATTRIBUTE *templ,
                                  CK_ULONG count) nogil
        CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE object,
                                  CK_ATTRIBUTE *templ,
                                  CK_ULONG count) nogil
        CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE *templ, CK_ULONG count) nogil
        CK_RV C_FindObjects(CK_SESSION_HANDLE session,
                            CK_OBJECT_HANDLE *object,
                            CK_ULONG maxCount, CK_ULONG *count) nogil
        CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_EncryptInit(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE key) nogil
        CK_RV C_Encrypt(CK_SESSION_HANDLE session,
                        CK_BYTE *data, CK_ULONG dataLen,
                        CK_BYTE *encData, CK_ULONG *encDataLen) nogil
        CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session,
                              CK_BYTE *part, CK_ULONG partLen,
                              CK_BYTE *encPart, CK_ULONG *encPartLen) nogil
        CK_RV C_EncryptFinal(CK_SESSION_HANDLE session,
                             CK_BYTE *lastPart, CK_ULONG *lastPartLen) nogil
        CK_RV C_DecryptInit(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE key) nogil
        CK_RV C_Decrypt(CK_SESSION_HANDLE session,
                        CK_BYTE *encData, CK_ULONG encDataLen,
                        CK_BYTE *data, CK_ULONG *dataLen) nogil
        CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session,
                              CK_BYTE *encPart, CK_ULONG encPartLen,
                              CK_BYTE *part, CK_ULONG *partLen) nogil
        CK_RV C_DecryptFinal(CK_SESSION_HANDLE session,
                             CK_BYTE *lastPart, CK_ULONG *lastPartLen) nogil
        CK_RV C_DigestInit(CK_SESSION_HANDLE session,
                           CK_MECHANISM *mechanism) nogil
        CK_RV C_Digest(CK_SESSION_HANDLE session,
                       CK_BYTE *data, CK_ULONG dataLen,
                       CK_BYTE *digest, CK_ULONG *digestLen) nogil
        CK_RV C_DigestUpdate(CK_SESSION_HANDLE session,
                             CK_BYTE *part, CK_ULONG partLen) nogil
        CK_RV C_DigestKey(CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE key) nogil
        CK_RV C_DigestFinal(CK_SESSION_HANDLE session,
                            CK_BYTE *digest, CK_ULONG *digestLen) nogil
        CK_RV C_SignInit(CK_SESSION_HANDLE session,
                         CK_MECHANISM *mechanism,
                         CK_OBJECT_HANDLE key) nogil
        CK_RV C_Sign(CK_SESSION_HANDLE session,
                     CK_BYTE *data, CK_ULONG dataLen,
                     CK_BYTE *signature, CK_ULONG *signatureLen) nogil
        CK_RV C_SignUpdate(CK_SESSION_HANDLE session,
                           CK_BYTE *part, CK_ULONG partLen) nogil
        CK_RV C_SignFinal(CK_SESSION_HANDLE session,
                          CK_BYTE *signature, CK_ULONG *signatureLen) nogil
        CK_RV C_SignRecoverInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key) nogil
        CK_RV C_SignRecover(CK_SESSION_HANDLE session,
                            CK_BYTE *data, CK_ULONG dataLen,
                            CK_BYTE *signature, CK_ULONG *signatureLen) nogil
        CK_RV C_VerifyInit(CK_SESSION_HANDLE session,
                           CK_MECHANISM *mechanism,
                           CK_OBJECT_HANDLE key) nogil
        CK_RV C_Verify(CK_SESSION_HANDLE session,
                       CK_BYTE *data, CK_ULONG dataLen,
                       CK_BYTE *signature, CK_ULONG signatureLen) nogil
        CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session,
                             CK_BYTE *part, CK_ULONG partLen) nogil
        CK_RV C_VerifyFinal(CK_SESSION_HANDLE session,
                            CK_BYTE *signature, CK_ULONG signatureLen) nogil
        CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE session,
                                  CK_MECHANISM *mechanism,
                                  CK_OBJECT_HANDLE key) nogil
        CK_RV C_VerifyRecover(CK_SESSION_HANDLE session,
                              CK_BYTE *signature, CK_ULONG signatureLen,
                              CK_BYTE *data, CK_ULONG *dataLen) nogil
        CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *part, CK_ULONG partLen,
                                    CK_BYTE *encPart,
                                    CK_ULONG *encPartLen) nogil
        CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *encPart, CK_ULONG encPartLen,
                                    CK_BYTE *part, CK_ULONG *partLen) nogil
        CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE *part, CK_ULONG partLen,
                                  CK_BYTE *encPart,
                                  CK_ULONG *encPartLen) nogil
        CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *encPart, CK_ULONG encPartLen,
                                    CK_BYTE *part, CK_ULONG *partLen) nogil
        CK_RV C_GenerateKey(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_ATTRIBUTE *templ, CK_ULONG count,
                            CK_OBJECT_HANDLE *key) nogil
        CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_ATTRIBUTE *publicKeyTemplate,
                                CK_ULONG publicKeyAttributeCount,
                                CK_ATTRIBUTE *privateKeyTemplate,
                                CK_ULONG privateKeyAttributeCount,
                                CK_OBJECT_HANDLE *publicKey,
                                CK_OBJECT_HANDLE *privateKey) nogil
        CK_RV C_WrapKey(CK_SESSION_HANDLE session,
                        CK_MECHANISM *mechanism,
                        CK_OBJECT_HANDLE wrappingKey,
                        CK_OBJECT_HANDLE key,
                        CK_BYTE *wrappedKey,
                        CK_ULONG *wrappedKeyLen) nogil
        CK_RV C_UnwrapKey(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mechanism,
                          CK_OBJECT_HANDLE unwrappingKey,
                          CK_BYTE *wrappedKey, CK_ULONG wrappedKeyLen,
                          CK_ATTRIBUTE *templ, CK_ULONG count,
                          CK_OBJECT_HANDLE *key) nogil
        CK_RV C_DeriveKey(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mechanism,
                          CK_OBJECT_HANDLE baseKey,
                          CK_ATTRIBUTE *templ, CK_ULONG count,
                          CK_OBJECT_HANDLE *key) nogil
        CK_RV C_SeedRandom(CK_SESSION_HANDLE session,
                           CK_BYTE *seed, CK_ULONG seedLen) nogil
        CK_RV C_GenerateRandom(CK_SESSION_HANDLE session,
                               CK_BYTE *randomData,
                               CK_ULONG randomLen) nogil
        CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE session) nogil
        CK_RV C_CancelFunction(CK_SESSION_HANDLE session) nogil
        CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
                                 CK_SLOT_ID *slot,
                                 void *pRserved) nogil
        ## v3.0 additions (after C_WaitForSlotEvent)
        CK_RV C_GetInterfaceList(CK_INTERFACE *interfacesList,
                                 CK_ULONG *count) nogil
        CK_RV C_GetInterface(CK_UTF8CHAR *interfaceName,
                             CK_VERSION *version,
                             CK_INTERFACE **ppInterface,
                             CK_FLAGS flags) nogil
        CK_RV C_LoginUser(CK_SESSION_HANDLE session,
                          CK_USER_TYPE userType,
                          CK_UTF8CHAR *pin, CK_ULONG pinLen,
                          CK_UTF8CHAR *username, CK_ULONG usernameLen) nogil
        CK_RV C_SessionCancel(CK_SESSION_HANDLE session,
                              CK_FLAGS flags) nogil
        CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE session,
                                   CK_MECHANISM *mechanism,
                                   CK_OBJECT_HANDLE key) nogil
        CK_RV C_EncryptMessage(CK_SESSION_HANDLE session,
                               void *parameter, CK_ULONG paramLen,
                               CK_BYTE *associated, CK_ULONG associatedLen,
                               CK_BYTE *plaintext, CK_ULONG plaintextLen,
                               CK_BYTE *ciphertext,
                               CK_ULONG *ciphertextLen) nogil
        CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE session,
                                    void *parameter,
                                    CK_ULONG paramLen,
                                    CK_BYTE *associated,
                                    CK_ULONG associatedLen) nogil
        CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE session,
                                   void *parameter, CK_ULONG paramLen,
                                   CK_BYTE *plaintext, CK_ULONG plaintextLen,
                                   CK_BYTE *ciphertext,
                                   CK_ULONG *ciphertextLen,
                                   CK_FLAGS flags) nogil
        CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE session,
                                   CK_MECHANISM *mechanism,
                                   CK_OBJECT_HANDLE key) nogil
        CK_RV C_DecryptMessage(CK_SESSION_HANDLE session,
                               void *parameter, CK_ULONG paramLen,
                               CK_BYTE *associated, CK_ULONG associatedLen,
                               CK_BYTE *ciphertext, CK_ULONG ciphertextLen,
                               CK_BYTE *plaintext, CK_ULONG *plaintextLen) nogil
        CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE session,
                                    void *parameter, CK_ULONG paramLen,
                                    CK_BYTE *associated,
                                    CK_ULONG associatedLen) nogil
        CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE session,
                                   void *parameter, CK_ULONG paramLen,
                                   CK_BYTE *ciphertext, CK_ULONG ciphertextLen,
                                   CK_BYTE *plaintext,
                                   CK_ULONG *plaintextLen,
                                   CK_FLAGS flags) nogil
        CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_MessageSignInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key) nogil
        CK_RV C_SignMessage(CK_SESSION_HANDLE session,
                            void *parameter, CK_ULONG paramLen,
                            CK_BYTE *data, CK_ULONG dataLen,
                            CK_BYTE *signature,
                            CK_ULONG *signatureLen) nogil
        CK_RV C_SignMessageBegin(CK_SESSION_HANDLE session,
                                 void *parameter,
                                 CK_ULONG paramLen) nogil
        CK_RV C_SignMessageNext(CK_SESSION_HANDLE session,
                                void *parameter, CK_ULONG paramLen,
                                CK_BYTE *data, CK_ULONG dataLen,
                                CK_BYTE *signature,
                                CK_ULONG *signatureLen) nogil
        CK_RV C_MessageSignFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE session,
                                  CK_MECHANISM *mechanism,
                                  CK_OBJECT_HANDLE key) nogil
        CK_RV C_VerifyMessage(CK_SESSION_HANDLE session,
                              void *parameter, CK_ULONG paramLen,
                              CK_BYTE *data, CK_ULONG dataLen,
                              CK_BYTE *signature,
                              CK_ULONG signatureLen) nogil
        CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE session,
                                   void *parameter,
                                   CK_ULONG paramLen) nogil
        CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE session,
                                  void *parameter, CK_ULONG paramLen,
                                  CK_BYTE *data, CK_ULONG dataLen,
                                  CK_BYTE *signature,
                                  CK_ULONG signatureLen) nogil
        CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE session) nogil

    # PKCS#11 v3.2 extended function list — superset of CK_FUNCTION_LIST_3_0.
    # Adds encapsulate/decapsulate (KEM) and other v3.2 functions.
    # Cython cannot inherit C structs, so v2.40+v3.0 fields are repeated
    # to get correct offsets for the v3.2 additions at the end.
    cdef struct CK_FUNCTION_LIST_3_2:
        CK_VERSION version
        ## v2.40 base (same layout as CK_FUNCTION_LIST)
        CK_RV C_Initialize(void *) nogil
        CK_RV C_Finalize(void *) nogil
        CK_RV C_GetInfo(CK_INFO *info) nogil
        CK_RV C_GetFunctionList(CK_FUNCTION_LIST **) nogil
        CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                            CK_SLOT_ID *slotList,
                            CK_ULONG *count) nogil
        CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                            CK_SLOT_INFO *info) nogil
        CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
                             CK_TOKEN_INFO *info) nogil
        CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE *mechanismList,
                                 CK_ULONG *count) nogil
        CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                                 CK_MECHANISM_TYPE mechanism,
                                 CK_MECHANISM_INFO *info) nogil
        CK_RV C_InitToken(CK_SLOT_ID slotID,
                          CK_UTF8CHAR *pin, CK_ULONG pinLen,
                          CK_UTF8CHAR *label) nogil
        CK_RV C_InitPIN(CK_SESSION_HANDLE session,
                        CK_UTF8CHAR *pin, CK_ULONG pinLen) nogil
        CK_RV C_SetPIN(CK_SESSION_HANDLE session,
                       CK_UTF8CHAR *oldPin, CK_ULONG oldPinLen,
                       CK_UTF8CHAR *newPin, CK_ULONG newPinLen) nogil
        CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                            void *application, void *notify,
                            CK_SESSION_HANDLE *session) nogil
        CK_RV C_CloseSession(CK_SESSION_HANDLE session) nogil
        CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) nogil
        CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session,
                               CK_SESSION_INFO *info) nogil
        CK_RV C_GetOperationState(CK_SESSION_HANDLE session,
                                  CK_BYTE *state, CK_ULONG *stateLen) nogil
        CK_RV C_SetOperationState(CK_SESSION_HANDLE session,
                                  CK_BYTE *state, CK_ULONG stateLen,
                                  CK_OBJECT_HANDLE encKey,
                                  CK_OBJECT_HANDLE authKey) nogil
        CK_RV C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE userType,
                      CK_UTF8CHAR *pin, CK_ULONG pinLen) nogil
        CK_RV C_Logout(CK_SESSION_HANDLE session) nogil
        CK_RV C_CreateObject(CK_SESSION_HANDLE session,
                             CK_ATTRIBUTE *templ, CK_ULONG count,
                             CK_OBJECT_HANDLE *object) nogil
        CK_RV C_CopyObject(CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE *templ, CK_ULONG count,
                           CK_OBJECT_HANDLE *newObject) nogil
        CK_RV C_DestroyObject(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE object) nogil
        CK_RV C_GetObjectSize(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE object,
                              CK_ULONG *size) nogil
        CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE object,
                                  CK_ATTRIBUTE *templ,
                                  CK_ULONG count) nogil
        CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE object,
                                  CK_ATTRIBUTE *templ,
                                  CK_ULONG count) nogil
        CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE *templ, CK_ULONG count) nogil
        CK_RV C_FindObjects(CK_SESSION_HANDLE session,
                            CK_OBJECT_HANDLE *object,
                            CK_ULONG maxCount, CK_ULONG *count) nogil
        CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_EncryptInit(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE key) nogil
        CK_RV C_Encrypt(CK_SESSION_HANDLE session,
                        CK_BYTE *data, CK_ULONG dataLen,
                        CK_BYTE *encData, CK_ULONG *encDataLen) nogil
        CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session,
                              CK_BYTE *part, CK_ULONG partLen,
                              CK_BYTE *encPart, CK_ULONG *encPartLen) nogil
        CK_RV C_EncryptFinal(CK_SESSION_HANDLE session,
                             CK_BYTE *lastPart, CK_ULONG *lastPartLen) nogil
        CK_RV C_DecryptInit(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_OBJECT_HANDLE key) nogil
        CK_RV C_Decrypt(CK_SESSION_HANDLE session,
                        CK_BYTE *encData, CK_ULONG encDataLen,
                        CK_BYTE *data, CK_ULONG *dataLen) nogil
        CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session,
                              CK_BYTE *encPart, CK_ULONG encPartLen,
                              CK_BYTE *part, CK_ULONG *partLen) nogil
        CK_RV C_DecryptFinal(CK_SESSION_HANDLE session,
                             CK_BYTE *lastPart, CK_ULONG *lastPartLen) nogil
        CK_RV C_DigestInit(CK_SESSION_HANDLE session,
                           CK_MECHANISM *mechanism) nogil
        CK_RV C_Digest(CK_SESSION_HANDLE session,
                       CK_BYTE *data, CK_ULONG dataLen,
                       CK_BYTE *digest, CK_ULONG *digestLen) nogil
        CK_RV C_DigestUpdate(CK_SESSION_HANDLE session,
                             CK_BYTE *part, CK_ULONG partLen) nogil
        CK_RV C_DigestKey(CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE key) nogil
        CK_RV C_DigestFinal(CK_SESSION_HANDLE session,
                            CK_BYTE *digest, CK_ULONG *digestLen) nogil
        CK_RV C_SignInit(CK_SESSION_HANDLE session,
                         CK_MECHANISM *mechanism,
                         CK_OBJECT_HANDLE key) nogil
        CK_RV C_Sign(CK_SESSION_HANDLE session,
                     CK_BYTE *data, CK_ULONG dataLen,
                     CK_BYTE *signature, CK_ULONG *signatureLen) nogil
        CK_RV C_SignUpdate(CK_SESSION_HANDLE session,
                           CK_BYTE *part, CK_ULONG partLen) nogil
        CK_RV C_SignFinal(CK_SESSION_HANDLE session,
                          CK_BYTE *signature, CK_ULONG *signatureLen) nogil
        CK_RV C_SignRecoverInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key) nogil
        CK_RV C_SignRecover(CK_SESSION_HANDLE session,
                            CK_BYTE *data, CK_ULONG dataLen,
                            CK_BYTE *signature, CK_ULONG *signatureLen) nogil
        CK_RV C_VerifyInit(CK_SESSION_HANDLE session,
                           CK_MECHANISM *mechanism,
                           CK_OBJECT_HANDLE key) nogil
        CK_RV C_Verify(CK_SESSION_HANDLE session,
                       CK_BYTE *data, CK_ULONG dataLen,
                       CK_BYTE *signature, CK_ULONG signatureLen) nogil
        CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session,
                             CK_BYTE *part, CK_ULONG partLen) nogil
        CK_RV C_VerifyFinal(CK_SESSION_HANDLE session,
                            CK_BYTE *signature, CK_ULONG signatureLen) nogil
        CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE session,
                                  CK_MECHANISM *mechanism,
                                  CK_OBJECT_HANDLE key) nogil
        CK_RV C_VerifyRecover(CK_SESSION_HANDLE session,
                              CK_BYTE *signature, CK_ULONG signatureLen,
                              CK_BYTE *data, CK_ULONG *dataLen) nogil
        CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *part, CK_ULONG partLen,
                                    CK_BYTE *encPart,
                                    CK_ULONG *encPartLen) nogil
        CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *encPart, CK_ULONG encPartLen,
                                    CK_BYTE *part, CK_ULONG *partLen) nogil
        CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE *part, CK_ULONG partLen,
                                  CK_BYTE *encPart,
                                  CK_ULONG *encPartLen) nogil
        CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE session,
                                    CK_BYTE *encPart, CK_ULONG encPartLen,
                                    CK_BYTE *part, CK_ULONG *partLen) nogil
        CK_RV C_GenerateKey(CK_SESSION_HANDLE session,
                            CK_MECHANISM *mechanism,
                            CK_ATTRIBUTE *templ, CK_ULONG count,
                            CK_OBJECT_HANDLE *key) nogil
        CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_ATTRIBUTE *publicKeyTemplate,
                                CK_ULONG publicKeyAttributeCount,
                                CK_ATTRIBUTE *privateKeyTemplate,
                                CK_ULONG privateKeyAttributeCount,
                                CK_OBJECT_HANDLE *publicKey,
                                CK_OBJECT_HANDLE *privateKey) nogil
        CK_RV C_WrapKey(CK_SESSION_HANDLE session,
                        CK_MECHANISM *mechanism,
                        CK_OBJECT_HANDLE wrappingKey,
                        CK_OBJECT_HANDLE key,
                        CK_BYTE *wrappedKey,
                        CK_ULONG *wrappedKeyLen) nogil
        CK_RV C_UnwrapKey(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mechanism,
                          CK_OBJECT_HANDLE unwrappingKey,
                          CK_BYTE *wrappedKey, CK_ULONG wrappedKeyLen,
                          CK_ATTRIBUTE *templ, CK_ULONG count,
                          CK_OBJECT_HANDLE *key) nogil
        CK_RV C_DeriveKey(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mechanism,
                          CK_OBJECT_HANDLE baseKey,
                          CK_ATTRIBUTE *templ, CK_ULONG count,
                          CK_OBJECT_HANDLE *key) nogil
        CK_RV C_SeedRandom(CK_SESSION_HANDLE session,
                           CK_BYTE *seed, CK_ULONG seedLen) nogil
        CK_RV C_GenerateRandom(CK_SESSION_HANDLE session,
                               CK_BYTE *randomData,
                               CK_ULONG randomLen) nogil
        CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE session) nogil
        CK_RV C_CancelFunction(CK_SESSION_HANDLE session) nogil
        CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
                                 CK_SLOT_ID *slot,
                                 void *pRserved) nogil
        ## v3.0 additions
        CK_RV C_GetInterfaceList(CK_INTERFACE *interfacesList,
                                 CK_ULONG *count) nogil
        CK_RV C_GetInterface(CK_UTF8CHAR *interfaceName,
                             CK_VERSION *version,
                             CK_INTERFACE **ppInterface,
                             CK_FLAGS flags) nogil
        CK_RV C_LoginUser(CK_SESSION_HANDLE session,
                          CK_USER_TYPE userType,
                          CK_UTF8CHAR *pin, CK_ULONG pinLen,
                          CK_UTF8CHAR *username, CK_ULONG usernameLen) nogil
        CK_RV C_SessionCancel(CK_SESSION_HANDLE session,
                              CK_FLAGS flags) nogil
        CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE session,
                                   CK_MECHANISM *mechanism,
                                   CK_OBJECT_HANDLE key) nogil
        CK_RV C_EncryptMessage(CK_SESSION_HANDLE session,
                               void *parameter, CK_ULONG paramLen,
                               CK_BYTE *associated, CK_ULONG associatedLen,
                               CK_BYTE *plaintext, CK_ULONG plaintextLen,
                               CK_BYTE *ciphertext,
                               CK_ULONG *ciphertextLen) nogil
        CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE session,
                                    void *parameter,
                                    CK_ULONG paramLen,
                                    CK_BYTE *associated,
                                    CK_ULONG associatedLen) nogil
        CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE session,
                                   void *parameter, CK_ULONG paramLen,
                                   CK_BYTE *plaintext, CK_ULONG plaintextLen,
                                   CK_BYTE *ciphertext,
                                   CK_ULONG *ciphertextLen,
                                   CK_FLAGS flags) nogil
        CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE session,
                                   CK_MECHANISM *mechanism,
                                   CK_OBJECT_HANDLE key) nogil
        CK_RV C_DecryptMessage(CK_SESSION_HANDLE session,
                               void *parameter, CK_ULONG paramLen,
                               CK_BYTE *associated, CK_ULONG associatedLen,
                               CK_BYTE *ciphertext, CK_ULONG ciphertextLen,
                               CK_BYTE *plaintext, CK_ULONG *plaintextLen) nogil
        CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE session,
                                    void *parameter, CK_ULONG paramLen,
                                    CK_BYTE *associated,
                                    CK_ULONG associatedLen) nogil
        CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE session,
                                   void *parameter, CK_ULONG paramLen,
                                   CK_BYTE *ciphertext, CK_ULONG ciphertextLen,
                                   CK_BYTE *plaintext,
                                   CK_ULONG *plaintextLen,
                                   CK_FLAGS flags) nogil
        CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_MessageSignInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM *mechanism,
                                CK_OBJECT_HANDLE key) nogil
        CK_RV C_SignMessage(CK_SESSION_HANDLE session,
                            void *parameter, CK_ULONG paramLen,
                            CK_BYTE *data, CK_ULONG dataLen,
                            CK_BYTE *signature,
                            CK_ULONG *signatureLen) nogil
        CK_RV C_SignMessageBegin(CK_SESSION_HANDLE session,
                                 void *parameter,
                                 CK_ULONG paramLen) nogil
        CK_RV C_SignMessageNext(CK_SESSION_HANDLE session,
                                void *parameter, CK_ULONG paramLen,
                                CK_BYTE *data, CK_ULONG dataLen,
                                CK_BYTE *signature,
                                CK_ULONG *signatureLen) nogil
        CK_RV C_MessageSignFinal(CK_SESSION_HANDLE session) nogil
        CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE session,
                                  CK_MECHANISM *mechanism,
                                  CK_OBJECT_HANDLE key) nogil
        CK_RV C_VerifyMessage(CK_SESSION_HANDLE session,
                              void *parameter, CK_ULONG paramLen,
                              CK_BYTE *data, CK_ULONG dataLen,
                              CK_BYTE *signature,
                              CK_ULONG signatureLen) nogil
        CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE session,
                                   void *parameter,
                                   CK_ULONG paramLen) nogil
        CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE session,
                                  void *parameter, CK_ULONG paramLen,
                                  CK_BYTE *data, CK_ULONG dataLen,
                                  CK_BYTE *signature,
                                  CK_ULONG signatureLen) nogil
        CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE session) nogil
        ## v3.2 additions
        CK_RV C_EncapsulateKey(CK_SESSION_HANDLE session,
                               CK_MECHANISM *mechanism,
                               CK_OBJECT_HANDLE hPublicKey,
                               CK_ATTRIBUTE *templ,
                               CK_ULONG ulAttributeCount,
                               CK_BYTE *pCiphertext,
                               CK_ULONG *pulCiphertextLen,
                               CK_OBJECT_HANDLE *phKey) nogil
        CK_RV C_DecapsulateKey(CK_SESSION_HANDLE session,
                               CK_MECHANISM *mechanism,
                               CK_OBJECT_HANDLE hPrivateKey,
                               CK_ATTRIBUTE *templ,
                               CK_ULONG ulAttributeCount,
                               CK_BYTE *pCiphertext,
                               CK_ULONG ulCiphertextLen,
                               CK_OBJECT_HANDLE *phKey) nogil
        ## C_VerifySignature* — stateless signature verification (v3.2)
        ## Signature is embedded in mechanism_param; data is streamed separately.
        CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE session,
                                    CK_MECHANISM *mechanism,
                                    CK_OBJECT_HANDLE hKey,
                                    CK_BYTE *pSignature,
                                    CK_ULONG ulSignatureLen) nogil
        CK_RV C_VerifySignature(CK_SESSION_HANDLE session,
                                CK_BYTE *data,
                                CK_ULONG dataLen) nogil
        CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE session,
                                      CK_BYTE *data,
                                      CK_ULONG dataLen) nogil
        CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE session) nogil
        ## Remaining v3.2 functions (stub layout to preserve correct struct offsets)
        CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE session,
                                          CK_SESSION_VALIDATION_FLAGS_TYPE type,
                                          CK_FLAGS *pFlags) nogil
        CK_RV C_AsyncComplete(CK_SESSION_HANDLE session,
                              CK_UTF8CHAR *pOperation,
                              CK_ASYNC_DATA *pResult) nogil
        CK_RV C_AsyncGetID(CK_SESSION_HANDLE session,
                           CK_UTF8CHAR *pOperation,
                           CK_ULONG *pulID) nogil
        CK_RV C_AsyncJoin(CK_SESSION_HANDLE session,
                          CK_UTF8CHAR *pOperation,
                          CK_ULONG ulID,
                          CK_BYTE *pData,
                          CK_ULONG ulData) nogil
        CK_RV C_WrapKeyAuthenticated(CK_SESSION_HANDLE session,
                                     CK_MECHANISM *mechanism,
                                     CK_OBJECT_HANDLE hWrappingKey,
                                     CK_OBJECT_HANDLE hKey,
                                     CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
                                     CK_BYTE *pWrappedKey,
                                     CK_ULONG *pulWrappedKeyLen) nogil
        CK_RV C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE session,
                                       CK_MECHANISM *mechanism,
                                       CK_OBJECT_HANDLE hUnwrappingKey,
                                       CK_BYTE *pWrappedKey,
                                       CK_ULONG ulWrappedKeyLen,
                                       CK_ATTRIBUTE *templ,
                                       CK_ULONG ulAttributeCount,
                                       CK_BYTE *pAssociatedData,
                                       CK_ULONG ulAssociatedDataLen,
                                       CK_OBJECT_HANDLE *phKey) nogil

# The only external API call that must be defined in a PKCS#11 library
# All other APIs are taken from the CK_FUNCTION_LIST table
ctypedef CK_RV (*C_GetFunctionList_ptr) (CK_FUNCTION_LIST **) nogil
ctypedef CK_RV (*C_GetInterface_ptr) (CK_UTF8CHAR *, CK_VERSION *,
                                      CK_INTERFACE **, CK_FLAGS) nogil

ctypedef CK_RV (*KeyOperationInit) (
        CK_SESSION_HANDLE session,
        CK_MECHANISM *mechanism,
        CK_OBJECT_HANDLE key
) nogil
ctypedef CK_RV (*OperationUpdateWithResult) (
        CK_SESSION_HANDLE session,
        CK_BYTE *part_in,
        CK_ULONG part_in_len,
        CK_BYTE *part_out,
        CK_ULONG *part_out_len
) nogil
ctypedef CK_RV (*OperationUpdate) (
        CK_SESSION_HANDLE session,
        CK_BYTE *part_in,
        CK_ULONG part_in_len
) nogil
ctypedef CK_RV (*OperationWithResult) (
        CK_SESSION_HANDLE session,
        CK_BYTE *part_out,
        CK_ULONG *part_out_len
) nogil

cdef inline CK_BYTE_buffer(length):
    """Make a buffer for `length` CK_BYTEs."""
    return array(shape=(length,), itemsize=sizeof(CK_BYTE), format='B')


cdef inline CK_ULONG_buffer(length):
    """Make a buffer for `length` CK_ULONGs."""
    return array(shape=(length,), itemsize=sizeof(CK_ULONG), format='L')


# Note: this `cdef inline` declaration doesn't seem to be consistently labelled
# as executed by Cython's line tracing, so we flag it as nocover
# to avoid noise in the metrics.

cdef inline object map_rv_to_error(CK_RV rv):  # pragma: nocover
    if rv == CKR_ATTRIBUTE_TYPE_INVALID:
        exc = AttributeTypeInvalid()
    elif rv == CKR_ATTRIBUTE_VALUE_INVALID:
        exc = AttributeValueInvalid()
    elif rv == CKR_ATTRIBUTE_READ_ONLY:
        exc = AttributeReadOnly()
    elif rv == CKR_ATTRIBUTE_SENSITIVE:
        exc = AttributeSensitive()
    elif rv == CKR_ARGUMENTS_BAD:
        exc = ArgumentsBad()
    elif rv == CKR_BUFFER_TOO_SMALL:
        exc = BufferTooSmall()
    elif rv == CKR_CRYPTOKI_ALREADY_INITIALIZED:
        exc = CryptokiAlreadyInitialized()
    elif rv == CKR_CRYPTOKI_NOT_INITIALIZED:
        exc = CryptokiNotInitialized()
    elif rv == CKR_DATA_INVALID:
        exc = DataInvalid()
    elif rv == CKR_DATA_LEN_RANGE:
        exc = DataLenRange()
    elif rv == CKR_DOMAIN_PARAMS_INVALID:
        exc = DomainParamsInvalid()
    elif rv == CKR_DEVICE_ERROR:
        exc = DeviceError()
    elif rv == CKR_DEVICE_MEMORY:
        exc = DeviceMemory()
    elif rv == CKR_DEVICE_REMOVED:
        exc = DeviceRemoved()
    elif rv == CKR_ENCRYPTED_DATA_INVALID:
        exc = EncryptedDataInvalid()
    elif rv == CKR_ENCRYPTED_DATA_LEN_RANGE:
        exc = EncryptedDataLenRange()
    elif rv == CKR_EXCEEDED_MAX_ITERATIONS:
        exc = ExceededMaxIterations()
    elif rv == CKR_FUNCTION_CANCELED:
        exc = FunctionCancelled()
    elif rv == CKR_FUNCTION_FAILED:
        exc = FunctionFailed()
    elif rv == CKR_FUNCTION_REJECTED:
        exc = FunctionRejected()
    elif rv == CKR_FUNCTION_NOT_SUPPORTED:
        exc = FunctionNotSupported()
    elif rv == CKR_KEY_HANDLE_INVALID:
        exc = KeyHandleInvalid()
    elif rv == CKR_KEY_INDIGESTIBLE:
        exc = KeyIndigestible()
    elif rv == CKR_KEY_NEEDED:
        exc = KeyNeeded()
    elif rv == CKR_KEY_NOT_NEEDED:
        exc = KeyNotNeeded()
    elif rv == CKR_KEY_SIZE_RANGE:
        exc = KeySizeRange()
    elif rv == CKR_KEY_NOT_WRAPPABLE:
        exc = KeyNotWrappable()
    elif rv == CKR_KEY_TYPE_INCONSISTENT:
        exc = KeyTypeInconsistent()
    elif rv == CKR_KEY_UNEXTRACTABLE:
        exc = KeyUnextractable()
    elif rv == CKR_GENERAL_ERROR:
        exc = GeneralError()
    elif rv == CKR_HOST_MEMORY:
        exc = HostMemory()
    elif rv == CKR_MECHANISM_INVALID:
        exc = MechanismInvalid()
    elif rv == CKR_MECHANISM_PARAM_INVALID:
        exc = MechanismParamInvalid()
    elif rv == CKR_NO_EVENT:
        exc = NoEvent()
    elif rv == CKR_OBJECT_HANDLE_INVALID:
        exc = ObjectHandleInvalid()
    elif rv == CKR_OPERATION_ACTIVE:
        exc = OperationActive()
    elif rv == CKR_OPERATION_NOT_INITIALIZED:
        exc = OperationNotInitialized()
    elif rv == CKR_PENDING:
        exc = Pending()
    elif rv == CKR_PIN_EXPIRED:
        exc = PinExpired()
    elif rv == CKR_PIN_INCORRECT:
        exc = PinIncorrect()
    elif rv == CKR_PIN_INVALID:
        exc = PinInvalid()
    elif rv == CKR_PIN_LEN_RANGE:
        exc = PinLenRange()
    elif rv == CKR_PIN_LOCKED:
        exc = PinLocked()
    elif rv == CKR_PIN_TOO_WEAK:
        exc = PinTooWeak()
    elif rv == CKR_PUBLIC_KEY_INVALID:
        exc = PublicKeyInvalid()
    elif rv == CKR_RANDOM_NO_RNG:
        exc = RandomNoRNG()
    elif rv == CKR_RANDOM_SEED_NOT_SUPPORTED:
        exc = RandomSeedNotSupported()
    elif rv == CKR_SESSION_CLOSED:
        exc = SessionClosed()
    elif rv == CKR_SESSION_COUNT:
        exc = SessionCount()
    elif rv == CKR_SESSION_ASYNC_NOT_SUPPORTED:
        exc = SessionAsyncNotSupported()
    elif rv == CKR_SESSION_EXISTS:
        exc = SessionExists()
    elif rv == CKR_SESSION_HANDLE_INVALID:
        exc = SessionHandleInvalid()
    elif rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        exc = ParallelNotSupported()
    elif rv == CKR_SESSION_READ_ONLY:
        exc = SessionReadOnly()
    elif rv == CKR_SESSION_READ_ONLY_EXISTS:
        exc = SessionReadOnlyExists()
    elif rv == CKR_SESSION_READ_WRITE_SO_EXISTS:
        exc = SessionReadWriteSOExists()
    elif rv == CKR_SIGNATURE_LEN_RANGE:
        exc = SignatureLenRange()
    elif rv == CKR_SIGNATURE_INVALID:
        exc = SignatureInvalid()
    elif rv == CKR_TEMPLATE_INCOMPLETE:
        exc = TemplateIncomplete()
    elif rv == CKR_TEMPLATE_INCONSISTENT:
        exc = TemplateInconsistent()
    elif rv == CKR_SLOT_ID_INVALID:
        exc = SlotIDInvalid()
    elif rv == CKR_SAVED_STATE_INVALID:
        exc = SavedStateInvalid()
    elif rv == CKR_STATE_UNSAVEABLE:
        exc = StateUnsaveable()
    elif rv == CKR_TOKEN_NOT_PRESENT:
        exc = TokenNotPresent()
    elif rv == CKR_TOKEN_NOT_RECOGNIZED:
        exc = TokenNotRecognised()
    elif rv == CKR_TOKEN_WRITE_PROTECTED:
        exc = TokenWriteProtected()
    elif rv == CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        exc = UnwrappingKeyHandleInvalid()
    elif rv == CKR_UNWRAPPING_KEY_SIZE_RANGE:
        exc = UnwrappingKeySizeRange()
    elif rv == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        exc = UnwrappingKeyTypeInconsistent()
    elif rv == CKR_USER_NOT_LOGGED_IN:
        exc = UserNotLoggedIn()
    elif rv == CKR_USER_ALREADY_LOGGED_IN:
        exc = UserAlreadyLoggedIn()
    elif rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
        exc = AnotherUserAlreadyLoggedIn()
    elif rv == CKR_USER_PIN_NOT_INITIALIZED:
        exc = UserPinNotInitialized()
    elif rv == CKR_USER_TOO_MANY_TYPES:
        exc = UserTooManyTypes()
    elif rv == CKR_USER_TYPE_INVALID:
        exc = UserTypeInvalid()
    elif rv == CKR_WRAPPED_KEY_INVALID:
        exc = WrappedKeyInvalid()
    elif rv == CKR_WRAPPED_KEY_LEN_RANGE:
        exc = WrappedKeyLenRange()
    elif rv == CKR_WRAPPING_KEY_HANDLE_INVALID:
        exc = WrappingKeyHandleInvalid()
    elif rv == CKR_WRAPPING_KEY_SIZE_RANGE:
        exc = WrappingKeySizeRange()
    elif rv == CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        exc = WrappingKeyTypeInconsistent()
    elif rv == CKR_ACTION_PROHIBITED:
        exc = ActionProhibited()
    elif rv == CKR_CURVE_NOT_SUPPORTED:
        exc = CurveNotSupported()
    elif rv == CKR_KEY_FUNCTION_NOT_PERMITTED:
        exc = KeyFunctionNotPermitted()
    elif rv == CKR_OPERATION_NOT_VALIDATED:
        exc = OperationNotValidated()
    elif rv == CKR_TOKEN_NOT_INITIALIZED:
        exc = TokenNotInitialized()
    elif rv == CKR_PARAMETER_SET_NOT_SUPPORTED:
        exc = ParameterSetNotSupported()
    else:
        exc = PKCS11Error("Unmapped error code %s" % hex(rv))
    return exc
