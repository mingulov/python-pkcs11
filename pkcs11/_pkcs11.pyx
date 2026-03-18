#cython: language_level=3
#coverage#cython: linetrace=True
"""
High-level Python PKCS#11 Wrapper.

Most class here inherit from pkcs11.types, which provides easier introspection
for Sphinx/Jedi/etc, as this module is not importable without having the
library loaded.
"""

from __future__ import (absolute_import, unicode_literals,
                        print_function, division)

from threading import RLock

from cpython.bytearray cimport PyByteArray_AS_STRING, PyByteArray_GET_SIZE
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.string cimport memcpy, memset, strlen

from pkcs11 import types
from pkcs11.attributes import AttributeMapper
from pkcs11.defaults import *
from pkcs11.exceptions import *
from pkcs11.constants import *
from pkcs11.mechanisms import *
from pkcs11.types import (
    _CK_UTF8CHAR_to_str,
    _CK_VERSION_to_tuple,
    _CK_MECHANISM_TYPE_to_enum,
    PROTECTED_AUTH,
)


cdef class lib(HasFuncList)

cdef class HasFuncList:
    cdef CK_FUNCTION_LIST *funclist
    cdef CK_FUNCTION_LIST_3_0 *funclist3   # NULL if module is v2.40 only
    cdef CK_FUNCTION_LIST_3_2 *funclist32  # NULL if module is not v3.2+

    def __cinit__(self, *args, **kwargs):
        self.funclist = NULL
        self.funclist3 = NULL
        self.funclist32 = NULL


cdef assertRV(rv) with gil:
    """Check for an acceptable RV value or thrown an exception."""
    if rv == CKR_OK:
        return
    raise map_rv_to_error(rv)


cdef bytes _coerce_pin_bytes(object pin):
    if isinstance(pin, bytes):
        return <bytes> pin
    return pin.encode('utf-8')


cdef bytes _coerce_utf8_bytes(object value):
    if isinstance(value, bytes):
        return <bytes> value
    return value.encode('utf-8')


cdef bytes _coerce_message_bytes(object value, object name):
    if isinstance(value, bytes):
        return <bytes> value
    if isinstance(value, str):
        return value.encode('utf-8')

    try:
        return bytes(value)
    except TypeError as ex:
        raise ArgumentsBad(f"`{name}` must be bytes-like or str.") from ex


cdef bytes _coerce_operation_name(object value):
    if isinstance(value, bytes):
        return <bytes> value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise ArgumentsBad("`operation` must be str or bytes.")


cdef inline CK_BYTE *_bytearray_ptr(bytearray value):
    if PyByteArray_GET_SIZE(value) == 0:
        return NULL
    return <CK_BYTE *> PyByteArray_AS_STRING(value)


cdef inline CK_ULONG _bytearray_len(bytearray value):
    return <CK_ULONG> PyByteArray_GET_SIZE(value)


cdef inline bint _attribute_is_template(CK_ATTRIBUTE_TYPE attr_type):
    return (
        attr_type == <CK_ATTRIBUTE_TYPE> Attribute.WRAP_TEMPLATE
        or attr_type == <CK_ATTRIBUTE_TYPE> Attribute.UNWRAP_TEMPLATE
        or attr_type == <CK_ATTRIBUTE_TYPE> Attribute.DERIVE_TEMPLATE
        or attr_type == <CK_ATTRIBUTE_TYPE> Attribute.ENCAPSULATE_TEMPLATE
        or attr_type == <CK_ATTRIBUTE_TYPE> Attribute.DECAPSULATE_TEMPLATE
    )


cdef inline void _zero_attribute_array(CK_ATTRIBUTE *data, CK_ULONG count):
    if count > 0:
        memset(data, 0, count * sizeof(CK_ATTRIBUTE))


cdef inline CK_OBJECT_HANDLE _coerce_object_handle(object value):
    if hasattr(value, "handle"):
        return <CK_OBJECT_HANDLE> value.handle
    return <CK_OBJECT_HANDLE> int(value)


cdef class AttributeList:
    """
    A list of CK_ATTRIBUTE objects.
    """

    cdef CK_ATTRIBUTE *data
    """CK_ATTRIBUTE * representation of the data."""
    cdef CK_ULONG count
    """Length of `data`."""
    cdef list child_values

    def __cinit__(self, attrs):
        self.data = NULL
        self.count = 0
        self.child_values = []

    @staticmethod
    cdef AttributeList allocate(CK_ULONG count):
        cdef AttributeList lst = AttributeList.__new__(AttributeList, ())
        lst.count = count
        lst.child_values = [None] * count
        if count == 0:
            lst.data = NULL
            return lst

        lst.data = <CK_ATTRIBUTE *> PyMem_Malloc(count * sizeof(CK_ATTRIBUTE))
        if lst.data is NULL:
            raise MemoryError()
        _zero_attribute_array(lst.data, count)
        return lst

    @staticmethod
    cdef AttributeList from_owned_pointer(CK_ATTRIBUTE * data, CK_ULONG count):
        cdef AttributeList lst = AttributeList.__new__(AttributeList, ())
        lst.data = data
        lst.count = count
        lst.child_values = [None] * count
        return lst

    @staticmethod
    cdef AttributeList from_template(dict template, object attribute_mapper):
        cdef AttributeList lst = AttributeList.allocate(<CK_ULONG> len(template))
        cdef CK_ULONG count = lst.count
        cdef bytes value_bytes
        cdef CK_CHAR * value_ptr
        cdef Py_ssize_t value_len
        cdef object packed_value
        cdef AttributeList child
        for index, (key, value) in enumerate(template.items()):
            lst.data[index].type = key
            packed_value = attribute_mapper.pack_attribute(key, value)
            if _attribute_is_template(<CK_ATTRIBUTE_TYPE> key):
                child = AttributeList.from_template(dict(packed_value), attribute_mapper)
                lst.child_values[index] = child
                lst.data[index].pValue = <void *> child.data
                lst.data[index].ulValueLen = child.count * sizeof(CK_ATTRIBUTE)
                continue

            value_bytes = packed_value
            value_len = len(value_bytes)
            if value_len == 0:
                lst.data[index].pValue = NULL
                lst.data[index].ulValueLen = 0
                continue
            # copy the result into a pointer that we manage, for consistency with the other init method
            value_ptr = <CK_CHAR *> PyMem_Malloc(value_len)
            if value_ptr is NULL:
                raise MemoryError()
            memcpy(value_ptr, <CK_CHAR *> value_bytes, <size_t> value_len)
            lst.data[index].pValue = <CK_CHAR *> value_ptr
            lst.data[index].ulValueLen = <CK_ULONG> value_len

        return lst

    def __init__(self, attrs):
        raise TypeError

    cdef at_index(self, CK_ULONG index, object attribute_mapper):
        cdef CK_ATTRIBUTE * attr
        cdef AttributeList child
        if index < self.count:
            attr = &self.data[index]
            if self.child_values and self.child_values[index] is not None:
                child = <AttributeList> self.child_values[index]
                return attribute_mapper.unpack_attributes(attr.type, child.as_dict(attribute_mapper))
            return attribute_mapper.unpack_attributes(
                attr.type,
                PyBytes_FromStringAndSize(<char *> attr.pValue, <Py_ssize_t> attr.ulValueLen)
            )
        else:
            raise IndexError()

    def as_dict(self, attribute_mapper):
        cdef CK_ATTRIBUTE * attr
        result = {}
        for index in range(self.count):
            attr = &self.data[index]
            result[attr.type] = self.at_index(index, attribute_mapper)
        return result

    def get(self, item, attribute_mapper):
        cdef CK_ULONG index = 0
        cdef CK_ATTRIBUTE_TYPE key = item
        for index in range(self.count):
            if self.data[index].type == key:
                return self.at_index(index, attribute_mapper)
        raise KeyError(item)

    def __dealloc__(self):
        cdef CK_ULONG index = 0
        if self.data is not NULL:
            for index in range(self.count):
                if not self.child_values or self.child_values[index] is None:
                    PyMem_Free(self.data[index].pValue)
            PyMem_Free(self.data)


cdef bint _allocate_nested_attribute_buffers(AttributeList attrs) with gil:
    cdef CK_ULONG index
    cdef CK_ATTRIBUTE *attr
    cdef AttributeList child
    cdef CK_ULONG nested_count
    cdef bint changed = False

    for index in range(attrs.count):
        attr = &attrs.data[index]
        if attrs.child_values[index] is not None:
            child = <AttributeList> attrs.child_values[index]
            if _allocate_nested_attribute_buffers(child):
                changed = True
            continue

        if _attribute_is_template(attr.type):
            if attr.ulValueLen == CK_UNAVAILABLE_INFORMATION:
                continue
            nested_count = <CK_ULONG> (attr.ulValueLen / sizeof(CK_ATTRIBUTE))
            child = AttributeList.allocate(nested_count)
            attrs.child_values[index] = child
            attr.pValue = <void *> child.data
            attr.ulValueLen = nested_count * sizeof(CK_ATTRIBUTE)
            changed = True
            continue

        if attr.pValue is NULL and attr.ulValueLen != 0 and attr.ulValueLen != CK_UNAVAILABLE_INFORMATION:
            attr.pValue = PyMem_Malloc(attr.ulValueLen)
            if attr.pValue is NULL:
                raise MemoryError()
            changed = True

    return changed


cdef void _ensure_attribute_values_ready(AttributeList attrs) with gil:
    cdef CK_ULONG index
    cdef CK_ATTRIBUTE *attr
    cdef AttributeList child

    for index in range(attrs.count):
        attr = &attrs.data[index]
        if attrs.child_values[index] is not None:
            child = <AttributeList> attrs.child_values[index]
            _ensure_attribute_values_ready(child)
            continue

        if attr.ulValueLen == CK_UNAVAILABLE_INFORMATION:
            raise FunctionFailed()
        if attr.ulValueLen != 0 and attr.pValue is NULL:
            raise FunctionFailed()


cdef class MechanismWithParam:
    """
    Python wrapper for a Mechanism with its parameter
    """

    cdef CK_MECHANISM *data
    """The mechanism."""
    cdef void *param
    """Reference to a pointer we might need to free."""
    cdef object _python_param
    cdef list _extra_allocations
    """
    Hold a reference to the original parameter object so it doesn't get
    GC'd before this one.
    """

    def __cinit__(self, *args):
        self.data = <CK_MECHANISM *> PyMem_Malloc(sizeof(CK_MECHANISM))
        self.param = NULL
        self._python_param = None
        self._extra_allocations = []

    def __init__(self, key_type, mapping, mechanism=None, param=None):
        self._python_param = param
        if mechanism is None:
            try:
                mechanism = mapping[key_type]
            except KeyError:
                raise ArgumentsBad("No default mechanism for this key type. "
                                    "Please specify `mechanism`.")

        if not isinstance(mechanism, Mechanism):
            raise ArgumentsBad("`mechanism` must be a Mechanism.")
        # Possible types of parameters we might need to allocate
        # These are used to make assigning to the object we malloc() easier
        # FIXME: is there a better way to do this?
        cdef CK_RSA_PKCS_OAEP_PARAMS *oaep_params
        cdef CK_RSA_PKCS_PSS_PARAMS *pss_params
        cdef CK_EDDSA_PARAMS *eddsa_params
        cdef CK_ECDH1_DERIVE_PARAMS *ecdh1_params
        cdef CK_KEY_DERIVATION_STRING_DATA *aes_ecb_params
        cdef CK_AES_CBC_ENCRYPT_DATA_PARAMS *aes_cbc_params
        cdef CK_GCM_PARAMS *gcm_params
        cdef CK_GCM_MESSAGE_PARAMS *gcm_message_params
        cdef CK_GCM_WRAP_PARAMS *gcm_wrap_params
        cdef CK_AES_CTR_PARAMS *aes_ctr_params
        cdef CK_CCM_PARAMS *ccm_params
        cdef CK_CCM_MESSAGE_PARAMS *ccm_message_params
        cdef CK_CCM_WRAP_PARAMS *ccm_wrap_params
        cdef CK_SALSA20_CHACHA20_POLY1305_PARAMS *chacha_poly_params
        cdef CK_HKDF_PARAMS *hkdf_params
        cdef CK_PKCS5_PBKD2_PARAMS2 *pbkd2_params
        cdef CK_PRF_DATA_PARAM *sp800_data_params
        cdef CK_SP800_108_COUNTER_FORMAT *sp800_counter_params
        cdef CK_SP800_108_DKM_LENGTH_FORMAT *sp800_dkm_params
        cdef CK_SP800_108_KDF_PARAMS *sp800_kdf_params
        cdef CK_SP800_108_FEEDBACK_KDF_PARAMS *sp800_feedback_params
        cdef CK_OBJECT_HANDLE *sp800_handle
        cdef CK_XEDDSA_PARAMS *xeddsa_params
        cdef CK_ECDH_AES_KEY_WRAP_PARAMS *ecdh_aes_params
        cdef CK_RSA_AES_KEY_WRAP_PARAMS *rsa_aes_params
        cdef CK_CHACHA20_PARAMS *chacha20_params
        cdef CK_SALSA20_PARAMS *salsa20_params
        cdef CK_DES_CBC_ENCRYPT_DATA_PARAMS *des_cbc_params
        cdef object sp800_entry
        cdef bytes data_bytes
        cdef bytes iv_bytes
        cdef Py_ssize_t sp800_index
        cdef bytearray iv_buffer
        cdef bytearray tag_buffer
        cdef bytearray nonce_buffer
        cdef bytearray mac_buffer

        # Unpack mechanism parameters

        if mechanism in (Mechanism.AES_ECB_ENCRYPT_DATA,
                         Mechanism.DES_ECB_ENCRYPT_DATA,
                         Mechanism.DES3_ECB_ENCRYPT_DATA):
            paramlen = sizeof(CK_KEY_DERIVATION_STRING_DATA)
            self.param = aes_ecb_params = \
                <CK_KEY_DERIVATION_STRING_DATA *> PyMem_Malloc(paramlen)
            aes_ecb_params.pData = <CK_BYTE *> param
            aes_ecb_params.ulLen = <CK_ULONG> len(param)

        elif isinstance(param, bytes):
            # Note: this is an escape hatch of sorts that can be used to provide parameters for
            #  unsupported algorithms in raw binary form.
            # We include it at this point in the chain for forwards compatibility reasons:
            #  if at a later point, "first class" support for the unsupported mechanism is added
            #  to the library, existing code that used this "raw mode" workaround will keep working
            #  because this branch takes priority.
            #
            # The parameter convention for AES_ECB_ENCRYPT_DATA predates this ordering decision,
            #  so it takes precedence over this branch for backwards compatibility.
            self.data.pParameter = <CK_BYTE *> param
            paramlen =  len(param)

        elif mechanism == Mechanism.RSA_PKCS_OAEP:
            paramlen = sizeof(CK_RSA_PKCS_OAEP_PARAMS)
            self.param = oaep_params = \
                <CK_RSA_PKCS_OAEP_PARAMS *> PyMem_Malloc(paramlen)

            oaep_params.source = CKZ_DATA_SPECIFIED

            if param is None:
                param = DEFAULT_MECHANISM_PARAMS[mechanism]

            (oaep_params.hashAlg, oaep_params.mgf, source_data) = param

            if source_data is None:
                oaep_params.pSourceData = NULL
                oaep_params.ulSourceDataLen = <CK_ULONG> 0
            else:
                oaep_params.pSourceData = <CK_BYTE *> source_data
                oaep_params.ulSourceDataLen = <CK_ULONG> len(source_data)

        elif mechanism in (Mechanism.RSA_PKCS_PSS,
                           Mechanism.SHA1_RSA_PKCS_PSS,
                           Mechanism.SHA224_RSA_PKCS_PSS,
                           Mechanism.SHA256_RSA_PKCS_PSS,
                           Mechanism.SHA384_RSA_PKCS_PSS,
                           Mechanism.SHA512_RSA_PKCS_PSS,
                           Mechanism.SHA3_224_RSA_PKCS_PSS,
                           Mechanism.SHA3_256_RSA_PKCS_PSS,
                           Mechanism.SHA3_384_RSA_PKCS_PSS,
                           Mechanism.SHA3_512_RSA_PKCS_PSS):
            paramlen = sizeof(CK_RSA_PKCS_PSS_PARAMS)
            self.param = pss_params = \
                <CK_RSA_PKCS_PSS_PARAMS *> PyMem_Malloc(paramlen)

            if param is None:
                # All PSS mechanisms have the same defaults
                param = DEFAULT_MECHANISM_PARAMS[Mechanism.RSA_PKCS_PSS]

            (pss_params.hashAlg, pss_params.mgf, pss_params.sLen) = param

        elif mechanism == Mechanism.EDDSA and param is not None:
            paramlen = sizeof(CK_EDDSA_PARAMS)
            self.param = eddsa_params = \
                <CK_EDDSA_PARAMS *> PyMem_Malloc(paramlen)
            (eddsa_params.phFlag, context_data) = param
            if context_data is None:
                eddsa_params.pContextData = NULL
                eddsa_params.ulContextDataLen = 0
            else:
                eddsa_params.pContextData = context_data
                eddsa_params.ulContextDataLen = <CK_ULONG> len(context_data)

        elif mechanism == Mechanism.XEDDSA and param is not None:
            paramlen = sizeof(CK_XEDDSA_PARAMS)
            self.param = xeddsa_params = \
                <CK_XEDDSA_PARAMS *> PyMem_Malloc(paramlen)
            xeddsa_params.hash = <CK_XEDDSA_HASH_TYPE> int(param)

        elif mechanism in (
                Mechanism.ECDH1_DERIVE,
                Mechanism.ECDH1_COFACTOR_DERIVE):
            paramlen = sizeof(CK_ECDH1_DERIVE_PARAMS)
            self.param = ecdh1_params = \
                <CK_ECDH1_DERIVE_PARAMS *> PyMem_Malloc(paramlen)

            (ecdh1_params.kdf, shared_data, public_data) = param

            if shared_data is None:
                ecdh1_params.pSharedData = NULL
                ecdh1_params.ulSharedDataLen = 0
            else:
                ecdh1_params.pSharedData = shared_data
                ecdh1_params.ulSharedDataLen = <CK_ULONG> len(shared_data)

            ecdh1_params.pPublicData = public_data
            ecdh1_params.ulPublicDataLen = <CK_ULONG> len(public_data)

        elif mechanism == Mechanism.AES_CBC_ENCRYPT_DATA:
            paramlen = sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)
            self.param = aes_cbc_params = \
                    <CK_AES_CBC_ENCRYPT_DATA_PARAMS *> PyMem_Malloc(paramlen)
            (iv, data) = param
            aes_cbc_params.iv = iv[:16]
            aes_cbc_params.pData = <CK_BYTE *> data
            aes_cbc_params.length = <CK_ULONG> len(data)

        elif mechanism in (Mechanism.DES_CBC_ENCRYPT_DATA,
                          Mechanism.DES3_CBC_ENCRYPT_DATA):
            paramlen = sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS)
            self.param = des_cbc_params = \
                <CK_DES_CBC_ENCRYPT_DATA_PARAMS *> PyMem_Malloc(paramlen)
            (iv, data) = param
            des_cbc_params.iv = iv[:8]
            des_cbc_params.pData = <CK_BYTE *> data
            des_cbc_params.length = <CK_ULONG> len(data)

        elif mechanism == Mechanism.AES_GCM and isinstance(param, GCMMessageParams):
            paramlen = sizeof(CK_GCM_MESSAGE_PARAMS)
            self.param = gcm_message_params = <CK_GCM_MESSAGE_PARAMS *> PyMem_Malloc(paramlen)
            iv_buffer = param.iv
            tag_buffer = param.tag
            gcm_message_params.pIv = _bytearray_ptr(iv_buffer)
            gcm_message_params.ulIvLen = _bytearray_len(iv_buffer)
            gcm_message_params.ulIvFixedBits = <CK_ULONG> param.iv_fixed_bits
            gcm_message_params.ivGenerator = <CK_GENERATOR_FUNCTION> int(param.iv_generator)
            gcm_message_params.pTag = _bytearray_ptr(tag_buffer)
            gcm_message_params.ulTagBits = <CK_ULONG> param.tag_bits

        elif mechanism == Mechanism.AES_GCM and isinstance(param, GCMWrapParams):
            paramlen = sizeof(CK_GCM_WRAP_PARAMS)
            self.param = gcm_wrap_params = <CK_GCM_WRAP_PARAMS *> PyMem_Malloc(paramlen)
            iv_buffer = param.iv
            gcm_wrap_params.pIv = _bytearray_ptr(iv_buffer)
            gcm_wrap_params.ulIvLen = _bytearray_len(iv_buffer)
            gcm_wrap_params.ulIvFixedBits = <CK_ULONG> param.iv_fixed_bits
            gcm_wrap_params.ivGenerator = <CK_GENERATOR_FUNCTION> int(param.iv_generator)
            if param.aad is not None:
                gcm_wrap_params.pAAD = <CK_BYTE *> param.aad
                gcm_wrap_params.ulAADLen = <CK_ULONG> len(param.aad)
            else:
                gcm_wrap_params.pAAD = NULL
                gcm_wrap_params.ulAADLen = 0
            gcm_wrap_params.ulTagBits = <CK_ULONG> param.tag_bits

        elif mechanism == Mechanism.AES_GCM:
            paramlen = sizeof(CK_GCM_PARAMS)
            if not isinstance(param, GCMParams):
                raise TypeError
            self.param = gcm_params = <CK_GCM_PARAMS *> PyMem_Malloc(paramlen)
            gcm_params.pIv = <CK_BYTE *> param.nonce
            gcm_params.ulIvLen = <CK_ULONG> len(param.nonce)
            gcm_params.ulIvBits = <CK_ULONG> len(param.nonce) * 8
            if param.aad is not None:
                gcm_params.pAAD = <CK_BYTE *> param.aad
                gcm_params.ulAADLen = <CK_ULONG> len(param.aad)
            else:
                gcm_params.pAAD = NULL
                gcm_params.ulAADLen = 0
            gcm_params.ulTagBits = <CK_ULONG> param.tag_bits

        elif mechanism == Mechanism.AES_CTR:
            paramlen = sizeof(CK_AES_CTR_PARAMS)
            self.param = aes_ctr_params = <CK_AES_CTR_PARAMS *> PyMem_Malloc(paramlen)
            # use a wrapper type to not break the forwards compat rule for params specified as `bytes`
            if not isinstance(param, CTRParams):
                raise TypeError
            aes_ctr_params.ulCounterBits = (16 - len(param.nonce)) * 8
            aes_ctr_params.cb = param.nonce + b"\x00" * (15 - len(param.nonce)) + b"\x01"

        elif mechanism == Mechanism.AES_CCM and isinstance(param, CCMMessageParams):
            paramlen = sizeof(CK_CCM_MESSAGE_PARAMS)
            self.param = ccm_message_params = <CK_CCM_MESSAGE_PARAMS *> PyMem_Malloc(paramlen)
            nonce_buffer = param.nonce
            mac_buffer = param.mac
            ccm_message_params.ulDataLen = <CK_ULONG> param.data_len
            ccm_message_params.pNonce = _bytearray_ptr(nonce_buffer)
            ccm_message_params.ulNonceLen = _bytearray_len(nonce_buffer)
            ccm_message_params.ulNonceFixedBits = <CK_ULONG> param.nonce_fixed_bits
            ccm_message_params.nonceGenerator = <CK_GENERATOR_FUNCTION> int(param.nonce_generator)
            ccm_message_params.pMAC = _bytearray_ptr(mac_buffer)
            ccm_message_params.ulMACLen = <CK_ULONG> param.mac_len

        elif mechanism == Mechanism.AES_CCM and isinstance(param, CCMWrapParams):
            paramlen = sizeof(CK_CCM_WRAP_PARAMS)
            self.param = ccm_wrap_params = <CK_CCM_WRAP_PARAMS *> PyMem_Malloc(paramlen)
            nonce_buffer = param.nonce
            ccm_wrap_params.ulDataLen = <CK_ULONG> param.data_len
            ccm_wrap_params.pNonce = _bytearray_ptr(nonce_buffer)
            ccm_wrap_params.ulNonceLen = _bytearray_len(nonce_buffer)
            ccm_wrap_params.ulNonceFixedBits = <CK_ULONG> param.nonce_fixed_bits
            ccm_wrap_params.nonceGenerator = <CK_GENERATOR_FUNCTION> int(param.nonce_generator)
            if param.aad is not None and len(param.aad) > 0:
                ccm_wrap_params.pAAD = <CK_BYTE *> param.aad
                ccm_wrap_params.ulAADLen = <CK_ULONG> len(param.aad)
            else:
                ccm_wrap_params.pAAD = NULL
                ccm_wrap_params.ulAADLen = 0
            ccm_wrap_params.ulMACLen = <CK_ULONG> param.mac_len

        elif mechanism == Mechanism.AES_CCM:
            paramlen = sizeof(CK_CCM_PARAMS)
            self.param = ccm_params = <CK_CCM_PARAMS *> PyMem_Malloc(paramlen)
            # CCM params: (data_len, nonce, aad, mac_length) or dict
            if isinstance(param, dict):
                ccm_params.ulDataLen = <CK_ULONG> param.get('data_len', 0)
                nonce = param.get('nonce', b'')
                aad = param.get('associated_data', param.get('aad', b''))
                ccm_params.ulMACLen = <CK_ULONG> param.get('mac_length', 16)
            else:
                (data_len, nonce, aad, mac_length) = param
                ccm_params.ulDataLen = <CK_ULONG> data_len
                ccm_params.ulMACLen = <CK_ULONG> mac_length
            ccm_params.pNonce = <CK_BYTE *> nonce
            ccm_params.ulNonceLen = <CK_ULONG> len(nonce)
            if aad is not None and len(aad) > 0:
                ccm_params.pAAD = <CK_BYTE *> aad
                ccm_params.ulAADLen = <CK_ULONG> len(aad)
            else:
                ccm_params.pAAD = NULL
                ccm_params.ulAADLen = 0

        elif mechanism in (Mechanism.CHACHA20_POLY1305,
                           Mechanism.SALSA20_POLY1305):
            paramlen = sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS)
            self.param = chacha_poly_params = \
                <CK_SALSA20_CHACHA20_POLY1305_PARAMS *> PyMem_Malloc(paramlen)
            # Params: (nonce, aad) tuple
            (nonce, aad) = param
            chacha_poly_params.pNonce = <CK_BYTE *> nonce
            chacha_poly_params.ulNonceLen = <CK_ULONG> len(nonce)
            if aad is not None and len(aad) > 0:
                chacha_poly_params.pAAD = <CK_BYTE *> aad
                chacha_poly_params.ulAADLen = <CK_ULONG> len(aad)
            else:
                chacha_poly_params.pAAD = NULL
                chacha_poly_params.ulAADLen = 0

        elif mechanism in (Mechanism.HKDF_DERIVE,
                           Mechanism.HKDF_DATA,
                           Mechanism.HKDF_KEY_GEN):
            paramlen = sizeof(CK_HKDF_PARAMS)
            self.param = hkdf_params = <CK_HKDF_PARAMS *> PyMem_Malloc(paramlen)
            # HKDF params: (hash_mechanism, salt, info) or dict
            # bExtract=True, bExpand=True for standard extract-then-expand
            if isinstance(param, dict):
                hkdf_params.bExtract = <CK_BBOOL> param.get('extract', True)
                hkdf_params.bExpand = <CK_BBOOL> param.get('expand', True)
                hkdf_params.prfHashMechanism = <CK_MECHANISM_TYPE> param.get('hash', param.get('prf_hash', 0))
                salt = param.get('salt', b'')
                info = param.get('info', b'')
            else:
                (prf_hash, salt, info) = param
                hkdf_params.bExtract = <CK_BBOOL> True
                hkdf_params.bExpand = <CK_BBOOL> True
                hkdf_params.prfHashMechanism = <CK_MECHANISM_TYPE> prf_hash

            if salt is not None and len(salt) > 0:
                hkdf_params.ulSaltType = CKF_HKDF_SALT_DATA
                hkdf_params.pSalt = <CK_BYTE *> salt
                hkdf_params.ulSaltLen = <CK_ULONG> len(salt)
            else:
                hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL
                hkdf_params.pSalt = NULL
                hkdf_params.ulSaltLen = 0
            hkdf_params.hSaltKey = 0  # Not using key-based salt

            if info is not None and len(info) > 0:
                hkdf_params.pInfo = <CK_BYTE *> info
                hkdf_params.ulInfoLen = <CK_ULONG> len(info)
            else:
                hkdf_params.pInfo = NULL
                hkdf_params.ulInfoLen = 0

        elif mechanism == Mechanism.PKCS5_PBKD2:
            paramlen = sizeof(CK_PKCS5_PBKD2_PARAMS2)
            self.param = pbkd2_params = \
                <CK_PKCS5_PBKD2_PARAMS2 *> PyMem_Malloc(paramlen)
            # Accepts a dict with keys: password, salt, iterations, prf
            # prf is a CKP_PKCS5_PBKD2_HMAC_* constant (int)
            if isinstance(param, dict):
                password = param['password']
                if isinstance(password, str):
                    password = password.encode('utf-8')
                salt = param.get('salt', b'')
                pbkd2_params.iterations = <CK_ULONG> param.get('iterations', 1000)
                pbkd2_params.prf = <CK_ULONG> param.get('prf', CKP_PKCS5_PBKD2_HMAC_SHA256)
            else:
                (password, salt, iterations, prf) = param
                if isinstance(password, str):
                    password = password.encode('utf-8')
                pbkd2_params.iterations = <CK_ULONG> iterations
                pbkd2_params.prf = <CK_ULONG> prf
            pbkd2_params.saltSource = CKZ_SALT_SPECIFIED
            pbkd2_params.pSaltSourceData = <CK_BYTE *> salt
            pbkd2_params.ulSaltSourceDataLen = <CK_ULONG> len(salt)
            pbkd2_params.pPrfData = NULL
            pbkd2_params.ulPrfDataLen = 0
            pbkd2_params.pPassword = <CK_UTF8CHAR *> password
            pbkd2_params.ulPasswordLen = <CK_ULONG> len(password)

        elif mechanism in (Mechanism.SP800_108_COUNTER_KDF,
                           Mechanism.SP800_108_DOUBLE_PIPELINE_KDF):
            if not isinstance(param, SP800108KDFParams):
                raise ArgumentsBad(
                    "SP800-108 counter/double-pipeline KDF parameters must use SP800108KDFParams."
                )
            paramlen = sizeof(CK_SP800_108_KDF_PARAMS)
            self.param = sp800_kdf_params = <CK_SP800_108_KDF_PARAMS *> PyMem_Malloc(paramlen)
            sp800_kdf_params.prfType = <CK_SP800_108_PRF_TYPE> int(param.prf_type)
            sp800_kdf_params.ulAdditionalDerivedKeys = 0
            sp800_kdf_params.pAdditionalDerivedKeys = NULL
            sp800_kdf_params.ulNumberOfDataParams = <CK_ULONG> len(param.data_params)
            if sp800_kdf_params.ulNumberOfDataParams == 0:
                sp800_kdf_params.pDataParams = NULL
            else:
                sp800_data_params = <CK_PRF_DATA_PARAM *> PyMem_Malloc(
                    sp800_kdf_params.ulNumberOfDataParams * sizeof(CK_PRF_DATA_PARAM)
                )
                if sp800_data_params is NULL:
                    raise MemoryError()
                self._extra_allocations.append(<size_t> sp800_data_params)
                memset(
                    sp800_data_params,
                    0,
                    sp800_kdf_params.ulNumberOfDataParams * sizeof(CK_PRF_DATA_PARAM),
                )
                sp800_kdf_params.pDataParams = sp800_data_params
                for sp800_index, sp800_entry in enumerate(param.data_params):
                    sp800_data_params[sp800_index].type = <CK_PRF_DATA_TYPE> int(sp800_entry.data_type)
                    if sp800_data_params[sp800_index].type in (
                        CK_SP800_108_ITERATION_VARIABLE,
                        CK_SP800_108_OPTIONAL_COUNTER,
                        CK_SP800_108_COUNTER,
                    ):
                        if not isinstance(sp800_entry.value, SP800108CounterFormat):
                            raise ArgumentsBad(
                                "SP800-108 counter data parameters require SP800108CounterFormat."
                            )
                        sp800_counter_params = <CK_SP800_108_COUNTER_FORMAT *> PyMem_Malloc(
                            sizeof(CK_SP800_108_COUNTER_FORMAT)
                        )
                        if sp800_counter_params is NULL:
                            raise MemoryError()
                        self._extra_allocations.append(<size_t> sp800_counter_params)
                        sp800_counter_params.bLittleEndian = <CK_BBOOL> sp800_entry.value.little_endian
                        sp800_counter_params.ulWidthInBits = <CK_ULONG> sp800_entry.value.width_in_bits
                        sp800_data_params[sp800_index].pValue = sp800_counter_params
                        sp800_data_params[sp800_index].ulValueLen = sizeof(CK_SP800_108_COUNTER_FORMAT)
                    elif sp800_data_params[sp800_index].type == CK_SP800_108_DKM_LENGTH:
                        if not isinstance(sp800_entry.value, SP800108DKMLengthFormat):
                            raise ArgumentsBad(
                                "SP800-108 DKM-length data parameters require SP800108DKMLengthFormat."
                            )
                        sp800_dkm_params = <CK_SP800_108_DKM_LENGTH_FORMAT *> PyMem_Malloc(
                            sizeof(CK_SP800_108_DKM_LENGTH_FORMAT)
                        )
                        if sp800_dkm_params is NULL:
                            raise MemoryError()
                        self._extra_allocations.append(<size_t> sp800_dkm_params)
                        sp800_dkm_params.dkmLengthMethod = <CK_SP800_108_DKM_LENGTH_METHOD> int(
                            sp800_entry.value.method
                        )
                        sp800_dkm_params.bLittleEndian = <CK_BBOOL> sp800_entry.value.little_endian
                        sp800_dkm_params.ulWidthInBits = <CK_ULONG> sp800_entry.value.width_in_bits
                        sp800_data_params[sp800_index].pValue = sp800_dkm_params
                        sp800_data_params[sp800_index].ulValueLen = sizeof(
                            CK_SP800_108_DKM_LENGTH_FORMAT
                        )
                    elif sp800_data_params[sp800_index].type == CK_SP800_108_BYTE_ARRAY:
                        data_bytes = _coerce_message_bytes(sp800_entry.value, "SP800-108 byte-array value")
                        sp800_entry.value = data_bytes
                        sp800_data_params[sp800_index].pValue = <CK_BYTE *> data_bytes
                        sp800_data_params[sp800_index].ulValueLen = <CK_ULONG> len(data_bytes)
                    elif sp800_data_params[sp800_index].type == CK_SP800_108_KEY_HANDLE:
                        sp800_handle = <CK_OBJECT_HANDLE *> PyMem_Malloc(sizeof(CK_OBJECT_HANDLE))
                        if sp800_handle is NULL:
                            raise MemoryError()
                        self._extra_allocations.append(<size_t> sp800_handle)
                        sp800_handle[0] = _coerce_object_handle(sp800_entry.value)
                        sp800_data_params[sp800_index].pValue = sp800_handle
                        sp800_data_params[sp800_index].ulValueLen = sizeof(CK_OBJECT_HANDLE)
                    else:
                        raise ArgumentsBad("Unsupported SP800-108 data parameter type.")

        elif mechanism == Mechanism.SP800_108_FEEDBACK_KDF:
            if not isinstance(param, SP800108FeedbackKDFParams):
                raise ArgumentsBad("SP800-108 feedback KDF parameters must use SP800108FeedbackKDFParams.")
            paramlen = sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS)
            self.param = sp800_feedback_params = <CK_SP800_108_FEEDBACK_KDF_PARAMS *> PyMem_Malloc(paramlen)
            sp800_feedback_params.prfType = <CK_SP800_108_PRF_TYPE> int(param.prf_type)
            sp800_feedback_params.ulAdditionalDerivedKeys = 0
            sp800_feedback_params.pAdditionalDerivedKeys = NULL
            iv_bytes = param.iv
            if iv_bytes:
                sp800_feedback_params.pIV = <CK_BYTE *> iv_bytes
                sp800_feedback_params.ulIVLen = <CK_ULONG> len(iv_bytes)
            else:
                sp800_feedback_params.pIV = NULL
                sp800_feedback_params.ulIVLen = 0
            sp800_feedback_params.ulNumberOfDataParams = <CK_ULONG> len(param.data_params)
            if sp800_feedback_params.ulNumberOfDataParams == 0:
                sp800_feedback_params.pDataParams = NULL
            else:
                sp800_data_params = <CK_PRF_DATA_PARAM *> PyMem_Malloc(
                    sp800_feedback_params.ulNumberOfDataParams * sizeof(CK_PRF_DATA_PARAM)
                )
                if sp800_data_params is NULL:
                    raise MemoryError()
                self._extra_allocations.append(<size_t> sp800_data_params)
                memset(
                    sp800_data_params,
                    0,
                    sp800_feedback_params.ulNumberOfDataParams * sizeof(CK_PRF_DATA_PARAM),
                )
                sp800_feedback_params.pDataParams = sp800_data_params
                for sp800_index, sp800_entry in enumerate(param.data_params):
                    sp800_data_params[sp800_index].type = <CK_PRF_DATA_TYPE> int(sp800_entry.data_type)
                    if sp800_data_params[sp800_index].type in (
                        CK_SP800_108_ITERATION_VARIABLE,
                        CK_SP800_108_OPTIONAL_COUNTER,
                        CK_SP800_108_COUNTER,
                    ):
                        if not isinstance(sp800_entry.value, SP800108CounterFormat):
                            raise ArgumentsBad(
                                "SP800-108 counter data parameters require SP800108CounterFormat."
                            )
                        sp800_counter_params = <CK_SP800_108_COUNTER_FORMAT *> PyMem_Malloc(
                            sizeof(CK_SP800_108_COUNTER_FORMAT)
                        )
                        if sp800_counter_params is NULL:
                            raise MemoryError()
                        self._extra_allocations.append(<size_t> sp800_counter_params)
                        sp800_counter_params.bLittleEndian = <CK_BBOOL> sp800_entry.value.little_endian
                        sp800_counter_params.ulWidthInBits = <CK_ULONG> sp800_entry.value.width_in_bits
                        sp800_data_params[sp800_index].pValue = sp800_counter_params
                        sp800_data_params[sp800_index].ulValueLen = sizeof(CK_SP800_108_COUNTER_FORMAT)
                    elif sp800_data_params[sp800_index].type == CK_SP800_108_DKM_LENGTH:
                        if not isinstance(sp800_entry.value, SP800108DKMLengthFormat):
                            raise ArgumentsBad(
                                "SP800-108 DKM-length data parameters require SP800108DKMLengthFormat."
                            )
                        sp800_dkm_params = <CK_SP800_108_DKM_LENGTH_FORMAT *> PyMem_Malloc(
                            sizeof(CK_SP800_108_DKM_LENGTH_FORMAT)
                        )
                        if sp800_dkm_params is NULL:
                            raise MemoryError()
                        self._extra_allocations.append(<size_t> sp800_dkm_params)
                        sp800_dkm_params.dkmLengthMethod = <CK_SP800_108_DKM_LENGTH_METHOD> int(
                            sp800_entry.value.method
                        )
                        sp800_dkm_params.bLittleEndian = <CK_BBOOL> sp800_entry.value.little_endian
                        sp800_dkm_params.ulWidthInBits = <CK_ULONG> sp800_entry.value.width_in_bits
                        sp800_data_params[sp800_index].pValue = sp800_dkm_params
                        sp800_data_params[sp800_index].ulValueLen = sizeof(
                            CK_SP800_108_DKM_LENGTH_FORMAT
                        )
                    elif sp800_data_params[sp800_index].type == CK_SP800_108_BYTE_ARRAY:
                        data_bytes = _coerce_message_bytes(sp800_entry.value, "SP800-108 byte-array value")
                        sp800_entry.value = data_bytes
                        sp800_data_params[sp800_index].pValue = <CK_BYTE *> data_bytes
                        sp800_data_params[sp800_index].ulValueLen = <CK_ULONG> len(data_bytes)
                    elif sp800_data_params[sp800_index].type == CK_SP800_108_KEY_HANDLE:
                        sp800_handle = <CK_OBJECT_HANDLE *> PyMem_Malloc(sizeof(CK_OBJECT_HANDLE))
                        if sp800_handle is NULL:
                            raise MemoryError()
                        self._extra_allocations.append(<size_t> sp800_handle)
                        sp800_handle[0] = _coerce_object_handle(sp800_entry.value)
                        sp800_data_params[sp800_index].pValue = sp800_handle
                        sp800_data_params[sp800_index].ulValueLen = sizeof(CK_OBJECT_HANDLE)
                    else:
                        raise ArgumentsBad("Unsupported SP800-108 data parameter type.")

        elif mechanism == Mechanism.ECDH_AES_KEY_WRAP:
            paramlen = sizeof(CK_ECDH_AES_KEY_WRAP_PARAMS)
            self.param = ecdh_aes_params = \
                <CK_ECDH_AES_KEY_WRAP_PARAMS *> PyMem_Malloc(paramlen)
            if isinstance(param, dict):
                ecdh_aes_params.ulAESKeyBits = <CK_ULONG> param.get('aes_key_bits', 256)
                ecdh_aes_params.kdf = <CK_EC_KDF_TYPE> param.get('kdf', 0)
                shared_data = param.get('shared_data', None)
            else:
                (aes_key_bits, kdf, shared_data) = param
                ecdh_aes_params.ulAESKeyBits = <CK_ULONG> aes_key_bits
                ecdh_aes_params.kdf = <CK_EC_KDF_TYPE> kdf
            if shared_data is not None and len(shared_data) > 0:
                ecdh_aes_params.pSharedData = <CK_BYTE *> shared_data
                ecdh_aes_params.ulSharedDataLen = <CK_ULONG> len(shared_data)
            else:
                ecdh_aes_params.pSharedData = NULL
                ecdh_aes_params.ulSharedDataLen = 0

        elif mechanism == Mechanism.RSA_AES_KEY_WRAP:
            # Allocate outer struct + embedded OAEP params as contiguous block
            paramlen = sizeof(CK_RSA_AES_KEY_WRAP_PARAMS) + sizeof(CK_RSA_PKCS_OAEP_PARAMS)
            self.param = rsa_aes_params = \
                <CK_RSA_AES_KEY_WRAP_PARAMS *> PyMem_Malloc(paramlen)
            oaep_params = <CK_RSA_PKCS_OAEP_PARAMS *>(
                <char *>rsa_aes_params + sizeof(CK_RSA_AES_KEY_WRAP_PARAMS))
            rsa_aes_params.pOAEPParams = oaep_params
            if isinstance(param, dict):
                rsa_aes_params.ulAESKeyBits = <CK_ULONG> param.get('aes_key_bits', 256)
                oaep_param = param.get('oaep_params', None)
            else:
                (aes_key_bits, oaep_param) = param
                rsa_aes_params.ulAESKeyBits = <CK_ULONG> aes_key_bits
            if oaep_param is None:
                oaep_param = DEFAULT_MECHANISM_PARAMS[Mechanism.RSA_PKCS_OAEP]
            (oaep_params.hashAlg, oaep_params.mgf, source_data) = oaep_param
            oaep_params.source = 0x00000001  # CKZ_DATA_SPECIFIED
            if source_data is not None:
                oaep_params.pSourceData = <CK_BYTE *> source_data
                oaep_params.ulSourceDataLen = <CK_ULONG> len(source_data)
            else:
                oaep_params.pSourceData = NULL
                oaep_params.ulSourceDataLen = 0

        elif mechanism == Mechanism.CHACHA20:
            paramlen = sizeof(CK_CHACHA20_PARAMS)
            self.param = chacha20_params = \
                <CK_CHACHA20_PARAMS *> PyMem_Malloc(paramlen)
            if isinstance(param, dict):
                block_counter = param.get('block_counter', b'\x00\x00\x00\x00')
                nonce = param['nonce']
            else:
                (block_counter, nonce) = param
            chacha20_params.pBlockCounter = <CK_BYTE *> block_counter
            chacha20_params.blockCounterBits = <CK_ULONG>(len(block_counter) * 8)
            chacha20_params.pNonce = <CK_BYTE *> nonce
            chacha20_params.ulNonceBits = <CK_ULONG>(len(nonce) * 8)

        elif mechanism == Mechanism.SALSA20:
            paramlen = sizeof(CK_SALSA20_PARAMS)
            self.param = salsa20_params = \
                <CK_SALSA20_PARAMS *> PyMem_Malloc(paramlen)
            if isinstance(param, dict):
                block_counter = param.get('block_counter', b'\x00\x00\x00\x00\x00\x00\x00\x00')
                nonce = param['nonce']
            else:
                (block_counter, nonce) = param
            salsa20_params.pBlockCounter = <CK_BYTE *> block_counter
            salsa20_params.pNonce = <CK_BYTE *> nonce
            salsa20_params.ulNonceBits = <CK_ULONG>(len(nonce) * 8)

        elif param is None:
            self.data.pParameter = NULL
            paramlen = 0

        else:
            raise ArgumentsBad("Unexpected argument to mechanism_param")

        self.data.mechanism = mechanism
        self.data.ulParameterLen = <CK_ULONG> paramlen

        if self.param != NULL:
            self.data.pParameter = self.param

    def __dealloc__(self):
        cdef object allocation
        for allocation in self._extra_allocations:
            PyMem_Free(<void *> <size_t> allocation)
        PyMem_Free(self.data)
        PyMem_Free(self.param)


cdef class MessageParameter:
    cdef void *data
    cdef CK_ULONG length
    cdef void *param
    cdef object _python_param

    def __cinit__(self, *args):
        self.data = NULL
        self.length = 0
        self.param = NULL
        self._python_param = None

    def __init__(self, parameter):
        cdef bytes parameter_bytes
        cdef CK_GCM_MESSAGE_PARAMS *gcm_message_params
        cdef CK_CCM_MESSAGE_PARAMS *ccm_message_params
        cdef bytearray iv_buffer
        cdef bytearray tag_buffer
        cdef bytearray nonce_buffer
        cdef bytearray mac_buffer

        if parameter is None:
            return

        if isinstance(parameter, bytes):
            self._python_param = parameter
            self.data = <void *> parameter
            self.length = <CK_ULONG> len(parameter)
            return

        if isinstance(parameter, str):
            parameter_bytes = parameter.encode("utf-8")
            self._python_param = parameter_bytes
            self.data = <void *> parameter_bytes
            self.length = <CK_ULONG> len(parameter_bytes)
            return

        self._python_param = parameter

        if isinstance(parameter, GCMMessageParams):
            self.length = sizeof(CK_GCM_MESSAGE_PARAMS)
            self.param = gcm_message_params = <CK_GCM_MESSAGE_PARAMS *> PyMem_Malloc(self.length)
            iv_buffer = parameter.iv
            tag_buffer = parameter.tag
            gcm_message_params.pIv = _bytearray_ptr(iv_buffer)
            gcm_message_params.ulIvLen = _bytearray_len(iv_buffer)
            gcm_message_params.ulIvFixedBits = <CK_ULONG> parameter.iv_fixed_bits
            gcm_message_params.ivGenerator = <CK_GENERATOR_FUNCTION> int(parameter.iv_generator)
            gcm_message_params.pTag = _bytearray_ptr(tag_buffer)
            gcm_message_params.ulTagBits = <CK_ULONG> parameter.tag_bits
            self.data = self.param
            return

        if isinstance(parameter, CCMMessageParams):
            self.length = sizeof(CK_CCM_MESSAGE_PARAMS)
            self.param = ccm_message_params = <CK_CCM_MESSAGE_PARAMS *> PyMem_Malloc(self.length)
            nonce_buffer = parameter.nonce
            mac_buffer = parameter.mac
            ccm_message_params.ulDataLen = <CK_ULONG> parameter.data_len
            ccm_message_params.pNonce = _bytearray_ptr(nonce_buffer)
            ccm_message_params.ulNonceLen = _bytearray_len(nonce_buffer)
            ccm_message_params.ulNonceFixedBits = <CK_ULONG> parameter.nonce_fixed_bits
            ccm_message_params.nonceGenerator = <CK_GENERATOR_FUNCTION> int(parameter.nonce_generator)
            ccm_message_params.pMAC = _bytearray_ptr(mac_buffer)
            ccm_message_params.ulMACLen = <CK_ULONG> parameter.mac_len
            self.data = self.param
            return

        raise ArgumentsBad("`parameter` must be bytes-like, str, or a supported message parameter helper.")

    def __dealloc__(self):
        PyMem_Free(self.param)


cdef class Slot(HasFuncList, types.Slot):
    """Extend Slot with implementation."""

    cdef readonly CK_SLOT_ID slot_id
    cdef readonly str slot_description
    cdef readonly str manufacturer_id
    cdef CK_FLAGS slot_flags
    cdef CK_VERSION _hw_version
    cdef CK_VERSION _fw_version
    cdef CK_VERSION _cryptoki_version

    @staticmethod
    cdef Slot make(CK_FUNCTION_LIST *funclist, CK_SLOT_ID slot_id, CK_SLOT_INFO info, CK_VERSION cryptoki_version,
                   CK_FUNCTION_LIST_3_0 *funclist3=NULL, CK_FUNCTION_LIST_3_2 *funclist32=NULL):
        description = info.slotDescription[:sizeof(info.slotDescription)]
        manufacturer_id = info.manufacturerID[:sizeof(info.manufacturerID)]

        cdef Slot slot = Slot.__new__(Slot)
        slot.funclist = funclist
        slot.funclist3 = funclist3
        slot.funclist32 = funclist32

        slot.slot_id = slot_id
        slot.slot_description = _CK_UTF8CHAR_to_str(description)
        slot.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturer_id)
        slot._hw_version = info.hardwareVersion
        slot._fw_version = info.firmwareVersion
        slot._cryptoki_version = cryptoki_version
        slot.slot_flags = info.flags
        return slot

    def __init__(self):
        raise TypeError

    @property
    def flags(self):
        """Capabilities of this slot (:class:`SlotFlag`)."""
        return SlotFlag(self.slot_flags)

    @property
    def hardware_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._hw_version)

    @property
    def firmware_version(self):
        """Firmware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._fw_version)

    @property
    def cryptoki_version(self):
        """PKCS#11 (cryptoki) API version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._cryptoki_version)

    def get_token(self):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_TOKEN_INFO info
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetTokenInfo(slot_id, &info)
        assertRV(retval)

        return Token.make(self, info)

    def get_mechanisms(self):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetMechanismList(slot_id, NULL, &count)
        assertRV(retval)

        if count == 0:
            return set()

        cdef CK_MECHANISM_TYPE [:] mechanisms = CK_ULONG_buffer(count)

        with nogil:
            retval = self.funclist.C_GetMechanismList(slot_id, &mechanisms[0], &count)
        assertRV(retval)

        return set(map(_CK_MECHANISM_TYPE_to_enum, mechanisms))

    def get_mechanism_info(self, mechanism):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_MECHANISM_TYPE mech_type = mechanism
        cdef CK_MECHANISM_INFO info
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetMechanismInfo(slot_id, mech_type, &info)
        assertRV(retval)

        return types.MechanismInfo(self, mechanism, **info)

    def init_token(self, label, so_pin):
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_UTF8CHAR *label_data
        cdef bytes pin = _coerce_pin_bytes(so_pin)
        cdef bytes label_bytes
        cdef CK_RV retval

        if isinstance(label, bytes):
            label_bytes = <bytes> label
        else:
            label_bytes = label.encode('utf-8')

        if len(label_bytes) > 32:
            raise ArgumentsBad("`label` must be 32 bytes or fewer")

        label_bytes = label_bytes.ljust(32, b' ')
        pin_data = pin
        pin_length = <CK_ULONG> len(pin)
        label_data = label_bytes

        with nogil:
            retval = self.funclist.C_InitToken(self.slot_id, pin_data, pin_length, label_data)
        assertRV(retval)

    def _identity(self):
        return Slot.__name__, self.slot_id

    def __str__(self):
        return "\n".join(
            (
                "Slot Description: %s" % self.slot_description,
                "Manufacturer ID: %s" % self.manufacturer_id,
                "Hardware Version: %s.%s" % self.hardware_version,
                "Firmware Version: %s.%s" % self.firmware_version,
                "Flags: %s" % self.flags,
            )
        )

    def __repr__(self):
        return "<{klass} (slotID={slot_id} flags={flags})>".format(
            klass=type(self).__name__, slot_id=self.slot_id, flags=str(self.flags)
        )


cdef class Token(HasFuncList, types.Token):
    """Extend Token with implementation."""

    cdef readonly Slot slot
    cdef readonly str label
    cdef readonly bytes serial
    cdef readonly str manufacturer_id
    cdef readonly str model
    cdef CK_FLAGS token_flags
    cdef CK_VERSION _hw_version
    cdef CK_VERSION _fw_version

    @staticmethod
    cdef Token make(Slot slot, CK_TOKEN_INFO info):
        label = info.label[:sizeof(info.label)]
        serial_number = info.serialNumber[:sizeof(info.serialNumber)]
        model = info.model[:sizeof(info.model)]
        manufacturer_id = info.manufacturerID[:sizeof(info.manufacturerID)]

        cdef Token token = Token.__new__(Token)
        token.funclist = slot.funclist
        token.funclist3 = slot.funclist3
        token.funclist32 = slot.funclist32
        token.slot = slot
        token.label = _CK_UTF8CHAR_to_str(label)
        token.serial = serial_number.rstrip()
        token.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturer_id)
        token.model = _CK_UTF8CHAR_to_str(model)
        token._hw_version = info.hardwareVersion
        token._fw_version = info.firmwareVersion
        token.token_flags = info.flags
        return token

    def __init__(self):
        raise TypeError

    @property
    def flags(self):
        """Capabilities of this token (:class:`TokenFlag`)."""
        return TokenFlag(self.token_flags)

    @property
    def hardware_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._hw_version)

    @property
    def firmware_version(self):
        """Firmware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._fw_version)

    def open(
            self,
            rw=False,
            user_pin=None,
            so_pin=None,
            async_=False,
            username=None,
            user_type=None,
            attribute_mapper=None,
            cancel_strategy=CancelStrategy.DEFAULT
    ):
        cdef CK_SLOT_ID slot_id = self.slot.slot_id
        cdef CK_SESSION_HANDLE handle
        cdef CK_FLAGS flags = CKF_SERIAL_SESSION
        cdef CK_RV retval
        cdef CK_USER_TYPE c_user_type
        cdef Session session

        if rw:
            flags |= CKF_RW_SESSION
        if async_:
            if self.funclist32 == NULL:
                raise NotImplementedError("async_=True requires PKCS#11 v3.2 interface")
            flags |= CKF_ASYNC_SESSION

        if user_pin is not None and so_pin is not None:
            raise ArgumentsBad("Set either `user_pin` or `so_pin`")
        elif user_pin is PROTECTED_AUTH:
            pin = None
            c_user_type = user_type if user_type is not None else CKU_USER
        elif so_pin is PROTECTED_AUTH:
            pin = PROTECTED_AUTH
            c_user_type = CKU_SO
        elif user_pin is not None:
            pin = user_pin
            c_user_type = user_type if user_type is not None else CKU_USER
        elif so_pin is not None:
            pin = so_pin
            c_user_type = CKU_SO
        else:
            pin = None
            c_user_type = CKU_USER_NOBODY

        with nogil:
            retval = self.funclist.C_OpenSession(slot_id, flags, NULL, NULL, &handle)
        assertRV(retval)

        session = Session.make(
            self, handle,
            rw=<bint> rw,
            async_=<bint> async_,
            user_type=CKU_USER_NOBODY,
            mapper=attribute_mapper or AttributeMapper(),
            cancel_strategy=<unsigned int> cancel_strategy
        )

        if c_user_type != CKU_USER_NOBODY or username is not None:
            try:
                session.login(c_user_type, pin=pin, username=username)
            except Exception:
                session.close()
                raise

        return session

    def __str__(self):
        return self.label

    def _identity(self):
        return Token.__name__, self.slot

    def __repr__(self):
        return "<{klass} (label='{label}' serial={serial} flags={flags})>".format(
            klass=type(self).__name__, label=self.label, serial=self.serial, flags=str(self.flags)
        )


cdef class OperationContext:
    cdef Session session
    cdef bint active

    def __cinit__(self, session, *args, **kwargs):
        self.session = session
        self.active = False

    def __init__(self, session):
        pass

    def __enter__(self):
        self.session.operation_lock.acquire()
        self.active = True
        self._initiate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._finalize(silent=False)

    cdef _handle_final_retval(self, CK_RV retval) with gil:
        self.active = False
        self.session.operation_lock.release()
        assertRV(retval)

    cdef _operation_aware_assert(self, CK_RV retval) with gil:
        if retval != CKR_BUFFER_TOO_SMALL and retval != CKR_OK:
            # This is an error that terminated the operation
            # We flag the operation as completed on our end as well.
            # This is useful to track because there's no way to cleanly cancel
            # cryptographic operations in PCKS#11 2.x.
            self._handle_final_retval(retval)

    def _initiate(self):
        raise NotImplementedError

    def _finalize(self, silent=False):
        if self.active:
            self.active = False
            self.session.operation_lock.release()

    def __del__(self):
        self._finalize()


cdef class OperationWithBinaryOutput(OperationContext):

    cdef MechanismWithParam mech

    cdef CK_ULONG buffer_size
    cdef CK_ULONG buffer_data_length
    cdef CK_BYTE [:] output_buf

    @staticmethod
    cdef OperationWithBinaryOutput _setup(
            type cls,
            Session session,
            MechanismWithParam mech,
            CK_ULONG buffer_size
    ) with gil:
        cdef OperationWithBinaryOutput op = cls.__new__(cls, session)
        op.mech = mech
        if buffer_size > 0:
            op.output_buf = CK_BYTE_buffer(buffer_size)
        op.buffer_size = buffer_size
        return op

    cdef resize_buffer(self, CK_ULONG length):
        self.output_buf = CK_BYTE_buffer(length)
        self.buffer_size = length

    cdef inline bytes current_output(self):
        return bytes(self.output_buf[:self.buffer_data_length])

    cdef CK_RV update_resizing_output(
            self,
            OperationUpdateWithResult op_update,
            CK_BYTE *data,
            CK_ULONG data_len,
    ) with gil:

        cdef CK_ULONG length = self.buffer_size
        cdef CK_BYTE *output_buf_loc = &self.output_buf[0]
        cdef CK_RV retval

        with nogil:
            retval = op_update(
                self.session.handle, data, data_len, NULL, &length
            )

        if retval != CKR_OK:
            return retval

        if length > self.buffer_size:
            self.resize_buffer(length)
            output_buf_loc = &self.output_buf[0]

        with nogil:
            retval = op_update(
                self.session.handle, data, data_len, output_buf_loc, &length
            )
        self.buffer_data_length = length
        return retval

    cdef CK_RV execute_resizing_output(self, OperationWithResult op) with gil:

        cdef CK_ULONG length = self.buffer_size
        cdef CK_BYTE *output_buf_loc = &self.output_buf[0]
        cdef CK_RV retval

        with nogil:
            retval = op(self.session.handle, NULL, &length)

        if retval != CKR_OK:
            return retval

        if length > self.buffer_size:
            self.resize_buffer(length)
            output_buf_loc = &self.output_buf[0]


        with nogil:
            retval = op(self.session.handle, output_buf_loc, &length)
        self.buffer_data_length = length
        return retval

    cdef bytes process_fully(
            self,
            OperationUpdateWithResult op,
            CK_BYTE *data,
            CK_ULONG data_len
    ) with gil:
        cdef CK_RV retval = self.update_resizing_output(op, data, data_len)
        self._handle_final_retval(retval)
        return self.current_output()

    cdef bytes update_with_result(
            self, OperationUpdateWithResult op, CK_BYTE *data, CK_ULONG data_len
    ) with gil:
        cdef CK_RV retval = self.update_resizing_output(op, data, data_len)
        self._operation_aware_assert(retval)
        return self.current_output()

    cdef update_no_output(
            self, OperationUpdate op, CK_BYTE *data, CK_ULONG data_len
    ) with gil:
        cdef CK_RV retval
        with nogil:
            retval = op(self.session.handle, data, data_len)
        self._operation_aware_assert(retval)

    cdef bytes finish_with_output(self, OperationWithResult op_final) with gil:
        cdef CK_RV retval = self.execute_resizing_output(op_final)
        self._handle_final_retval(retval)
        return self.current_output()


cdef class SearchIter(OperationContext):
    """Iterate a search for objects on a session."""

    cdef AttributeList template
    cdef CK_ULONG batch_size

    def __init__(self, session, attrs, batch_size):
        cdef Session _session = session
        cdef AttributeList template = _session.make_attribute_list(attrs)
        self.template = template
        self.batch_size = batch_size
        super().__init__(_session)

    def __iter__(self):
        return self

    def _batch_iter(self, results, count):
        for ix in range(count):
            yield make_object(self.session, results[ix])

    def __next__(self):
        """Get the next batch of objects."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj
        cdef CK_ULONG count
        cdef CK_RV retval

        cdef CK_OBJECT_HANDLE [:] results = CK_ULONG_buffer(self.batch_size)

        with nogil:
            retval = self.session.funclist.C_FindObjects(handle, &results[0], self.batch_size, &count)
        assertRV(retval)

        if count == 0:
            self._finalize()
            raise StopIteration()
        else:
            return self._batch_iter(results, count)

    def _initiate(self):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_ATTRIBUTE *attr_data = self.template.data
        cdef CK_ULONG attr_count = self.template.count
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_FindObjectsInit(handle, attr_data, attr_count)
        assertRV(retval)

    def _finalize(self, silent=False):
        """Finish the operation."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_RV retval

        if self.active:
            with nogil:
                retval = self.session.funclist.C_FindObjectsFinal(handle)
            if not silent:
                self._handle_final_retval(retval)


cdef class DigestOperation(OperationWithBinaryOutput):

    @staticmethod
    cdef DigestOperation setup(
            Session session,
            MechanismWithParam mech,
            CK_ULONG buffer_size
    ) with gil:
        cdef DigestOperation op = <DigestOperation> OperationWithBinaryOutput._setup(
            DigestOperation, session, mech, buffer_size
        )
        return op

    def _initiate(self):
        cdef CK_RV retval
        with nogil:
            retval = self.session.funclist.C_DigestInit(self.session.handle, self.mech.data)
        self._operation_aware_assert(retval)

    cdef bytes digest_process_fully(self, CK_BYTE *data, CK_ULONG data_len) with gil:
        cdef Session session = self.session
        return self.process_fully(session.funclist.C_Digest, data, data_len)

    cdef void update_digest(self, CK_BYTE *data, CK_ULONG data_len):
        self.update_no_output(self.session.funclist.C_DigestUpdate, data, data_len)

    cdef void update_digest_with_key(self, CK_OBJECT_HANDLE key):
        cdef Session session = self.session
        with nogil:
            retval = session.funclist.C_DigestKey(session.handle, key)
        self._operation_aware_assert(retval)

    def ingest_chunks(self, chunks):
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_OBJECT_HANDLE key

        for chunk in chunks:
            if not chunk:
                continue
            if isinstance(chunk, types.Key):
                key = chunk.handle
                self.update_digest_with_key(key)
            else:
                data_ptr = chunk
                data_len = <CK_ULONG> len(chunk)
                self.update_digest(data_ptr, data_len)

    cdef bytes finish(self):
        return self.finish_with_output(self.session.funclist.C_DigestFinal)

    def _finalize(self, silent=False):
        cdef Session session = self.session
        if self.active:
            self.execute_resizing_output(session.funclist.C_DigestFinal)
        super()._finalize(silent=silent)


def merge_templates(default_template, *user_templates):
    template = default_template.copy()

    for user_template in user_templates:
        if user_template is not None:
            template.update(user_template)

    return {
        key: value
        for key, value in template.items()
        if value is not DEFAULT
    }


cdef class Session(HasFuncList, types.Session):
    """Extend Session with implementation."""

    cdef readonly CK_SESSION_HANDLE handle
    cdef readonly Token token
    cdef readonly bint rw
    cdef readonly bint async_
    cdef CK_USER_TYPE _user_type
    cdef object operation_lock
    cdef object attribute_mapper
    cdef unsigned int cancel_strategy

    @staticmethod
    cdef Session make(
            Token token,
            CK_SESSION_HANDLE handle,
            bint rw,
            bint async_,
            CK_USER_TYPE user_type,
            object mapper,
            unsigned int cancel_strategy
    ):
        cdef Session session = Session.__new__(Session)

        session.funclist = token.funclist
        session.funclist3 = token.funclist3
        session.funclist32 = token.funclist32
        session.token = token

        session.handle = handle
        # Big operation lock prevents other threads from entering/reentering
        # operations. If the same thread enters the lock, they will get a
        # Cryptoki warning
        session.operation_lock = RLock()

        session.rw = rw
        session.async_ = async_
        session._user_type = user_type
        session.attribute_mapper = mapper
        session.cancel_strategy = cancel_strategy
        return session

    def __init__(self):
        raise TypeError

    def _identity(self):
        return Session.__name__, self.token, self.handle

    @property
    def user_type(self):
        """User type for this session (:class:`pkcs11.constants.UserType`)."""
        return UserType(self._user_type)

    def close(self):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_RV retval

        if self.user_type != UserType.NOBODY:
            self.logout()

        with nogil:
            retval = self.funclist.C_CloseSession(handle)
        assertRV(retval)

    def login(self, user_type=UserType.USER, pin=None, username=None):
        cdef CK_UTF8CHAR *pin_data = NULL
        cdef CK_ULONG pin_length = 0
        cdef CK_UTF8CHAR *username_data = NULL
        cdef CK_ULONG username_length = 0
        cdef CK_RV retval
        cdef CK_USER_TYPE c_user_type = user_type
        cdef bytes pin_bytes
        cdef bytes username_bytes

        if pin is PROTECTED_AUTH:
            if not self.token.flags & TokenFlag.PROTECTED_AUTHENTICATION_PATH:
                raise ArgumentsBad("Protected authentication is not supported by loaded module")
        elif pin is not None:
            pin_bytes = _coerce_pin_bytes(pin)
            pin_data = pin_bytes
            pin_length = <CK_ULONG> len(pin_bytes)

        if username is not None:
            username_bytes = _coerce_utf8_bytes(username)
            username_data = username_bytes
            username_length = <CK_ULONG> len(username_bytes)

            if self.funclist32 != NULL:
                with nogil:
                    retval = self.funclist32.C_LoginUser(
                        self.handle,
                        c_user_type,
                        pin_data,
                        pin_length,
                        username_data,
                        username_length,
                    )
            elif self.funclist3 != NULL:
                with nogil:
                    retval = self.funclist3.C_LoginUser(
                        self.handle,
                        c_user_type,
                        pin_data,
                        pin_length,
                        username_data,
                        username_length,
                    )
            else:
                raise NotImplementedError("login(username=...) requires PKCS#11 v3.0 interface")
        else:
            with nogil:
                retval = self.funclist.C_Login(self.handle, c_user_type, pin_data, pin_length)

        assertRV(retval)
        self._user_type = c_user_type

    def logout(self):
        cdef CK_RV retval

        if self.user_type == UserType.NOBODY:
            return

        with nogil:
            retval = self.funclist.C_Logout(self.handle)
        assertRV(retval)
        self._user_type = CKU_USER_NOBODY

    def get_objects(self, attrs=None, batch_size=10):
        with SearchIter(self, attrs or {}, batch_size) as op:
            for batch in op:
                yield from batch

    def reaffirm_credentials(self, pin):
        self.login(UserType.CONTEXT_SPECIFIC, pin=pin)

    def cancel(self, flags=0):
        cdef CK_FLAGS c_flags = flags
        cdef CK_RV retval

        if self.funclist32 != NULL:
            with nogil:
                retval = self.funclist32.C_SessionCancel(self.handle, c_flags)
        elif self.funclist3 != NULL:
            with nogil:
                retval = self.funclist3.C_SessionCancel(self.handle, c_flags)
        else:
            raise NotImplementedError("cancel requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def get_validation_flags(self, type=SessionValidationFlagsType.LAST_VALIDATION_OK):
        cdef CK_SESSION_VALIDATION_FLAGS_TYPE c_type = type
        cdef CK_FLAGS flags
        cdef CK_RV retval

        if self.funclist32 == NULL:
            raise NotImplementedError("get_validation_flags requires PKCS#11 v3.2 interface")

        with nogil:
            retval = self.funclist32.C_GetSessionValidationFlags(self.handle, c_type, &flags)
        assertRV(retval)
        return flags

    def async_complete(self, operation, capture_result=True):
        cdef Session session = self
        cdef bytes operation_name
        cdef CK_UTF8CHAR *operation_ptr
        cdef CK_ASYNC_DATA result
        cdef CK_RV retval
        cdef object object_result = None
        cdef object additional_object_result = None

        if session.funclist32 == NULL:
            raise NotImplementedError("async_complete requires PKCS#11 v3.2 interface")

        operation_name = _coerce_operation_name(operation)
        operation_ptr = operation_name

        if not capture_result:
            with nogil:
                retval = session.funclist32.C_AsyncComplete(session.handle, operation_ptr, NULL)
            assertRV(retval)
            return None

        result.ulVersion = 0
        result.pValue = NULL
        result.ulValue = 0
        result.hObject = 0
        result.hAdditionalObject = 0

        with nogil:
            retval = session.funclist32.C_AsyncComplete(session.handle, operation_ptr, &result)
        assertRV(retval)

        if result.hObject != 0:
            object_result = make_object(session, result.hObject)
        if result.hAdditionalObject != 0:
            additional_object_result = make_object(session, result.hAdditionalObject)

        return types.AsyncResult(
            value=(
                PyBytes_FromStringAndSize(<char *> result.pValue, <Py_ssize_t> result.ulValue)
                if result.pValue != NULL else None
            ),
            object=object_result,
            additional_object=additional_object_result,
        )

    def async_get_id(self, operation):
        cdef Session session = self
        cdef bytes operation_name
        cdef CK_UTF8CHAR *operation_ptr
        cdef CK_ULONG operation_id
        cdef CK_RV retval

        if session.funclist32 == NULL:
            raise NotImplementedError("async_get_id requires PKCS#11 v3.2 interface")

        operation_name = _coerce_operation_name(operation)
        operation_ptr = operation_name

        with nogil:
            retval = session.funclist32.C_AsyncGetID(session.handle, operation_ptr, &operation_id)
        assertRV(retval)
        return operation_id

    def async_join(self, operation, operation_id, data=None):
        cdef Session session = self
        cdef bytes operation_name
        cdef CK_UTF8CHAR *operation_ptr
        cdef CK_ULONG c_operation_id = <CK_ULONG> operation_id
        cdef CK_BYTE *data_ptr = NULL
        cdef CK_ULONG data_len = 0
        cdef CK_RV retval
        cdef bytearray data_buffer

        if session.funclist32 == NULL:
            raise NotImplementedError("async_join requires PKCS#11 v3.2 interface")

        operation_name = _coerce_operation_name(operation)
        operation_ptr = operation_name

        if data is not None:
            if not isinstance(data, bytearray):
                raise ArgumentsBad("`data` must be a bytearray when supplied.")
            data_buffer = data
            data_ptr = _bytearray_ptr(data_buffer)
            data_len = _bytearray_len(data_buffer)

        with nogil:
            retval = session.funclist32.C_AsyncJoin(
                session.handle,
                operation_ptr,
                c_operation_id,
                data_ptr,
                data_len,
            )
        assertRV(retval)

    def message_encrypt_init(self, key, mechanism=None, mechanism_param=None):
        cdef CK_RV retval
        cdef Session session = self
        cdef CK_MECHANISM *mech_data
        cdef CK_OBJECT_HANDLE key_handle

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(key.key_type, DEFAULT_ENCRYPT_MECHANISMS, mechanism, mechanism_param)
        mech_data = mech.data
        key_handle = key.handle

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageEncryptInit(session.handle, mech_data, key_handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageEncryptInit(session.handle, mech_data, key_handle)
        else:
            raise NotImplementedError("message_encrypt_init requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def encrypt_message(self, data, parameter=None, associated_data=None):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef bytes aad_bytes
        cdef CK_BYTE *aad_ptr = NULL
        cdef CK_ULONG aad_len = 0
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_ULONG output_len
        cdef CK_RV retval

        if associated_data is not None:
            aad_bytes = _coerce_message_bytes(associated_data, "associated_data")
            aad_ptr = aad_bytes
            aad_len = <CK_ULONG> len(aad_bytes)

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_EncryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_EncryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        else:
            raise NotImplementedError("encrypt_message requires PKCS#11 v3.0 interface")
        assertRV(retval)

        cdef CK_BYTE [:] output_buf = CK_BYTE_buffer(output_len or 1)
        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_EncryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        else:
            with nogil:
                retval = session.funclist3.C_EncryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        assertRV(retval)
        return bytes(output_buf[:output_len])

    def encrypt_message_begin(self, parameter=None, associated_data=None):
        cdef Session session = self
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef bytes aad_bytes
        cdef CK_BYTE *aad_ptr = NULL
        cdef CK_ULONG aad_len = 0
        cdef CK_RV retval

        if associated_data is not None:
            aad_bytes = _coerce_message_bytes(associated_data, "associated_data")
            aad_ptr = aad_bytes
            aad_len = <CK_ULONG> len(aad_bytes)

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_EncryptMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length, aad_ptr, aad_len
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_EncryptMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length, aad_ptr, aad_len
                )
        else:
            raise NotImplementedError("encrypt_message_begin requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def encrypt_message_next(self, data, parameter=None, flags=0):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_ULONG output_len
        cdef CK_FLAGS c_flags = flags
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_EncryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                    c_flags,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_EncryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                    c_flags,
                )
        else:
            raise NotImplementedError("encrypt_message_next requires PKCS#11 v3.0 interface")
        assertRV(retval)

        cdef CK_BYTE [:] output_buf = CK_BYTE_buffer(output_len or 1)
        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_EncryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                    c_flags,
                )
        else:
            with nogil:
                retval = session.funclist3.C_EncryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                    c_flags,
                )
        assertRV(retval)
        return bytes(output_buf[:output_len])

    def message_encrypt_final(self):
        cdef Session session = self
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageEncryptFinal(session.handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageEncryptFinal(session.handle)
        else:
            raise NotImplementedError("message_encrypt_final requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def message_decrypt_init(self, key, mechanism=None, mechanism_param=None):
        cdef CK_RV retval
        cdef Session session = self
        cdef CK_MECHANISM *mech_data
        cdef CK_OBJECT_HANDLE key_handle

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(key.key_type, DEFAULT_ENCRYPT_MECHANISMS, mechanism, mechanism_param)
        mech_data = mech.data
        key_handle = key.handle

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageDecryptInit(session.handle, mech_data, key_handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageDecryptInit(session.handle, mech_data, key_handle)
        else:
            raise NotImplementedError("message_decrypt_init requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def decrypt_message(self, data, parameter=None, associated_data=None):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef bytes aad_bytes
        cdef CK_BYTE *aad_ptr = NULL
        cdef CK_ULONG aad_len = 0
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_ULONG output_len
        cdef CK_RV retval

        if associated_data is not None:
            aad_bytes = _coerce_message_bytes(associated_data, "associated_data")
            aad_ptr = aad_bytes
            aad_len = <CK_ULONG> len(aad_bytes)

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_DecryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_DecryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        else:
            raise NotImplementedError("decrypt_message requires PKCS#11 v3.0 interface")
        assertRV(retval)

        cdef CK_BYTE [:] output_buf = CK_BYTE_buffer(output_len or 1)
        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_DecryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        else:
            with nogil:
                retval = session.funclist3.C_DecryptMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    aad_ptr, aad_len,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        assertRV(retval)
        return bytes(output_buf[:output_len])

    def decrypt_message_begin(self, parameter=None, associated_data=None):
        cdef Session session = self
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef bytes aad_bytes
        cdef CK_BYTE *aad_ptr = NULL
        cdef CK_ULONG aad_len = 0
        cdef CK_RV retval

        if associated_data is not None:
            aad_bytes = _coerce_message_bytes(associated_data, "associated_data")
            aad_ptr = aad_bytes
            aad_len = <CK_ULONG> len(aad_bytes)

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_DecryptMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length, aad_ptr, aad_len
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_DecryptMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length, aad_ptr, aad_len
                )
        else:
            raise NotImplementedError("decrypt_message_begin requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def decrypt_message_next(self, data, parameter=None, flags=0):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_ULONG output_len
        cdef CK_FLAGS c_flags = flags
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_DecryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                    c_flags,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_DecryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                    c_flags,
                )
        else:
            raise NotImplementedError("decrypt_message_next requires PKCS#11 v3.0 interface")
        assertRV(retval)

        cdef CK_BYTE [:] output_buf = CK_BYTE_buffer(output_len or 1)
        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_DecryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                    c_flags,
                )
        else:
            with nogil:
                retval = session.funclist3.C_DecryptMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                    c_flags,
                )
        assertRV(retval)
        return bytes(output_buf[:output_len])

    def message_decrypt_final(self):
        cdef Session session = self
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageDecryptFinal(session.handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageDecryptFinal(session.handle)
        else:
            raise NotImplementedError("message_decrypt_final requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def message_sign_init(self, key, mechanism=None, mechanism_param=None):
        cdef CK_RV retval
        cdef Session session = self
        cdef CK_MECHANISM *mech_data
        cdef CK_OBJECT_HANDLE key_handle

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(key.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        mech_data = mech.data
        key_handle = key.handle

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageSignInit(session.handle, mech_data, key_handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageSignInit(session.handle, mech_data, key_handle)
        else:
            raise NotImplementedError("message_sign_init requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def sign_message(self, data, parameter=None):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_ULONG output_len
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_SignMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_SignMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        else:
            raise NotImplementedError("sign_message requires PKCS#11 v3.0 interface")
        assertRV(retval)

        cdef CK_BYTE [:] output_buf = CK_BYTE_buffer(output_len or 1)
        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_SignMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        else:
            with nogil:
                retval = session.funclist3.C_SignMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        assertRV(retval)
        return bytes(output_buf[:output_len])

    def sign_message_begin(self, parameter=None):
        cdef Session session = self
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_SignMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_SignMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length
                )
        else:
            raise NotImplementedError("sign_message_begin requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def sign_message_next(self, data, parameter=None):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_ULONG output_len
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_SignMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_SignMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    NULL, &output_len,
                )
        else:
            raise NotImplementedError("sign_message_next requires PKCS#11 v3.0 interface")
        assertRV(retval)

        cdef CK_BYTE [:] output_buf = CK_BYTE_buffer(output_len or 1)
        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_SignMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        else:
            with nogil:
                retval = session.funclist3.C_SignMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    &output_buf[0], &output_len,
                )
        assertRV(retval)
        return bytes(output_buf[:output_len])

    def message_sign_final(self):
        cdef Session session = self
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageSignFinal(session.handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageSignFinal(session.handle)
        else:
            raise NotImplementedError("message_sign_final requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def message_verify_init(self, key, mechanism=None, mechanism_param=None):
        cdef CK_RV retval
        cdef Session session = self
        cdef CK_MECHANISM *mech_data
        cdef CK_OBJECT_HANDLE key_handle

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(key.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        mech_data = mech.data
        key_handle = key.handle

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageVerifyInit(session.handle, mech_data, key_handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageVerifyInit(session.handle, mech_data, key_handle)
        else:
            raise NotImplementedError("message_verify_init requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def verify_message(self, data, signature, parameter=None):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef bytes signature_bytes = _coerce_message_bytes(signature, "signature")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_BYTE *sig_ptr = signature_bytes
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature_bytes)
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_VerifyMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    sig_ptr, sig_len,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_VerifyMessage(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    sig_ptr, sig_len,
                )
        else:
            raise NotImplementedError("verify_message requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def verify_message_begin(self, parameter=None):
        cdef Session session = self
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_VerifyMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_VerifyMessageBegin(
                    session.handle, parameter_data.data, parameter_data.length
                )
        else:
            raise NotImplementedError("verify_message_begin requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def verify_message_next(self, data, signature, parameter=None):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef bytes signature_bytes = _coerce_message_bytes(signature, "signature")
        cdef MessageParameter parameter_data = MessageParameter(parameter)
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_BYTE *sig_ptr = signature_bytes
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature_bytes)
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_VerifyMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    sig_ptr, sig_len,
                )
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_VerifyMessageNext(
                    session.handle,
                    parameter_data.data, parameter_data.length,
                    data_ptr, data_len,
                    sig_ptr, sig_len,
                )
        else:
            raise NotImplementedError("verify_message_next requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def message_verify_final(self):
        cdef Session session = self
        cdef CK_RV retval

        if session.funclist32 != NULL:
            with nogil:
                retval = session.funclist32.C_MessageVerifyFinal(session.handle)
        elif session.funclist3 != NULL:
            with nogil:
                retval = session.funclist3.C_MessageVerifyFinal(session.handle)
        else:
            raise NotImplementedError("message_verify_final requires PKCS#11 v3.0 interface")

        assertRV(retval)

    def verify_signature_init(self, key, signature, mechanism=None, mechanism_param=None):
        cdef Session session = self
        cdef bytes signature_bytes = _coerce_message_bytes(signature, "signature")
        cdef CK_BYTE *signature_ptr = signature_bytes
        cdef CK_ULONG signature_len = <CK_ULONG> len(signature_bytes)
        cdef CK_RV retval
        cdef CK_MECHANISM *mech_data
        cdef CK_OBJECT_HANDLE key_handle

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")
        if session.funclist32 == NULL:
            raise NotImplementedError("verify_signature_init requires PKCS#11 v3.2 interface")

        mech = MechanismWithParam(key.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        mech_data = mech.data
        key_handle = key.handle

        with nogil:
            retval = session.funclist32.C_VerifySignatureInit(
                session.handle, mech_data, key_handle, signature_ptr, signature_len
            )
        assertRV(retval)

    def verify_signature(self, data):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_RV retval

        if session.funclist32 == NULL:
            raise NotImplementedError("verify_signature requires PKCS#11 v3.2 interface")

        with nogil:
            retval = session.funclist32.C_VerifySignature(session.handle, data_ptr, data_len)
        assertRV(retval)

    def verify_signature_update(self, data):
        cdef Session session = self
        cdef bytes data_bytes = _coerce_message_bytes(data, "data")
        cdef CK_BYTE *data_ptr = data_bytes
        cdef CK_ULONG data_len = <CK_ULONG> len(data_bytes)
        cdef CK_RV retval

        if session.funclist32 == NULL:
            raise NotImplementedError("verify_signature_update requires PKCS#11 v3.2 interface")

        with nogil:
            retval = session.funclist32.C_VerifySignatureUpdate(session.handle, data_ptr, data_len)
        assertRV(retval)

    def verify_signature_final(self):
        cdef Session session = self
        cdef CK_RV retval

        if session.funclist32 == NULL:
            raise NotImplementedError("verify_signature_final requires PKCS#11 v3.2 interface")

        with nogil:
            retval = session.funclist32.C_VerifySignatureFinal(session.handle)
        assertRV(retval)

    def create_object(self, attrs):
        template = self.make_attribute_list(attrs)

        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_OBJECT_HANDLE new
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_CreateObject(handle, attr_data, attr_count, &new)
        assertRV(retval)

        return make_object(self, new)

    def create_domain_parameters(self, key_type, attrs,
                                 local=False, store=False):
        if local and store:
            raise ArgumentsBad("Cannot set both `local` and `store`")

        attrs = dict(attrs)
        attrs[Attribute.CLASS] = ObjectClass.DOMAIN_PARAMETERS
        attrs[Attribute.KEY_TYPE] = key_type
        attrs[Attribute.TOKEN] = store

        if local:
            return LocalDomainParameters(self, attrs)
        else:
            return self.create_object(attrs)

    def generate_domain_parameters(self, key_type, param_length, store=False,
                                   mechanism=None, mechanism_param=None,
                                   template=None):
        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if not isinstance(param_length, int):
            raise ArgumentsBad("`param_length` is the length in bits.")

        mech = MechanismWithParam(
            key_type, DEFAULT_PARAM_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        template_ = {
            Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS,
            Attribute.TOKEN: store,
            Attribute.PRIME_BITS: param_length,
        }
        attrs = self.make_attribute_list(merge_templates(template_, template))

        return self.generate_key_from_attrs(attrs, mech)

    cdef AttributeList make_attribute_list(self, template):
        return AttributeList.from_template(dict(template), self.attribute_mapper)

    def generate_key(self, key_type, key_length=None,
                     id=None, label=None,
                     store=False, capabilities=None,
                     mechanism=None, mechanism_param=None,
                     template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if key_length is not None and not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        template_ = self.attribute_mapper.secret_key_template(
            capabilities=capabilities, id_=id, label=label, store=store,
        )
        template_[Attribute.KEY_TYPE] = key_type
        # Build attributes
        if key_type not in (KeyType.DES2, KeyType.DES3, KeyType.GOST28147, KeyType.SEED):
            if key_length is None:
                raise ArgumentsBad("Must provide `key_length'")

            template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes

        attrs = self.make_attribute_list(merge_templates(template_, template))

        return self.generate_key_from_attrs(attrs, mech)

    cdef object generate_key_from_attrs(
            self, AttributeList attrs, MechanismWithParam mech
    ):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key

        with nogil:
            retval = self.funclist.C_GenerateKey(handle, mech_data, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(self, key)


    def _generate_keypair(self, key_type, key_length=None,
                          id=None, label=None,
                          store=False, capabilities=None,
                          mechanism=None, mechanism_param=None,
                          public_template=None, private_template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if key_length is not None and not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        public_template_ = self.attribute_mapper.public_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )

        if key_type is KeyType.RSA:
            if key_length is None:
                raise ArgumentsBad("Must provide `key_length'")

            # Some PKCS#11 implementations don't default this, it makes sense
            # to do it here
            public_template_.update({
                Attribute.PUBLIC_EXPONENT: b'\1\0\1',
                Attribute.MODULUS_BITS: key_length,
            })

        public_attrs = self.make_attribute_list(merge_templates(public_template_, public_template))

        private_template_ = self.attribute_mapper.private_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )
        private_attrs = self.make_attribute_list(merge_templates(private_template_, private_template))
        return self.generate_keypair_from_attrs(public_attrs, private_attrs, mech)

    cdef tuple generate_keypair_from_attrs(
            self,
            AttributeList public_attrs,
            AttributeList private_attrs,
            MechanismWithParam mech
    ):

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *public_attr_data = public_attrs.data
        cdef CK_ULONG public_attr_count = public_attrs.count
        cdef CK_ATTRIBUTE *private_attr_data = private_attrs.data
        cdef CK_ULONG private_attr_count = private_attrs.count
        cdef CK_OBJECT_HANDLE public_key
        cdef CK_OBJECT_HANDLE private_key
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateKeyPair(handle, mech_data, public_attr_data, public_attr_count, private_attr_data, private_attr_count, &public_key, &private_key)
        assertRV(retval)

        return (make_object(self, public_key),
                make_object(self, private_key))

    def seed_random(self, seed):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_BYTE *seed_data = seed
        cdef CK_ULONG seed_len = <CK_ULONG> len(seed)
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_SeedRandom(handle, seed_data, seed_len)
        assertRV(retval)

    def generate_random(self, nbits):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_ULONG length = nbits // 8
        cdef CK_CHAR [:] random = CK_BYTE_buffer(length)
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateRandom(handle, &random[0], length)
        assertRV(retval)

        return bytes(random)

    def get_operation_state(self):
        """Get the current operation state (C_GetOperationState).

        Returns the operation state as bytes, or raises an error if
        no operation is active or the module doesn't support it.
        """
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_ULONG length = 0
        cdef CK_RV retval

        # First call to get required length
        with nogil:
            retval = self.funclist.C_GetOperationState(handle, NULL, &length)
        assertRV(retval)

        cdef CK_BYTE [:] state = CK_BYTE_buffer(length)
        with nogil:
            retval = self.funclist.C_GetOperationState(handle, &state[0], &length)
        assertRV(retval)

        return bytes(state[:length])

    def set_operation_state(self, state, encryption_key=0, authentication_key=0):
        """Restore a previously saved operation state (C_SetOperationState).

        :param bytes state: Operation state from get_operation_state()
        :param int encryption_key: Handle of encryption key (0 if none)
        :param int authentication_key: Handle of authentication key (0 if none)
        """
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_BYTE *state_ptr = state
        cdef CK_ULONG state_len = <CK_ULONG> len(state)
        cdef CK_OBJECT_HANDLE enc_key = <CK_OBJECT_HANDLE> encryption_key
        cdef CK_OBJECT_HANDLE auth_key = <CK_OBJECT_HANDLE> authentication_key
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_SetOperationState(
                handle, state_ptr, state_len, enc_key, auth_key)
        assertRV(retval)

    def __digest_operation(self, mechanism, mechanism_param):
        mech = MechanismWithParam(
            None, {},
            mechanism, mechanism_param)
        return DigestOperation.setup(self, mech, 1024)

    def _digest(self, data, mechanism=None, mechanism_param=None):
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_RV retval

        cdef DigestOperation op =  self.__digest_operation(mechanism, mechanism_param)
        with op:
            return op.digest_process_fully(data_ptr, data_len)

    def _digest_generator(self, data, mechanism=None, mechanism_param=None):

        cdef DigestOperation op = self.__digest_operation(mechanism, mechanism_param)
        with op:
            op.ingest_chunks(data)
            return op.finish()

    def set_pin(self, old_pin, new_pin):
        cdef CK_ULONG old_pin_length
        cdef CK_ULONG new_pin_length
        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_UTF8CHAR *old_pin_data
        cdef CK_UTF8CHAR *new_pin_data
        cdef CK_RV retval

        pin_old = _coerce_pin_bytes(old_pin)
        pin_new = _coerce_pin_bytes(new_pin)

        old_pin_data = pin_old
        new_pin_data = pin_new
        old_pin_length = <CK_ULONG> len(pin_old)
        new_pin_length = <CK_ULONG> len(pin_new)

        with nogil:
            retval = self.funclist.C_SetPIN(handle, old_pin_data, old_pin_length, new_pin_data, new_pin_length)
        assertRV(retval)

    def init_pin(self, pin):
        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval

        pin = _coerce_pin_bytes(pin)

        pin_data = pin
        pin_length = <CK_ULONG> len(pin)

        with nogil:
            retval = self.funclist.C_InitPIN(handle, pin_data, pin_length)
        assertRV(retval)

cdef class ObjectHandleWrapper(HasFuncList):
    """
    Class implementing generic operations on PKCS#11 objects.
    """

    cdef readonly Session session
    cdef readonly CK_OBJECT_HANDLE handle

    @staticmethod
    cdef ObjectHandleWrapper wrap(Session session, CK_OBJECT_HANDLE handle):
        cdef ObjectHandleWrapper obj = ObjectHandleWrapper.__new__(ObjectHandleWrapper)
        obj.funclist = session.funclist
        obj.session = session
        obj.handle = handle
        return obj

    def __init__(self):
        raise TypeError

    cdef AttributeList get_attribute_list(self, CK_ATTRIBUTE_TYPE * keys, CK_ULONG total) with gil:
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ULONG ix = 0
        cdef CK_ULONG retrievable = 0
        cdef CK_ATTRIBUTE *tpl = <CK_ATTRIBUTE *> PyMem_Malloc(total * sizeof(CK_ATTRIBUTE))
        cdef CK_RV retval
        cdef AttributeList result
        cdef AttributeList child
        cdef CK_ULONG nested_count

        for ix in range(total):
            tpl[ix].type = keys[ix]
            tpl[ix].pValue = NULL
            tpl[ix].ulValueLen = <CK_ULONG> 0

        with nogil:
            retval = self.funclist.C_GetAttributeValue(handle, obj, tpl, total)

        for ix in range(total):
            if tpl[ix].ulValueLen != CK_UNAVAILABLE_INFORMATION:
                # overwrite the template at position 'retrievable' in the buffer
                tpl[retrievable].type = tpl[ix].type
                tpl[retrievable].pValue = NULL
                tpl[retrievable].ulValueLen = tpl[ix].ulValueLen
                retrievable += 1
            # The spec prohibits returning CK_UNAVAILABLE_INFORMATION
            #  together with CKR_OK, but some tokens do that anyway.
            #  Let's be defensive and map that to a proper error,
            if tpl[ix].ulValueLen == CK_UNAVAILABLE_INFORMATION and retval == CKR_OK:
                retval = CKR_FUNCTION_FAILED
                break

        # when this gets GC'd, the __dealloc__ will clean up our buffers
        result = AttributeList.from_owned_pointer(tpl, retrievable)
        if retrievable:
            for ix in range(retrievable):
                if _attribute_is_template(tpl[ix].type):
                    nested_count = <CK_ULONG> (tpl[ix].ulValueLen / sizeof(CK_ATTRIBUTE))
                    child = AttributeList.allocate(nested_count)
                    result.child_values[ix] = child
                    tpl[ix].pValue = <void *> child.data
                elif tpl[ix].ulValueLen != 0:
                    tpl[ix].pValue = PyMem_Malloc(tpl[ix].ulValueLen)
                    if tpl[ix].pValue is NULL:
                        raise MemoryError()

            while True:
                with nogil:
                    retval = self.funclist.C_GetAttributeValue(handle, obj, tpl, retrievable)
                if retval != CKR_OK and retval != CKR_BUFFER_TOO_SMALL:
                    break
                if not _allocate_nested_attribute_buffers(result):
                    break
            _ensure_attribute_values_ready(result)
        assertRV(retval)
        return result


    def __getitem__(self, key):
        cdef CK_ATTRIBUTE_TYPE key_t = key
        return self.get_attribute_list(&key_t, 1).at_index(0, self.session.attribute_mapper)

    def __setitem__(self, key, value):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE template
        cdef CK_RV retval
        cdef AttributeList nested_template
        cdef object packed_value
        cdef bytes value_bytes

        packed_value = self.session.attribute_mapper.pack_attribute(key, value)

        template.type = key
        if _attribute_is_template(<CK_ATTRIBUTE_TYPE> key):
            nested_template = AttributeList.from_template(dict(packed_value), self.session.attribute_mapper)
            template.pValue = <void *> nested_template.data
            template.ulValueLen = nested_template.count * sizeof(CK_ATTRIBUTE)
        else:
            value_bytes = packed_value
            if len(value_bytes) == 0:
                template.pValue = NULL
                template.ulValueLen = 0
            else:
                template.pValue = <CK_CHAR *> value_bytes
                template.ulValueLen = <CK_ULONG> len(value_bytes)

        with nogil:
            retval = self.funclist.C_SetAttributeValue(handle, obj, &template, 1)
        assertRV(retval)

    def destroy(self):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_DestroyObject(handle, obj)
        assertRV(retval)

    def get_size(self):
        """Return approximate size of the object in bytes (C_GetObjectSize)."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ULONG size = 0
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_GetObjectSize(handle, obj, &size)
        assertRV(retval)
        return size

    def copy(self, attrs):
        template = self.session.make_attribute_list(attrs)

        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_OBJECT_HANDLE new_obj
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_CopyObject(handle, obj, attr_data, attr_count, &new_obj)
        assertRV(retval)
        return new_obj

    def identity(self):
        return ObjectHandleWrapper.__name__, self.session, self.handle


class Object(types.Object):
    """Expand Object with an implementation."""

    def __init__(self, wrapper: ObjectHandleWrapper):
        self.wrapper = wrapper

    def __getitem__(self, item):
        return self.wrapper[item]

    def __setitem__(self, key, value):
        self.wrapper[key] = value

    def get_attributes(self, keys):
        cdef ObjectHandleWrapper wrapper = self.wrapper
        cdef CK_ULONG total = len(keys)

        if not total:
            return {}

        cdef CK_ATTRIBUTE_TYPE * key_ptr = <CK_ATTRIBUTE_TYPE *> PyMem_Malloc(total * sizeof(CK_ATTRIBUTE_TYPE))
        cdef CK_ULONG ix = 0
        for ix, key in enumerate(keys):
            key_ptr[ix] = <CK_ATTRIBUTE_TYPE> key

        try:
            result = wrapper.get_attribute_list(key_ptr, total).as_dict(wrapper.session.attribute_mapper)
        finally:
            PyMem_Free(key_ptr)
        return result

    @property
    def session(self):
        return self.wrapper.session

    @property
    def handle(self):
        return self.wrapper.handle

    def copy(self, attrs):
        new_obj = self.wrapper.copy(attrs)
        return make_object(self.wrapper.session, new_obj)

    def destroy(self):
        self.wrapper.destroy()

    def _identity(self):
        return Object.__name__, self.wrapper.identity()


cdef object make_object(Session session, CK_OBJECT_HANDLE handle) with gil:
    """
    Make an object with the right bases for its class and capabilities.
    """
    wrapper = ObjectHandleWrapper.wrap(session, handle)

    cdef CK_ATTRIBUTE_TYPE[8] attr_keys = [
        Attribute.CLASS,
        Attribute.ENCRYPT,
        Attribute.DECRYPT,
        Attribute.SIGN,
        Attribute.VERIFY,
        Attribute.WRAP,
        Attribute.UNWRAP,
        Attribute.DERIVE
    ]

    try:
        # Determine a list of base classes to manufacture our class with
        try:
            attributes = wrapper.get_attribute_list(&attr_keys[0], 8)
        except PKCS11Error:
            # retry fetching the flags one by one, some tokens do not implement error handling
            # on bulk fetches correctly.
            attributes = {}
            for key in attr_keys:
                try:
                    attributes[key] = wrapper[key]
                except (AttributeTypeInvalid, AttributeSensitive, FunctionFailed):
                    continue

        # Fetch v3.2 KEM attributes separately into a plain dict so that we
        # don't mutate the AttributeList returned by get_attribute_list (which
        # doesn't support __setitem__) and so that missing attributes on older
        # tokens silently produce a falsy value rather than a KeyError.
        kem_attrs: dict = {}
        if session.funclist32 != NULL:
            for key in (Attribute.ENCAPSULATE, Attribute.DECAPSULATE):
                try:
                    kem_attrs[key] = wrapper[key]
                except (AttributeTypeInvalid, AttributeSensitive, FunctionFailed, PKCS11Error):
                    pass

        object_class = attributes.get(Attribute.CLASS, session.attribute_mapper)
        bases = (_CLASS_MAP[object_class],)

        # Build a list of mixins for this new class
        for attribute, mixin in (
                (Attribute.ENCRYPT, EncryptMixin),
                (Attribute.DECRYPT, DecryptMixin),
                (Attribute.SIGN, SignMixin),
                (Attribute.VERIFY, VerifyMixin),
                (Attribute.WRAP, WrapMixin),
                (Attribute.UNWRAP, UnwrapMixin),
                (Attribute.DERIVE, DeriveMixin),
        ):
            try:
                if attributes.get(attribute, session.attribute_mapper):
                    bases += (mixin,)
            except KeyError:
                pass

        # v3.2 KEM mixins — only when the v3.2 interface is available
        if session.funclist32 != NULL:
            for attribute, mixin in (
                    (Attribute.ENCAPSULATE, EncapsulateMixin),
                    (Attribute.DECAPSULATE, DecapsulateMixin),
            ):
                if kem_attrs.get(attribute):
                    bases += (mixin,)

        bases += (Object,)

        # Manufacture a class with the right capabilities.
        klass = type(bases[0].__name__, bases, {})

        return klass(wrapper)

    except KeyError:
        return Object(wrapper)


class EncapsulateMixin(types.EncapsulateMixin):
    """Expand EncapsulateMixin with an implementation (PKCS#11 v3.2+)."""

    def encapsulate_key(self, key_type,
                        id=None, label=None,
                        store=False, capabilities=None,
                        mechanism=None, mechanism_param=None,
                        template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_ENCAPSULATE_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session

        if session.funclist32 == NULL:
            raise NotImplementedError("encapsulate_key requires PKCS#11 v3.2 interface")

        template_ = session.attribute_mapper.secret_key_template(
            capabilities=capabilities, id_=id, label=label, store=store,
        )
        template_[Attribute.KEY_TYPE] = key_type
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE pub_key = self.handle
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_ULONG ct_len
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        # First call: determine ciphertext length
        with nogil:
            retval = session.funclist32.C_EncapsulateKey(
                session.handle, mech_data, pub_key,
                attr_data, attr_count,
                NULL, &ct_len, &key)
        assertRV(retval)

        cdef CK_BYTE [:] ct_buf = CK_BYTE_buffer(ct_len)

        # Second call: retrieve ciphertext and key handle
        with nogil:
            retval = session.funclist32.C_EncapsulateKey(
                session.handle, mech_data, pub_key,
                attr_data, attr_count,
                &ct_buf[0], &ct_len, &key)
        assertRV(retval)

        return bytes(ct_buf[:ct_len]), make_object(session, key)


class DecapsulateMixin(types.DecapsulateMixin):
    """Expand DecapsulateMixin with an implementation (PKCS#11 v3.2+)."""

    def decapsulate_key(self, key_type, ciphertext,
                        id=None, label=None,
                        store=False, capabilities=None,
                        mechanism=None, mechanism_param=None,
                        template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_ENCAPSULATE_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session

        if session.funclist32 == NULL:
            raise NotImplementedError("decapsulate_key requires PKCS#11 v3.2 interface")

        template_ = session.attribute_mapper.secret_key_template(
            capabilities=capabilities, id_=id, label=label, store=store,
        )
        template_[Attribute.KEY_TYPE] = key_type
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE priv_key = self.handle
        cdef CK_BYTE *ct_ptr = ciphertext
        cdef CK_ULONG ct_len = <CK_ULONG> len(ciphertext)
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist32.C_DecapsulateKey(
                session.handle, mech_data, priv_key,
                attr_data, attr_count,
                ct_ptr, ct_len, &key)
        assertRV(retval)

        return make_object(session, key)


class SecretKey(types.SecretKey):
    pass


class PublicKey(types.PublicKey):
    pass


class PrivateKey(types.PrivateKey):
    pass


class GenerateWithParametersMixin(types.DomainParameters):
    def generate_keypair(self,
                         id=None, label=None,
                         store=False, capabilities=None,
                         mechanism=None, mechanism_param=None,
                         public_template=None, private_template=None):

        cdef Session session = self.session
        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[self.key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_GENERATE_MECHANISMS, mechanism, mechanism_param)

        # Build attributes
        public_template_ = session.attribute_mapper.public_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )

        # Copy in our domain parameters.
        # Not all parameters are appropriate for all domains.
        try:
            public_template_.update(
                self.get_attributes(
                    (
                        Attribute.BASE,
                        Attribute.PRIME,
                        Attribute.SUBPRIME,
                        Attribute.EC_PARAMS,
                    )
                )
            )
        except (AttributeTypeInvalid, FunctionFailed):
            pass

        public_attrs = session.make_attribute_list(merge_templates(public_template_, public_template))

        private_template_ = session.attribute_mapper.private_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )
        private_attrs = session.make_attribute_list(merge_templates(private_template_, private_template))

        return session.generate_keypair_from_attrs(public_attrs, private_attrs, mech)


class LocalDomainParameters(GenerateWithParametersMixin, types.LocalDomainParameters):
    pass

class StoredDomainParameters(GenerateWithParametersMixin):
    pass

class Certificate(types.Certificate):
    pass


cdef class KeyOperation(OperationWithBinaryOutput):
    cdef CK_OBJECT_HANDLE key
    cdef CK_FLAGS cancel_flags
    cdef KeyOperationInit op_init

    @staticmethod
    cdef KeyOperation _common_key_setup(
            type cls,
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:

        cdef KeyOperation op = <KeyOperation> OperationWithBinaryOutput._setup(
            cls, session, mech, buffer_size
        )
        op.key = key
        return op

    def unclean_shutdown(self):
        """
        Shutdown implementation for 2.x PKCS#11 modules that don't support shutdown signalling
        """
        raise NotImplementedError

    def _initiate(self):
        cdef CK_RV retval
        with nogil:
            retval = self.op_init(self.session.handle, self.mech.data, self.key)
        self._operation_aware_assert(retval)

    def _cancel_operation(self, silent):
        cdef CK_RV retval
        if self.session.cancel_strategy == CancelStrategy.CANCEL_WITH_SESSION_CANCEL:
            if self.cancel_flags != 0:
                try:
                    self.session.cancel(self.cancel_flags)
                    return
                except (FunctionNotSupported, NotImplementedError):
                    pass
                except PKCS11Error:
                    if not silent:
                        raise
                    return
            self.unclean_shutdown()
        elif self.session.cancel_strategy == CancelStrategy.CANCEL_WITH_INIT:
            # cancel the operation if still active
            # This is a PKCS#11 3.x feature
            with nogil:
                retval = self.op_init(self.session.handle, NULL, self.key)
            if retval == CKR_OPERATION_CANCEL_FAILED and not silent:
                raise PKCS11Error("Failed to cancel operation")
        else:
            # No official cancel protocol in v2.x of the standard
            # Try the poor man's way by making a hail-mary call to C_XYZFinish() and ignoring the response
            self.unclean_shutdown()

    def _finalize(self, silent=False):
        if self.active:
            self._cancel_operation(silent)
        super()._finalize(silent=silent)


cdef class DataCryptOperation(KeyOperation):

    cdef OperationUpdateWithResult op_update
    cdef OperationWithResult op_final
    cdef OperationUpdateWithResult op_full

    @staticmethod
    cdef DataCryptOperation setup_encrypt(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:
        cdef DataCryptOperation op = <DataCryptOperation> KeyOperation._common_key_setup(
            DataCryptOperation, session, mech, key, buffer_size
        )
        op.op_init = session.funclist.C_EncryptInit
        op.cancel_flags = <CK_FLAGS> int(MechanismFlag.ENCRYPT)
        op.op_update = session.funclist.C_EncryptUpdate
        op.op_final = session.funclist.C_EncryptFinal
        op.op_full = session.funclist.C_Encrypt
        return op

    @staticmethod
    cdef DataCryptOperation setup_decrypt(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:
        cdef DataCryptOperation op = <DataCryptOperation> KeyOperation._common_key_setup(
            DataCryptOperation, session, mech, key, buffer_size
        )
        op.op_init = session.funclist.C_DecryptInit
        op.cancel_flags = <CK_FLAGS> int(MechanismFlag.DECRYPT)
        op.op_update = session.funclist.C_DecryptUpdate
        op.op_final = session.funclist.C_DecryptFinal
        op.op_full = session.funclist.C_Decrypt
        return op

    cdef bytes crypt_process_fully(self, CK_BYTE *data, CK_ULONG data_len) with gil:
        return self.process_fully(self.op_full, data, data_len)

    cdef bytes finish(self) with gil:
        return self.finish_with_output(self.op_final)

    def unclean_shutdown(self):
        self.execute_resizing_output(self.op_final)

    def update_chunks(self, chunks):
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len

        for chunk in chunks:
            if not chunk:
                continue
            data_ptr = chunk
            data_len = <CK_ULONG> len(chunk)
            yield self.update_with_result(self.op_update, data_ptr, data_len)


class EncryptMixin(types.EncryptMixin):
    """Expand EncryptMixin with an implementation."""

    def __encrypt_operation(self, mechanism, mechanism_param, buffer_size):

        mech = MechanismWithParam(self.key_type, DEFAULT_ENCRYPT_MECHANISMS, mechanism, mechanism_param)

        return DataCryptOperation.setup_encrypt(self.session, mech, self.handle, buffer_size)

    def _encrypt(self, data, mechanism=None, mechanism_param=None, buffer_size=8192):
        """
        Non chunking encrypt. Needed for some mechanisms.
        """
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)

        cdef DataCryptOperation op = self.__encrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            return op.crypt_process_fully(data, data_len)


    def _encrypt_generator(self, data,
                           mechanism=None, mechanism_param=None,
                           buffer_size=8192):
        """
        Do chunked encryption.
        """
        cdef DataCryptOperation op = self.__encrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            yield from op.update_chunks(data)
            yield op.finish()


class DecryptMixin(types.DecryptMixin):
    """Expand DecryptMixin with an implementation."""

    def __decrypt_operation(self, mechanism, mechanism_param, buffer_size):

        mech = MechanismWithParam(self.key_type, DEFAULT_ENCRYPT_MECHANISMS, mechanism, mechanism_param)

        return DataCryptOperation.setup_decrypt(self.session, mech, self.handle, buffer_size)

    def _decrypt(self, data, mechanism=None, mechanism_param=None, pin=None, buffer_size=8192):
        """Non chunking decrypt."""
        cdef Session session = self.session
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)

        cdef DataCryptOperation op = self.__decrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            return op.crypt_process_fully(data, data_len)


    def _decrypt_generator(self, data,
                           mechanism=None, mechanism_param=None, pin=None,
                           buffer_size=8192):
        """
        Chunking decrypt.
        """
        cdef Session session = self.session

        cdef DataCryptOperation op = self.__decrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            yield from op.update_chunks(data)
            yield op.finish()


cdef class SignOrVerifyOperation(KeyOperation):
    cdef OperationUpdate op_update

    def ingest_chunks(self, chunks):
        cdef Session session = self.session
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len

        for chunk in chunks:
            if not chunk:
                continue
            data_ptr = chunk
            data_len = <CK_ULONG> len(chunk)
            self.update_no_output(self.op_update, data_ptr, data_len)


cdef class DataSignOperation(SignOrVerifyOperation):

    @staticmethod
    cdef DataSignOperation setup(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:
        cdef DataSignOperation op = <DataSignOperation> KeyOperation._common_key_setup(
            DataSignOperation, session, mech, key, buffer_size
        )
        op.op_init = session.funclist.C_SignInit
        op.cancel_flags = <CK_FLAGS> int(MechanismFlag.SIGN)
        op.op_update = session.funclist.C_SignUpdate
        return op

    cdef bytes sign_process_fully(self, CK_BYTE *data, CK_ULONG data_len) with gil:
        cdef Session session = self.session
        return self.process_fully(session.funclist.C_Sign, data, data_len)

    cdef bytes finish(self) with gil:
        cdef Session session = self.session
        return self.finish_with_output(session.funclist.C_SignFinal)

    def unclean_shutdown(self):
        cdef Session session = self.session
        self.execute_resizing_output(session.funclist.C_SignFinal)


class SignMixin(types.SignMixin):
    """Expand SignMixin with an implementation."""

    def __sign_operation(self, mechanism, mechanism_param, buffer_size):
        mech = MechanismWithParam(self.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        return DataSignOperation.setup(self.session, mech, self.handle, buffer_size)

    def _sign(self, data,
              mechanism=None, mechanism_param=None, pin=None, buffer_size=8192):
        cdef Session session = self.session
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef DataSignOperation op = self.__sign_operation(mechanism, mechanism_param, buffer_size)

        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            return op.sign_process_fully(data, data_len)

    def _sign_generator(self, data,
                        mechanism=None, mechanism_param=None, pin=None, buffer_size=8192):

        cdef Session session = self.session
        cdef DataSignOperation op = self.__sign_operation(mechanism, mechanism_param, buffer_size)
        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            op.ingest_chunks(data)
            return op.finish()


cdef class DataVerifyOperation(SignOrVerifyOperation):

    @staticmethod
    cdef DataVerifyOperation setup(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key
    ) with gil:
        cdef DataVerifyOperation op = <DataVerifyOperation> KeyOperation._common_key_setup(
            DataVerifyOperation, session, mech, key, 0
        )
        op.op_init = session.funclist.C_VerifyInit
        op.cancel_flags = <CK_FLAGS> int(MechanismFlag.VERIFY)
        op.op_update = session.funclist.C_VerifyUpdate
        return op

    cdef verify_process_fully(
        self,
        CK_BYTE *data,
        CK_ULONG data_len,
        CK_BYTE *sig,
        CK_ULONG sig_len,
    ) with gil:
        cdef Session session = self.session
        cdef CK_RV retval
        with nogil:
            retval = session.funclist.C_Verify(session.handle, data, data_len, sig, sig_len)
        self._handle_final_retval(retval)

    cdef finish(self, CK_BYTE *sig, CK_ULONG sig_len) with gil:
        cdef Session session = self.session
        cdef CK_RV retval
        with nogil:
            retval = session.funclist.C_VerifyFinal(session.handle, sig, sig_len)
        self._handle_final_retval(retval)

    def unclean_shutdown(self):
        cdef Session session = self.session
        cdef CK_BYTE dummy = 0
        with nogil:
            session.funclist.C_VerifyFinal(session.handle, &dummy, 0)


class VerifyMixin(types.VerifyMixin):
    """Expand VerifyMixin with an implementation."""

    def __verify_operation(self, mechanism, mechanism_param):
        mech = MechanismWithParam(self.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        return DataVerifyOperation.setup(self.session, mech, self.handle)

    def _verify(self, data, signature,
                mechanism=None, mechanism_param=None):

        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE *sig_ptr = signature
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature)
        cdef DataVerifyOperation op = self.__verify_operation(mechanism, mechanism_param)

        with op:
            op.verify_process_fully(data_ptr, data_len, sig_ptr, sig_len)

    def _verify_generator(self, data, signature,
                          mechanism=None, mechanism_param=None):

        cdef CK_BYTE *sig_ptr = signature
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature)
        cdef DataVerifyOperation op = self.__verify_operation(mechanism, mechanism_param)

        with op:
            op.ingest_chunks(data)
            return op.finish(sig_ptr, sig_len)


class WrapMixin(types.WrapMixin):
    """Expand WrapMixin with an implementation."""

    def wrap_key(self, key,
                 mechanism=None, mechanism_param=None):

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(self.key_type, DEFAULT_WRAP_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE wrapping_key = self.handle
        cdef CK_OBJECT_HANDLE key_to_wrap = key.handle
        cdef CK_ULONG length
        cdef CK_RV retval

        # Find out how many bytes we need to allocate
        with nogil:
            retval = session.funclist.C_WrapKey(session.handle, mech_data, wrapping_key, key_to_wrap, NULL, &length)
        assertRV(retval)

        cdef CK_BYTE [:] data = CK_BYTE_buffer(length)

        with nogil:
            retval = session.funclist.C_WrapKey(session.handle, mech_data, wrapping_key, key_to_wrap, &data[0], &length)
        assertRV(retval)

        return bytes(data[:length])

    def wrap_key_authenticated(self, key,
                               associated_data=None,
                               mechanism=None, mechanism_param=None):

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        cdef Session session = self.session
        cdef bytes associated_data_bytes
        cdef CK_BYTE *aad_ptr = NULL
        cdef CK_ULONG aad_len = 0
        cdef CK_MECHANISM *mech_data
        cdef CK_OBJECT_HANDLE wrapping_key = self.handle
        cdef CK_OBJECT_HANDLE key_to_wrap = key.handle
        cdef CK_ULONG length
        cdef CK_RV retval
        cdef object tag = None

        if session.funclist32 == NULL:
            raise NotImplementedError("wrap_key_authenticated requires PKCS#11 v3.2 interface")

        if associated_data is not None:
            associated_data_bytes = _coerce_message_bytes(associated_data, "associated_data")
            aad_ptr = associated_data_bytes
            aad_len = <CK_ULONG> len(associated_data_bytes)

        mech = MechanismWithParam(self.key_type, DEFAULT_WRAP_MECHANISMS, mechanism, mechanism_param)
        mech_data = mech.data

        with nogil:
            retval = session.funclist32.C_WrapKeyAuthenticated(
                session.handle,
                mech_data,
                wrapping_key,
                key_to_wrap,
                aad_ptr,
                aad_len,
                NULL,
                &length,
            )
        assertRV(retval)

        cdef CK_BYTE [:] data = CK_BYTE_buffer(length or 1)

        with nogil:
            retval = session.funclist32.C_WrapKeyAuthenticated(
                session.handle,
                mech_data,
                wrapping_key,
                key_to_wrap,
                aad_ptr,
                aad_len,
                &data[0],
                &length,
            )
        assertRV(retval)

        if isinstance(mechanism_param, GCMMessageParams):
            tag = bytes(mechanism_param.tag[: (mechanism_param.tag_bits + 7) // 8])
        elif isinstance(mechanism_param, CCMMessageParams):
            tag = bytes(mechanism_param.mac[: mechanism_param.mac_len])

        return bytes(data[:length]), tag


class UnwrapMixin(types.UnwrapMixin):
    """Expand UnwrapMixin with an implementation."""

    def unwrap_key(self, object_class, key_type, key_data,
                   id=None, label=None,
                   mechanism=None, mechanism_param=None,
                   store=False, capabilities=None,
                   template=None):

        if not isinstance(object_class, ObjectClass):
            raise ArgumentsBad("`object_class` must be ObjectClass.")

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_WRAP_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session

        # Build attributes
        template_ = session.attribute_mapper.generic_key_template(
            {
                Attribute.CLASS: object_class,
                Attribute.KEY_TYPE: key_type,
            },
            id_=id,
            label=label,
            store=store,
            capabilities=capabilities,
        )
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE unwrapping_key = self.handle
        cdef CK_BYTE *wrapped_key_ptr = key_data
        cdef CK_ULONG wrapped_key_len = <CK_ULONG> len(key_data)
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_UnwrapKey(session.handle, mech_data, unwrapping_key, wrapped_key_ptr, wrapped_key_len, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(session, key)

    def unwrap_key_authenticated(self, object_class, key_type, key_data, tag,
                                 associated_data=None,
                                 id=None, label=None,
                                 mechanism=None, mechanism_param=None,
                                 store=False, capabilities=None,
                                 template=None):

        if not isinstance(object_class, ObjectClass):
            raise ArgumentsBad("`object_class` must be ObjectClass.")

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        cdef Session session = self.session
        cdef bytes wrapped_key_bytes = _coerce_message_bytes(key_data, "key_data")
        cdef bytes associated_data_bytes
        cdef bytes tag_bytes = _coerce_message_bytes(tag, "tag")
        cdef CK_BYTE *aad_ptr = NULL
        cdef CK_ULONG aad_len = 0
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        if session.funclist32 == NULL:
            raise NotImplementedError("unwrap_key_authenticated requires PKCS#11 v3.2 interface")

        if associated_data is not None:
            associated_data_bytes = _coerce_message_bytes(associated_data, "associated_data")
            aad_ptr = associated_data_bytes
            aad_len = <CK_ULONG> len(associated_data_bytes)

        if isinstance(mechanism_param, GCMMessageParams):
            mechanism_param.tag[:] = tag_bytes
            if mechanism_param.tag_bits != len(tag_bytes) * 8:
                raise ArgumentsBad("GCMMessageParams.tag_bits must match the supplied tag length.")
        elif isinstance(mechanism_param, CCMMessageParams):
            mechanism_param.mac[:] = tag_bytes
            if mechanism_param.mac_len != len(tag_bytes):
                raise ArgumentsBad("CCMMessageParams.mac_len must match the supplied tag length.")

        mech = MechanismWithParam(self.key_type, DEFAULT_WRAP_MECHANISMS, mechanism, mechanism_param)

        template_ = session.attribute_mapper.generic_key_template(
            {
                Attribute.CLASS: object_class,
                Attribute.KEY_TYPE: key_type,
            },
            id_=id,
            label=label,
            store=store,
            capabilities=capabilities,
        )
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE unwrapping_key = self.handle
        cdef CK_BYTE *wrapped_key_ptr = wrapped_key_bytes
        cdef CK_ULONG wrapped_key_len = <CK_ULONG> len(wrapped_key_bytes)
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count

        with nogil:
            retval = session.funclist32.C_UnwrapKeyAuthenticated(
                session.handle,
                mech_data,
                unwrapping_key,
                wrapped_key_ptr,
                wrapped_key_len,
                attr_data,
                attr_count,
                aad_ptr,
                aad_len,
                &key,
            )
        assertRV(retval)

        return make_object(session, key)


class DeriveMixin(types.DeriveMixin):
    """Expand DeriveMixin with an implementation."""

    def derive_key(self, key_type, key_length,
                   id=None, label=None,
                   store=False, capabilities=None,
                   mechanism=None, mechanism_param=None,
                   template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_DERIVE_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session

        template_ = session.attribute_mapper.secret_key_template(
            capabilities=capabilities, id_=id, label=label, store=store,
        )
        template_[Attribute.KEY_TYPE] = key_type
        template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE src_key = self.handle
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_DeriveKey(session.handle, mech_data, src_key, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(session, key)


_CLASS_MAP = {
    ObjectClass.SECRET_KEY: SecretKey,
    ObjectClass.PUBLIC_KEY: PublicKey,
    ObjectClass.PRIVATE_KEY: PrivateKey,
    ObjectClass.DOMAIN_PARAMETERS: StoredDomainParameters,
    ObjectClass.CERTIFICATE: Certificate,
}

cdef extern from "../extern/load_module.c":
    ctypedef struct P11_HANDLE:
        void *get_function_list_ptr
        void *get_interface_ptr   # NULL if module doesn't support C_GetInterface

    object p11_error()
    P11_HANDLE* p11_open(object path_str)
    int p11_close(P11_HANDLE* handle)


cdef class lib(HasFuncList):
    """
    Main entry point.

    This class needs to be defined cdef, so it can't shadow a class in
    pkcs11.types.
    """

    cdef readonly str so
    cdef readonly str manufacturer_id
    cdef readonly str library_description
    cdef readonly bint initialized
    cdef CK_VERSION _cryptoki_version
    cdef CK_VERSION _library_version
    cdef P11_HANDLE *_p11_handle
    cdef str _interface_version  # negotiated: "2.40", "3.0", "3.1", or "3.2"

    cdef _load_pkcs11_lib(self, so, requested_interface) with gil:
        """Load a PKCS#11 library and negotiate the interface version.

        Tries C_GetInterface first (v3.0+); falls back to C_GetFunctionList
        (v2.40) when C_GetInterface is not exported by the module.

        :param so: path to a valid PKCS#11 shared library
        :param requested_interface: "auto", "2.40", "3.0", "3.1", or "3.2"
        :raises: PKCS11Error
        """
        cdef C_GetFunctionList_ptr populate_function_list
        cdef C_GetInterface_ptr get_interface
        cdef CK_INTERFACE *iface = NULL
        cdef CK_VERSION req_version
        cdef CK_RV retval

        cdef P11_HANDLE *handle = p11_open(so)
        if handle == NULL:
            err = <str> p11_error()
            if err:
                raise PKCS11Error(f"OS exception while loading {so}: {err}")
            else:
                raise PKCS11Error(f"Unknown exception while loading {so}")
        self._p11_handle = handle

        # --- Attempt v3.0+ interface negotiation via C_GetInterface ---
        if handle.get_interface_ptr != NULL and requested_interface != "2.40":
            get_interface = <C_GetInterface_ptr> handle.get_interface_ptr

            # Try versions in descending order unless a specific one is requested
            versions_to_try = []
            if requested_interface == "auto":
                versions_to_try = [(3, 2), (3, 1), (3, 0)]
            elif requested_interface == "3.2":
                versions_to_try = [(3, 2)]
            elif requested_interface == "3.1":
                versions_to_try = [(3, 1)]
            elif requested_interface == "3.0":
                versions_to_try = [(3, 0)]

            for major, minor in versions_to_try:
                req_version.major = major
                req_version.minor = minor
                retval = get_interface(b"PKCS 11", &req_version, &iface, 0)
                if retval == CKR_OK and iface != NULL:
                    if major == 3 and minor == 2:
                        self.funclist32 = <CK_FUNCTION_LIST_3_2 *> iface.pFunctionList
                        self.funclist3 = <CK_FUNCTION_LIST_3_0 *> iface.pFunctionList
                        self.funclist = <CK_FUNCTION_LIST *> iface.pFunctionList
                        self._interface_version = "3.2"
                    elif major == 3 and minor == 1:
                        self.funclist3 = <CK_FUNCTION_LIST_3_0 *> iface.pFunctionList
                        self.funclist = <CK_FUNCTION_LIST *> iface.pFunctionList
                        self._interface_version = "3.1"
                    else:  # 3.0
                        self.funclist3 = <CK_FUNCTION_LIST_3_0 *> iface.pFunctionList
                        self.funclist = <CK_FUNCTION_LIST *> iface.pFunctionList
                        self._interface_version = "3.0"
                    return
                iface = NULL

        # --- Fall back to v2.40 via C_GetFunctionList ---
        if requested_interface not in ("auto", "2.40"):
            raise PKCS11Error(
                f"Module does not support interface v{requested_interface}; "
                f"C_GetInterface returned no matching interface"
            )
        populate_function_list = <C_GetFunctionList_ptr> handle.get_function_list_ptr
        assertRV(populate_function_list(&self.funclist))
        self._interface_version = "2.40"

    def __cinit__(self, so, interface="auto"):
        cdef CK_RV retval
        self._p11_handle = NULL
        self._interface_version = "2.40"
        self._load_pkcs11_lib(so, interface)
        self.initialized = False
        # at this point, funclist (and optionally funclist3/funclist32) are set

    cpdef initialize(self):
        cdef CK_RV retval
        if self.funclist != NULL and not self.initialized:
            with nogil:
                retval = self.funclist.C_Initialize(NULL)
            assertRV(retval)
            self.initialized = True

    cdef CK_RV _finalize(self):
        cdef CK_RV retval = CKR_OK
        if self.funclist != NULL and self.initialized:
            retval = self.funclist.C_Finalize(NULL)
            self.initialized = False
        return retval

    def finalize(self):
        assertRV(self._finalize())

    def reinitialize(self):
        if self.funclist != NULL:
            self.finalize()
            self.initialize()

    def __init__(self, so, interface="auto"):
        self.so = so
        cdef CK_INFO info
        cdef CK_RV retval

        self.initialize()

        with nogil:
            retval = self.funclist.C_GetInfo(&info)
        assertRV(retval)

        manufacturerID = info.manufacturerID[:sizeof(info.manufacturerID)]
        libraryDescription = info.libraryDescription[:sizeof(info.libraryDescription)]

        self.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturerID)
        self.library_description = _CK_UTF8CHAR_to_str(libraryDescription)
        self._cryptoki_version = info.cryptokiVersion
        self._library_version = info.libraryVersion

    @property
    def library_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._library_version)

    @property
    def cryptoki_version(self):
        """PKCS#11 (cryptoki) API version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._cryptoki_version)

    @property
    def interface_version(self):
        """Negotiated PKCS#11 interface version (:class:`str`).

        One of ``"2.40"``, ``"3.0"``, ``"3.1"``, or ``"3.2"``.
        """
        return self._interface_version

    def get_interface_list(self):
        """Return list of supported interface ``(name, major, minor)`` tuples.

        Calls ``C_GetInterfaceList`` (PKCS#11 v3.0+).  Returns an empty list
        when the module is v2.40 only.

        :rtype: list[tuple[str, int, int]]
        """
        if self.funclist3 == NULL:
            return []

        cdef CK_ULONG count
        cdef CK_RV retval
        cdef CK_INTERFACE *ifaces
        cdef CK_INTERFACE *iface_ptr
        cdef CK_FUNCTION_LIST *fl_ptr
        cdef CK_ULONG i

        with nogil:
            retval = self.funclist3.C_GetInterfaceList(NULL, &count)
        if retval != CKR_OK or count == 0:
            return []

        ifaces = <CK_INTERFACE *> PyMem_Malloc(count * sizeof(CK_INTERFACE))
        if ifaces == NULL:
            raise MemoryError()

        try:
            with nogil:
                retval = self.funclist3.C_GetInterfaceList(ifaces, &count)
            if retval != CKR_OK:
                return []

            result = []
            for i in range(count):
                iface_ptr = &ifaces[i]
                if iface_ptr.pInterfaceName == NULL or iface_ptr.pFunctionList == NULL:
                    continue
                name = (<bytes> iface_ptr.pInterfaceName[:strlen(<char *> iface_ptr.pInterfaceName)]).decode('utf-8', errors='replace').strip()
                fl_ptr = <CK_FUNCTION_LIST *> iface_ptr.pFunctionList
                result.append((name, fl_ptr.version.major, fl_ptr.version.minor))
            return result
        finally:
            PyMem_Free(ifaces)

    def __str__(self):
        return '\n'.join((
            "Library: %s" % self.so,
            "Manufacturer ID: %s" % self.manufacturer_id,
            "Library Description: %s" % self.library_description,
            "Cryptoki Version: %s.%s" % self.cryptoki_version,
            "Library Version: %s.%s" % self.library_version,
        ))

    def __repr__(self):
        return '<pkcs11.lib ({so})>'.format(
            so=self.so)


    def get_slots(self, token_present=False):
        """Get all slots."""

        cdef CK_BBOOL present = token_present
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetSlotList(present, NULL, &count)
        assertRV(retval)

        if count == 0:
            return []

        cdef CK_SLOT_ID [:] slot_list = CK_ULONG_buffer(count)

        with nogil:
            retval = self.funclist.C_GetSlotList(present, &slot_list[0], &count)
        assertRV(retval)

        cdef CK_SLOT_ID slot_id
        cdef CK_SLOT_INFO info

        slots = []

        for slot_id in slot_list:
            with nogil:
                retval = self.funclist.C_GetSlotInfo(slot_id, &info)
            assertRV(retval)

            slots.append(
                Slot.make(self.funclist, slot_id, info, self._cryptoki_version,
                          self.funclist3, self.funclist32)
            )

        return slots


    def get_tokens(self,
                   token_label=None,
                   token_serial=None,
                   token_flags=None,
                   slot_flags=None,
                   mechanisms=None):
        """Search for a token matching the parameters."""

        for slot in self.get_slots():
            try:
                token = slot.get_token()
                token_mechanisms = slot.get_mechanisms()

                if token_label is not None and \
                        token.label != token_label:
                    continue

                if token_serial is not None and \
                        token.serial != token_serial:
                    continue

                if token_flags is not None and \
                        not token.flags & token_flags:
                    continue

                if slot_flags is not None and \
                        not slot.flags & slot_flags:
                    continue

                if mechanisms is not None and \
                        not set(mechanisms).issubset(token_mechanisms):
                    continue

                yield token
            except (TokenNotPresent, TokenNotRecognised):
                continue

    def get_token(self, **kwargs):
        """Get a single token."""
        iterator = self.get_tokens(**kwargs)

        try:
            token = next(iterator)
        except StopIteration:
            raise NoSuchToken("No token matching %s" % kwargs)

        try:
            next(iterator)
            raise MultipleTokensReturned(
                "More than 1 token matches %s" % kwargs)
        except StopIteration:
            return token

    def wait_for_slot_event(self, blocking=True):
        cdef CK_SLOT_ID slot_id
        cdef CK_FLAGS flag = 0
        cdef CK_RV retval

        if not blocking:
            flag |= CKF_DONT_BLOCK

        with nogil:
            retval = self.funclist.C_WaitForSlotEvent(flag, &slot_id, NULL)
        assertRV(retval)

        cdef CK_SLOT_INFO info

        with nogil:
            retval = self.funclist.C_GetSlotInfo(slot_id, &info)
        assertRV(retval)

        slotDescription = info.slotDescription[:sizeof(info.slotDescription)]
        manufacturerID = info.manufacturerID[:sizeof(info.manufacturerID)]

        return Slot(self, slot_id, slotDescription, manufacturerID,
                 info.hardwareVersion, info.firmwareVersion, info.flags)

    def unload(self):
        self._finalize()
        self.funclist = NULL
        if self._p11_handle != NULL:
            p11_close(self._p11_handle)
            self._p11_handle = NULL

    def __dealloc__(self):
        self.unload()
