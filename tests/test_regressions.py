import unittest

from pkcs11 import ArgumentsBad, Attribute, CancelStrategy, GeneratorFunction, MechanismFlag, MessageFlag
from pkcs11.attributes import AttributeMapper
from pkcs11.constants import ProfileID, Trust, ValidationAuthorityType, ValidationType
from pkcs11.mechanisms import (
    CCMMessageParams,
    CCMWrapParams,
    GCMMessageParams,
    GCMWrapParams,
    KeyType,
    Mechanism,
    SP800108CounterFormat,
    SP800108DKMLengthFormat,
    SP800108DKMLengthMethod,
    SP800108DataParam,
    SP800108DataType,
    SP800108FeedbackKDFParams,
    SP800108KDFParams,
)


class AttributeMapperRegressionTests(unittest.TestCase):
    def test_public_key_template_is_isolated_per_call(self):
        mapper = AttributeMapper()

        first = mapper.public_key_template(
            capabilities=MechanismFlag.ENCRYPT,
            id_=b"one",
            label="ONE",
            store=True,
        )
        second = mapper.public_key_template(
            capabilities=0,
            id_=None,
            label=None,
            store=False,
        )

        self.assertEqual(first[Attribute.ID], b"one")
        self.assertEqual(first[Attribute.LABEL], "ONE")
        self.assertTrue(first[Attribute.TOKEN])
        self.assertTrue(first[Attribute.ENCRYPT])

        self.assertEqual(second[Attribute.ID], b"")
        self.assertEqual(second[Attribute.LABEL], "")
        self.assertFalse(second[Attribute.TOKEN])
        self.assertFalse(second[Attribute.ENCRYPT])

    def test_private_key_template_is_isolated_per_call(self):
        mapper = AttributeMapper()

        first = mapper.private_key_template(
            capabilities=MechanismFlag.SIGN | MechanismFlag.DECAPSULATE,
            id_=b"two",
            label="TWO",
            store=True,
        )
        second = mapper.private_key_template(
            capabilities=0,
            id_=None,
            label=None,
            store=False,
        )

        self.assertEqual(first[Attribute.ID], b"two")
        self.assertEqual(first[Attribute.LABEL], "TWO")
        self.assertTrue(first[Attribute.TOKEN])
        self.assertTrue(first[Attribute.SIGN])
        self.assertTrue(first[Attribute.DECAPSULATE])

        self.assertEqual(second[Attribute.ID], b"")
        self.assertEqual(second[Attribute.LABEL], "")
        self.assertFalse(second[Attribute.TOKEN])
        self.assertFalse(second.get(Attribute.SIGN, False))
        self.assertNotIn(Attribute.DECAPSULATE, second)

    def test_validation_attributes_round_trip(self):
        mapper = AttributeMapper()

        validation_type = mapper.unpack_attributes(
            Attribute.VALIDATION_TYPE,
            mapper.pack_attribute(Attribute.VALIDATION_TYPE, ValidationType.HARDWARE),
        )
        validation_authority = mapper.unpack_attributes(
            Attribute.VALIDATION_AUTHORITY_TYPE,
            mapper.pack_attribute(
                Attribute.VALIDATION_AUTHORITY_TYPE,
                ValidationAuthorityType.NIST_CMVP,
            ),
        )
        validation_version = mapper.unpack_attributes(
            Attribute.VALIDATION_VERSION,
            mapper.pack_attribute(Attribute.VALIDATION_VERSION, (3, 2)),
        )
        trust_value = mapper.unpack_attributes(
            Attribute.TRUST_SERVER_AUTH,
            mapper.pack_attribute(Attribute.TRUST_SERVER_AUTH, Trust.ANCHOR),
        )

        self.assertEqual(validation_type, ValidationType.HARDWARE)
        self.assertEqual(validation_authority, ValidationAuthorityType.NIST_CMVP)
        self.assertEqual(validation_version, (3, 2))
        self.assertEqual(trust_value, Trust.ANCHOR)

    def test_template_attributes_round_trip(self):
        mapper = AttributeMapper()
        template = {
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        }

        packed = mapper.pack_attribute(Attribute.WRAP_TEMPLATE, template)
        unpacked = mapper.unpack_attributes(Attribute.WRAP_TEMPLATE, packed)

        self.assertEqual(unpacked, template)

    def test_allowed_mechanisms_round_trip(self):
        mapper = AttributeMapper()

        value = mapper.unpack_attributes(
            Attribute.ALLOWED_MECHANISMS,
            mapper.pack_attribute(
                Attribute.ALLOWED_MECHANISMS,
                [Mechanism.AES_GCM, Mechanism.AES_KEY_WRAP],
            ),
        )

        self.assertEqual(value, [Mechanism.AES_GCM, Mechanism.AES_KEY_WRAP])

    def test_hss_list_attributes_round_trip(self):
        mapper = AttributeMapper()

        lms_types = mapper.unpack_attributes(
            Attribute.HSS_LMS_TYPES,
            mapper.pack_attribute(Attribute.HSS_LMS_TYPES, [5, 6, 7]),
        )
        lmots_types = mapper.unpack_attributes(
            Attribute.HSS_LMOTS_TYPES,
            mapper.pack_attribute(Attribute.HSS_LMOTS_TYPES, [1, 2, 3]),
        )

        self.assertEqual(lms_types, [5, 6, 7])
        self.assertEqual(lmots_types, [1, 2, 3])

    def test_message_flag_and_generator_constants(self):
        self.assertEqual(MessageFlag.END_OF_MESSAGE, 0x00000001)
        self.assertEqual(GeneratorFunction.GENERATE, 0x00000001)
        self.assertEqual(GeneratorFunction.NO_GENERATE, 0x00000000)

    def test_v32_profile_and_key_type_constants(self):
        self.assertEqual(ProfileID.INVALID_ID, 0x00000000)
        self.assertEqual(ProfileID.COMPLETE_PROVIDER, 0x00000005)
        self.assertEqual(ProfileID.HKDF_TLS_TOKEN, 0x00000006)
        self.assertEqual(KeyType.POLY1305, 0x00000034)
        self.assertEqual(KeyType.AES_XTS, 0x00000035)
        self.assertEqual(KeyType.HSS, 0x00000046)
        self.assertEqual(KeyType.XMSS, 0x00000047)
        self.assertEqual(KeyType.XMSSMT, 0x00000048)

    def test_hash_based_signature_mechanisms_are_present(self):
        self.assertEqual(Mechanism.HSS_KEY_PAIR_GEN, 0x00004032)
        self.assertEqual(Mechanism.HSS, 0x00004033)
        self.assertEqual(Mechanism.XMSS_KEY_PAIR_GEN, 0x00004034)
        self.assertEqual(Mechanism.XMSSMT_KEY_PAIR_GEN, 0x00004035)
        self.assertEqual(Mechanism.XMSS, 0x00004036)
        self.assertEqual(Mechanism.XMSSMT, 0x00004037)

    def test_cancel_strategy_session_cancel_is_exposed(self):
        self.assertEqual(CancelStrategy.CANCEL_WITH_SESSION_CANCEL, 2)

    def test_gcm_message_params_coerce_mutable_buffers(self):
        params = GCMMessageParams(
            iv=b"\x00" * 12,
            tag=b"\x00" * 16,
            iv_generator=GeneratorFunction.GENERATE,
        )

        self.assertIsInstance(params.iv, bytearray)
        self.assertIsInstance(params.tag, bytearray)
        self.assertEqual(params.tag_bits, 128)
        self.assertEqual(params.iv_generator, GeneratorFunction.GENERATE)

    def test_ccm_message_params_validate_lengths(self):
        params = CCMMessageParams(
            data_len=32,
            nonce=b"\x00" * 12,
            mac=b"\x00" * 16,
            nonce_generator=GeneratorFunction.NO_GENERATE,
            mac_len=16,
        )

        self.assertIsInstance(params.nonce, bytearray)
        self.assertIsInstance(params.mac, bytearray)
        self.assertEqual(params.mac_len, 16)

        with self.assertRaises(ArgumentsBad):
            CCMMessageParams(data_len=32, nonce=b"\x00" * 12, mac=b"\x00" * 8, mac_len=16)

    def test_wrap_param_helpers_use_mutable_nonce_iv_buffers(self):
        gcm = GCMWrapParams(iv=b"\x00" * 12, aad=b"aad")
        ccm = CCMWrapParams(data_len=24, nonce=b"\x00" * 12, aad=b"aad")

        self.assertIsInstance(gcm.iv, bytearray)
        self.assertEqual(gcm.tag_bits, 128)
        self.assertIsInstance(ccm.nonce, bytearray)
        self.assertEqual(ccm.mac_len, 16)

    def test_sp800_108_helpers_validate_and_store_values(self):
        counter = SP800108CounterFormat(32, little_endian=True)
        dkm_length = SP800108DKMLengthFormat(
            SP800108DKMLengthMethod.SUM_OF_KEYS,
            16,
            little_endian=False,
        )

        params = SP800108KDFParams(
            Mechanism.SHA256_HMAC,
            [
                SP800108DataParam(SP800108DataType.ITERATION_VARIABLE, counter),
                SP800108DataParam(SP800108DataType.DKM_LENGTH, dkm_length),
                SP800108DataParam(SP800108DataType.BYTE_ARRAY, b"label"),
            ],
        )
        feedback = SP800108FeedbackKDFParams(
            Mechanism.SHA256_HMAC,
            [SP800108DataParam(SP800108DataType.BYTE_ARRAY, b"context")],
            iv=b"iv",
        )

        self.assertEqual(params.prf_type, Mechanism.SHA256_HMAC)
        self.assertEqual(len(params.data_params), 3)
        self.assertEqual(feedback.iv, b"iv")

        with self.assertRaises(ArgumentsBad):
            SP800108CounterFormat(0)
        with self.assertRaises(ArgumentsBad):
            SP800108DKMLengthFormat(SP800108DKMLengthMethod.SUM_OF_KEYS, 0)
        with self.assertRaises(ArgumentsBad):
            SP800108KDFParams(Mechanism.SHA256_HMAC, [])
