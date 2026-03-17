"""
PKCS#11 v3.x surface guards and helper APIs.
"""

import unittest

import pkcs11
from pkcs11 import Attribute, MechanismFlag, ObjectClass
from pkcs11.mechanisms import Mechanism

from . import TestCase, requires


class V3SurfaceGuardTests(TestCase):
    def _skip_if_not_guard_backend(self, *supported_versions):
        if self.lib.interface_version in supported_versions:
            raise unittest.SkipTest(
                f"Guard-path test only applies when interface is not one of {supported_versions}"
            )

    def test_open_async_requires_v32_interface(self):
        self._skip_if_not_guard_backend("3.2")

        with self.assertRaises(NotImplementedError):
            self.token.open(async_=True)

    def test_async_management_requires_v32_interface(self):
        self._skip_if_not_guard_backend("3.2")

        with self.assertRaises(NotImplementedError):
            self.session.async_complete("C_SignInit")
        with self.assertRaises(NotImplementedError):
            self.session.async_get_id("C_SignInit")
        with self.assertRaises(NotImplementedError):
            self.session.async_join("C_SignInit", 1)

    def test_message_encryption_requires_v30_interface(self):
        self._skip_if_not_guard_backend("3.0", "3.1", "3.2")

        with self.assertRaises(NotImplementedError):
            self.session.encrypt_message(b"payload")

    def test_message_sign_requires_v30_interface(self):
        self._skip_if_not_guard_backend("3.0", "3.1", "3.2")

        with self.assertRaises(NotImplementedError):
            self.session.sign_message(b"payload")

    @requires(Mechanism.AES_KEY_GEN)
    def test_verify_signature_requires_v32_interface(self):
        self._skip_if_not_guard_backend("3.2")

        key = self.session.generate_key(pkcs11.KeyType.AES, 128)

        with self.assertRaises(NotImplementedError):
            self.session.verify_signature_init(key, b"\x00" * 16)

    @requires(Mechanism.AES_KEY_GEN)
    def test_authenticated_wrap_requires_v32_interface(self):
        self._skip_if_not_guard_backend("3.2")

        wrapping_key = self.session.generate_key(
            pkcs11.KeyType.AES,
            128,
            capabilities=MechanismFlag.WRAP | MechanismFlag.UNWRAP,
        )
        key = self.session.generate_key(
            pkcs11.KeyType.AES,
            128,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

        with self.assertRaises(NotImplementedError):
            wrapping_key.wrap_key_authenticated(key)

    @requires(Mechanism.AES_KEY_GEN)
    def test_authenticated_unwrap_requires_v32_interface(self):
        self._skip_if_not_guard_backend("3.2")

        unwrapping_key = self.session.generate_key(
            pkcs11.KeyType.AES,
            128,
            capabilities=MechanismFlag.WRAP | MechanismFlag.UNWRAP,
        )

        with self.assertRaises(NotImplementedError):
            unwrapping_key.unwrap_key_authenticated(
                ObjectClass.SECRET_KEY,
                pkcs11.KeyType.AES,
                b"wrapped-key",
                b"tag",
            )
