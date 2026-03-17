"""
PKCS#11 library and interface negotiation
"""

import unittest

import pkcs11

from . import LIB


class InterfaceTests(unittest.TestCase):
    def test_interface_version_reported(self):
        lib = pkcs11.lib(LIB)
        self.assertIn(lib.interface_version, ("2.40", "3.0", "3.1", "3.2"))

    def test_get_interface_list_returns_expected_shape(self):
        lib = pkcs11.lib(LIB)
        interfaces = lib.get_interface_list()

        self.assertIsInstance(interfaces, list)

        if lib.interface_version == "2.40":
            self.assertEqual(interfaces, [])
            return

        self.assertGreater(len(interfaces), 0)
        for name, major, minor in interfaces:
            self.assertIsInstance(name, str)
            self.assertIsInstance(major, int)
            self.assertIsInstance(minor, int)
