"""
PKCS#11 Slots and Tokens
"""

import os
import tempfile
import unittest

import pkcs11
from pkcs11 import PKCS11Error

from . import LIB, TOKEN, Not, Only


class SlotsAndTokensTests(unittest.TestCase):
    def test_double_initialise(self):
        attempt1 = pkcs11.lib(LIB)
        attempt2 = pkcs11.lib(LIB)
        self.assertIsNotNone(attempt1)
        self.assertIsNotNone(attempt2)
        self.assertIs(attempt1, attempt2)

    def test_nonexistent_lib(self):
        with self.assertRaises(RuntimeError):
            pkcs11.lib("thislibdoesntexist.so")

    def test_double_initialise_nonexistent_lib(self):
        self.assertIsNotNone(pkcs11.lib(LIB))
        with self.assertRaises(RuntimeError):
            pkcs11.lib("somethingelse.so")

    @Only.softhsm2
    def test_get_slots(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()

        self.assertEqual(len(slots), 2)
        slot1, slot2 = slots

        self.assertIsInstance(slot1, pkcs11.Slot)
        self.assertEqual(slot1.flags, pkcs11.SlotFlag.TOKEN_PRESENT)

    def test_get_mechanisms(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        mechanisms = slot.get_mechanisms()
        self.assertIn(pkcs11.Mechanism.RSA_PKCS, mechanisms)

    def test_reinitialize(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()
        self.assertGreaterEqual(len(slots), 1)

        lib.reinitialize()

        self.assertTrue(lib.initialized)
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()
        self.assertGreaterEqual(len(slots), 1)

    def test_finalize(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()
        self.assertGreaterEqual(len(slots), 1)

        lib.finalize()
        self.assertFalse(lib.initialized)
        self.assertRaises(PKCS11Error, lib.get_slots)

    def test_auto_reinitialise(self):
        lib = pkcs11.lib(LIB)
        lib.finalize()
        self.assertFalse(lib.initialized)
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()
        self.assertGreaterEqual(len(slots), 1)

    def test_unload_reload(self):
        pkcs11.lib(LIB)
        pkcs11.unload(LIB)

        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()
        self.assertGreaterEqual(len(slots), 1)

    def test_unload_clears_explicit_interface_cache(self):
        pkcs11.unload(LIB)
        v240_lib = pkcs11.lib(LIB, interface="2.40")

        pkcs11.unload(LIB)

        reloaded = pkcs11.lib(LIB, interface="2.40")
        self.assertIsNot(v240_lib, reloaded)
        pkcs11.unload(LIB)

    @Only.softhsm2
    def test_init_token(self):
        original_conf = os.environ.get("SOFTHSM2_CONF")

        with tempfile.TemporaryDirectory() as tmpdir:
            token_dir = os.path.join(tmpdir, "tokens")
            conf = os.path.join(tmpdir, "softhsm2.conf")
            os.mkdir(token_dir)
            with open(conf, "w", encoding="ascii") as handle:
                handle.write(
                    "\n".join(
                        (
                            f"directories.tokendir = {token_dir}",
                            "objectstore.backend = file",
                            "log.level = INFO",
                            "slots.removable = false",
                        )
                    )
                )

            try:
                if original_conf is None:
                    os.environ.pop("SOFTHSM2_CONF", None)
                os.environ["SOFTHSM2_CONF"] = conf
                pkcs11.unload(LIB)

                lib = pkcs11.lib(LIB)
                slot, *_ = lib.get_slots()
                slot.init_token("INIT TOKEN", b"5678")
                token = slot.get_token()

                self.assertEqual(token.label, "INIT TOKEN")
                self.assertIn(pkcs11.TokenFlag.TOKEN_INITIALIZED, token.flags)
            finally:
                pkcs11.unload(LIB)
                if original_conf is None:
                    os.environ.pop("SOFTHSM2_CONF", None)
                else:
                    os.environ["SOFTHSM2_CONF"] = original_conf

    def test_get_mechanism_info(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        info = slot.get_mechanism_info(pkcs11.Mechanism.RSA_PKCS_OAEP)
        self.assertIsInstance(info, pkcs11.MechanismInfo)

    @Not.nfast  # EC not supported
    @Not.opencryptoki
    def test_get_mechanism_info_ec(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        info = slot.get_mechanism_info(pkcs11.Mechanism.EC_KEY_PAIR_GEN)
        self.assertIsInstance(info, pkcs11.MechanismInfo)
        self.assertIn(pkcs11.MechanismFlag.EC_NAMEDCURVE, info.flags)

    @Only.softhsm2
    def test_get_tokens(self):
        lib = pkcs11.lib(LIB)

        tokens = lib.get_tokens(token_flags=pkcs11.TokenFlag.RNG)
        self.assertEqual(len(list(tokens)), 2)

        tokens = lib.get_tokens(token_label=TOKEN)
        self.assertEqual(len(list(tokens)), 1)

    @Only.softhsm2
    def test_get_tokens_by_mechanism_subset(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label=TOKEN)
        mechanisms = tuple(token.slot.get_mechanisms())
        self.assertGreaterEqual(len(mechanisms), 1)

        tokens = list(
            lib.get_tokens(
                token_label=TOKEN,
                mechanisms=mechanisms[: min(len(mechanisms), 2)],
            )
        )
        self.assertEqual(len(tokens), 1)

    @Only.softhsm2
    def test_get_token(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        token = slot.get_token()

        self.assertIsInstance(token, pkcs11.Token)
        self.assertEqual(token.label, TOKEN)
        self.assertIn(pkcs11.TokenFlag.TOKEN_INITIALIZED, token.flags)
        self.assertIn(pkcs11.TokenFlag.LOGIN_REQUIRED, token.flags)
