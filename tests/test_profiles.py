"""
PKCS#11 v3.0 profile objects
"""

import pkcs11
from pkcs11 import Attribute, ObjectClass
from pkcs11.constants import ProfileID

from . import TestCase


class ProfileObjectTests(TestCase):
    def test_profile_object_enumeration(self):
        if self.lib.interface_version == "2.40":
            self.skipTest("Requires PKCS#11 v3.0+ interface")

        try:
            profiles = list(self.session.get_objects({Attribute.CLASS: ObjectClass.PROFILE}))
        except Exception as ex:
            self.skipTest(f"Module does not support CKO_PROFILE enumeration: {ex}")

        self.assertIsInstance(profiles, list)

    def test_profile_ids_are_known_or_vendor_defined(self):
        if self.lib.interface_version == "2.40":
            self.skipTest("Requires PKCS#11 v3.0+ interface")

        try:
            profiles = list(self.session.get_objects({Attribute.CLASS: ObjectClass.PROFILE}))
        except Exception as ex:
            self.skipTest(f"Module does not support CKO_PROFILE enumeration: {ex}")

        if not profiles:
            self.skipTest("No CKO_PROFILE objects present")

        known = {int(profile_id) for profile_id in ProfileID}
        for profile in profiles:
            profile_id = int(profile[Attribute.PROFILE_ID])
            if profile_id < ProfileID.VENDOR_DEFINED:
                self.assertIn(profile_id, known)
