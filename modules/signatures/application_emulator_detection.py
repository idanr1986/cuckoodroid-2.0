# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature


class ApplicationEmulatorDetection(Signature):
    name = "application_emulator_detection"
    description = "Application Using Emulation Detection (Static)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        strings = self.get_apkinfo("interesting_strings", {}).get("emulator", [])
        for string in strings:
            self.mark_ioc("String", string)
        apkid = self.get_apkinfo("APKiD", {})
        for file_matched in apkid:
            for anti_vm in apkid[file_matched].get("anti_vm", []):
                self.mark_ioc("APKiD Rule", anti_vm)
        return self.has_marks()
