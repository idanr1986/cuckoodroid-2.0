# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature


class ApplicationObfuscator(Signature):
    name = "application_obfuscator"
    description = "Application Using Obfuscator (Static)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        apkid = self.get_apkinfo("APKiD", {})
        for file_matched in apkid:
            for obfuscator in apkid[file_matched].get("obfuscator", []):
                self.mark_ioc(file_matched.replace("_", "."), obfuscator)
                ApplicationObfuscator.description = "Application Using " + obfuscator + " Obfuscator (Static)"
        return self.has_marks()
