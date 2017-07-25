# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature


class ApplicationPacker(Signature):
    name = "application_packer"
    description = "Application Using Packer (Static)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        apkid = self.get_apkinfo("APKiD", {})
        for file_matched in apkid:
            for packer in apkid[file_matched].get("packer", []):
                self.mark_ioc(file_matched.replace("_", " ."), packer)
                ApplicationPacker.description = "Application Using " + packer + " Packer (Static)"
        return self.has_marks()
