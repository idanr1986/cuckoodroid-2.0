# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature


class ApplicationAntiDisassembly(Signature):
    name = "application_anti_disassembly"
    description = "Application Using Anti Disassembly (Static)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        apkid = self.get_apkinfo("APKiD", {})
        for file_matched in apkid:
            for anti in apkid[file_matched].get("anti_disassembly", []):
                self.mark_ioc(file_matched.replace("_", "."), anti)
        return self.has_marks()
