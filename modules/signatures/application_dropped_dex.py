# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class ApplicationDroppedDex(Signature):
    name = "application_dropped_dex"
    description = "Application Dropped Dex File (Dynamic)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        dropped_dex = self.get_droidmon("dropped_dex", [])
        for dex in dropped_dex:
            if "/system/" not in dex:
                self.mark_ioc("File", dex)
        return self.has_marks()

