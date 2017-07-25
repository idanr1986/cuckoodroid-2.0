# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class ApplicationDroppedSo(Signature):
    name = "application_dropped_so"
    description = "Application Dropped Shared Object File (Dynamic)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        dropped_dex = self.get_droidmon("dropped_so", [])
        for so in dropped_dex:
            self.mark_ioc("File", so)
        return self.has_marks()