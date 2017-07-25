# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class ApplicationDroppedFiles(Signature):
    name = "application_dropped_files"
    description = "Application Dropped Files (Dynamic)"
    severity = 1
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        dropped = self.get_results("dropped", [])
        for file in dropped:
            self.mark_ioc("File", file.get("name", None))

        return self.has_marks()