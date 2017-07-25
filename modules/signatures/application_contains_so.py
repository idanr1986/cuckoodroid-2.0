# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os

from lib.cuckoo.common.abstracts import Signature




class ApplicationContainsSo(Signature):
    name = "application_contains_so"
    description = "Application Contains Shared Object Files (Static)"
    severity = 2
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        so_files = self.get_apkinfo("files_flaged", {}).get("so", {})
        for file in so_files:
            self.mark_ioc(file["name"], file)
        return self.has_marks()