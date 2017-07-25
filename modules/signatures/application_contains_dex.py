# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os

from lib.cuckoo.common.abstracts import Signature




class ApplicationContainsDex(Signature):
    name = "application_contains_dex"
    description = "Application Contains Secondary DEX File (Static)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        dex_files = self.get_apkinfo("files_flaged", {}).get("dex", {})
        for file in dex_files:
            self.mark_ioc(file["name"], file)
        return self.has_marks()

