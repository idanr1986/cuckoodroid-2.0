# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os

from lib.cuckoo.common.abstracts import Signature




class ApplicationContainsJar(Signature):
    name = "application_contains_jar"
    description = "Application Contains Jar File (Static)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        jar_files = self.get_apkinfo("files_flaged", {}).get("jar", {})
        for file in jar_files:
            self.mark_ioc(file["name"], file)
        return self.has_marks()