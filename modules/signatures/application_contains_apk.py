# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ApplicationContainsApk(Signature):
    name = "application_contains_apk"
    description = "Application Contains APK (Static)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        for apk in self.get_apkinfo("files_flaged", {}).get("apk", []):
            self.mark_ioc("File", apk)
        return self.has_marks()
