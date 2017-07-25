# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os

from lib.cuckoo.common.abstracts import Signature




class ApplicationContainsArm(Signature):
    name = "application_contains_arm_binaries"
    description = "Application Contains ARM Binaries (Static)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        arm_exe_files = self.get_apkinfo("files_flaged", {}).get("arm_exe", {})
        for file in arm_exe_files:
            self.mark_ioc(file["name"], file)
        return self.has_marks()

