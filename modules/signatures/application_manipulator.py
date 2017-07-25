# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature


class ApplicationManipulator(Signature):
    name = "application_manipulator"
    description = "Application Using Manipulator (Static)"
    severity = 2
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        apkid = self.get_apkinfo("APKiD", {})
        for file_matched in apkid:
            for manipulator in apkid[file_matched].get("manipulator", []):
                self.mark_ioc(file_matched.replace("_", "."), manipulator)
                ApplicationManipulator.description = "Application Using " + manipulator + " Manipulator (Static)"
        return self.has_marks()
