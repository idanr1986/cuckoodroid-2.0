# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
from androguard.core.analysis.analysis import uVMAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from lib.cuckoo.common.abstracts import Signature

class PackerGeneric(Signature):
    name = "android_packer_generic"
    description = "Application Using Packer Generic (Static)"
    severity = 3
    categories = ["android"]
    authors = ["idanr"]
    minimum = "2.0"

    def convert_class(self, cls):
        return "L"+cls.replace(".", "/")+";"

    def on_complete(self):

        receivers = self.get_results("apkinfo", {}).get("manifest", {}).get("receivers", {})
        activities = self.get_results("apkinfo", {}).get("manifest", {}).get("activities", {})
        services = self.get_results("apkinfo", {}).get("manifest", {}).get("services", {})

        app_path = self.get_results("target",{}).get("file",{}).get("path", None)

        if not app_path:
            return False

        if not os.path.exists(app_path):
            return False

        app_apk = APK(app_path)
        dvm = DalvikVMFormat(app_apk.get_dex())
        classes = set()
        for cls in dvm.get_classes():
            classes.add(cls.name)
        for receiver in receivers:
            if self.convert_class(receiver) not in classes:
                return True

        for activity in activities:
            if self.convert_class(activity) not in classes:
                return True

        for service in services:
            if self.convert_class(service) not in classes:
                return True



