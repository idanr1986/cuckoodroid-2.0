# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidNativeCode(Signature):
    name = "android_native_code"
    description = "Application Uses Native Jni Methods (Static)"
    severity = 2
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        if self.get_apkinfo("static_method_calls").get("is_native_code"):
            for call in self.get_apkinfo("static_method_calls", []).get("native_method_calls", []):
                self.mark_ioc("Static API Call", call)
            return True
