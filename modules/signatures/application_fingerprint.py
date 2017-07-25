# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidFingerprint(Signature):
    name = "application_fingerprint"
    description = "Application Fingerprint (Dynamic)"
    severity = 1
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        for fingerprint in self.get_droidmon("fingerprint", []):
            self.mark_ioc("Dynamic API Call", fingerprint+"()")
        return self.has_marks()