# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ApplicationContainsEncryptedAssets(Signature):
    name = "application_contains_encrypted_assets"
    description = "Application Contains Encrypted Assets (Static)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        for asset in self.get_apkinfo("encrypted_assets", {}):
            self.mark_ioc(asset["name"], "entropy : "+str(asset["entropy"]))
        return self.has_marks()
