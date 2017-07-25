# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidComponentEnabledSetting(Signature):
    name = "application_setComponentEnabledSetting"
    description = "Application Set Component Enabled Setting (Dynamic)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        for component in self.get_droidmon("ComponentEnabledSetting", []):
            self.mark_ioc("Dynamic API Call", component)
        return self.has_marks()
