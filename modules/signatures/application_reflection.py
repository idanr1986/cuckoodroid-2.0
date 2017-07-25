# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidUsingReflection(Signature):
    name = "application_reflection"
    description = "Application Uses Reflection (Dynamic)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        for query in self.get_droidmon().get("reflection_calls", []):
            self.mark_ioc("Dynamic API Call", query)
        return self.has_marks()
