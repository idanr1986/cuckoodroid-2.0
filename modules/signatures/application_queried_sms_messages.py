# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidPrivateInfoQuery(Signature):
    name = "application_queried_sms_messages"
    description = "Application Reads Private SMS Messages (Dynamic)"
    severity = 4
    categories = ["android"]
    authors = ["idanr86"]
    minimum = "2.0"

    def on_complete(self):
        for query in self.get_droidmon().get("ContentResolver_queries", []):
            if "sms" in query:
                self.mark_ioc("Content Resolver Query", query)
        return self.has_marks()
