# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidSMS(Signature):
    name = "application_sent_sms_messages"
    description = "Application Sending SMS messages (Dynamic)"
    severity = 4
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        for sms in self.get_droidmon().get("sms",[]):
            self.mark_ioc(sms["dest_number"], sms["content"])
        return self.has_marks()