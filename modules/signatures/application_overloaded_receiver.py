# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class ApplicationPackageReference(Signature):
    name = "application_overloaded_receiver"
    description = "Application Contains Overloaded Broadcast Receiver (Static)"
    severity = 3
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):
        ACTION_COUNT_THRESHOLD = 5
        receivers = self.get_apkinfo("manifest").get("receivers_info", {})
        for recv in receivers:
            for intent in recv.get("intents",[]):
                if len(intent.get("actions", [])) > ACTION_COUNT_THRESHOLD:
                    self.mark_ioc(recv["name"], str(intent.get("actions", [])))

        return self.has_marks()