# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidStopProcess(Signature):
    name = "application_stopped_processes"
    description = "Application Stopped Application Processes (Dynamic)"
    severity = 4
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        for proc in self.get_droidmon().get("killed_process",[]):
            self.mark_ioc("Process", proc)
        return self.has_marks()

