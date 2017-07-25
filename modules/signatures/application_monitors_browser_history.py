# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class ApplicationMonitorsBrowserHistory(Signature):
    name = "application_monitors_browser_history"
    description = "Application Monitors Browser Activity (Dynamic)"
    severity = 4
    categories = ["android"]
    authors = ["idanr1986"]
    minimum = "2.0"

    def on_complete(self):

        #content://browser/bookmarks
        #content://com.android.chrome.browser/history
        #"com.android.browser.permission.READ_HISTORY_BOOKMARKS",
        for query in self.get_droidmon().get("registerContentObserver", []):
            if "content://browser/bookmarks" in query or "content://com.android.chrome.browser/history" in query:
                self.mark_ioc("Content Observer", query)
        if self.has_marks():
            for permission in self.get_apkinfo("manifest",{}).get("permissions",[]):
                if "com.android.browser.permission.READ_HISTORY_BOOKMARKS" in permission["name"]:
                    self.mark_ioc("Permission", permission["name"]+" - " + permission["description"])
        return self.has_marks()
