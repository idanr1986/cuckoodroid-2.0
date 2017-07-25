# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
from lib.api.adb import dump_droidmon_logs, execute_sample, install_sample,execute_service,find_pid,\
    crash_check,ui_crash_check,log_app_logs,crash_check_2

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooCrashError

log = logging.getLogger()

class Apk(Package):
    """Apk analysis package."""
    def __init__(self, options={}):
        super(Apk, self).__init__(options)

        self.package, self.activity, self.service = options.get("apk_entry", ":").split(":")
        log_message = "package: %s activity: %s service: %s" % (self.package, self.activity, self.service)
        self.pid = None
        self.crash = False
        log.info(log_message)

    def start(self, path):
        install_sample(path)
        if self.activity != "":
            execute_sample(self.package, self.activity)
        else:
            execute_service(self.package, self.service)

    def check(self):
        if not self.pid:
            self.pid = find_pid(self.package)

        if self.pid:
            if crash_check(self.pid) or crash_check_2(self.pid):
                self.crash = True
                return False
        return True

    def finish(self):
        dump_droidmon_logs(self.package)
        #ui_crash_check(self.package)
        #if self.pid:
        #    log_app_logs(self.pid)
        if self.crash:
            raise CuckooCrashError("Application Crashed during Analysis")
        return True
