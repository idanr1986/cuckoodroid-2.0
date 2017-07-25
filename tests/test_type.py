import os
import subprocess
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat


def get_type(file_path):
        """Get MIME file type.
        @return: file type.
        """

        file_type = None
        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.file(file_path)
        except Exception as e:
            print e
            try:
                file_type = magic.from_file(file_path)
            except Exception as e:
                print("Error getting magic from file %s: %s",
                          file_path, e)
        finally:
            try:
                ms.close()
            except:
                pass

        if file_type is None:
            try:
                p = subprocess.Popen(["file", "-b", file_path],
                                     stdout=subprocess.PIPE)
                file_type = p.stdout.read().strip()
            except Exception as e:
                print("Error running file(1) on %s: %s",
                          file_path, e)

        return file_type


path = "/Users/guardianangel/Samples/drweb/bankbot/bc99204385cb8e6f709d037863f974c88a8aec9b46b939bc58539fe37383e7a8.apk"

def check_class_in_dex(dvm, receiver):
    receiver_check = "L"+receiver.replace(".", "/")+";"
    for cls in dvm.get_classes():
        if receiver_check == cls.name:
            return True
    return False


def test(app_path):

    if not app_path:
        return False

    if not os.path.exists(app_path):
        return False

    app_apk = APK(app_path)
    dvm = DalvikVMFormat(app_apk.get_dex())

    receivers = app_apk.get_receivers()
    activities = app_apk.get_activities()
    services = app_apk.get_services()

    for activity in activities:
        if not check_class_in_dex(dvm, activity):
            return True

    for receiver in receivers:
        if not check_class_in_dex(dvm, receiver):
            return True
    for service in services:
        if not check_class_in_dex(dvm, service):
            return True

    return False
print test(path)
