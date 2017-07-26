# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.
from collections import defaultdict

import json
import logging
import os
import hashlib

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class Droidmon(Processing):
    """Extract Dynamic API calls Info From Droidmon logs."""

    def __init__(self):
        self.key = "droidmon"

        self.droidmon = {}

        self.droidmon["accounts"] = set()
        self.droidmon["api"]= defaultdict(int)
        self.droidmon["assets_open"] = set()
        self.droidmon["commands"] = set()
        self.droidmon["commands_output"] = set()
        self.droidmon["ComponentEnabledSetting"] = []
        self.droidmon["connected_urls"] = set()
        self.droidmon["ContentResolver_queries"] = set()
        self.droidmon["ContentValues"] = []
        self.droidmon["crypto_data"] = set()
        self.droidmon["crypto_keys"] = []
        self.droidmon["data_leak"] = set()
        self.droidmon["decoded_base64"] = []
        self.droidmon["DexClassLoader"] = []
        self.droidmon["DexFile"] = []
        self.droidmon["dropped_dex"] = set()
        self.droidmon["dropped_so"] = set()
        self.droidmon["encoded_base64"] = []
        self.droidmon["error"] = []
        self.droidmon["events"] = set()
        self.droidmon["file_accessed"] = set()
        self.droidmon["findLibrary"] = []
        self.droidmon["findResource"] = []
        self.droidmon["fingerprint"] = set()
        self.droidmon["get_system_services"] = set()
        self.droidmon["handleReceiver"] = []
        self.droidmon["httpConnections"] = []
        self.droidmon["killed_process"] = []
        self.droidmon["loadClass"] = set()
        self.droidmon["loadDex"] = set()
        self.droidmon["logs"] = []
        self.droidmon["mac_data"] = []
        self.droidmon["PathClassLoader"] = []
        self.droidmon["raw"] = []
        self.droidmon["reflected_api"] = defaultdict(int)
        self.droidmon["reflection_calls"] = set()
        self.droidmon["registerContentObserver"] = set()
        self.droidmon["registered_receivers"] = set()
        self.droidmon["sendBroadcast"] = set()
        self.droidmon["setMobileDataEnabled"] = set()
        self.droidmon["SharedPreferences"] = []
        self.droidmon["sleep"] = []
        self.droidmon["sms"] = []
        self.droidmon["started_activities"] = set()
        self.droidmon["started_services"] = set()
        self.droidmon["SystemProperties"] = set()
        self.droidmon["TelephonyManager_listen"] = set()
        self.droidmon["types"]= defaultdict(int)


    def _handle_android_os_SystemProperties_get(self, api_call):
        self.droidmon["SystemProperties"].add(api_call["args"][0])

    def _handle_javax_crypto_spec_SecretKeySpec_javax_crypto_spec_SecretKeySpec(self, api_call):
        key = api_call["args"][0]
        for current_key in self.droidmon["crypto_keys"]:
            if key in current_key["key"]:
                break
        else:
            self.droidmon["crypto_keys"].append({
                "key": api_call["args"][0],
                "type": api_call["args"][1],
            })

    def _handle_javax_crypto_Cipher_doFinal(self, api_call):
        if "mode" in api_call["this"]:
            if api_call["this"]["mode"] == 1:
                self.droidmon["crypto_data"].add(api_call["args"][0])
            else:
                self.droidmon["crypto_data"].add(api_call["result"])
        else:
            self.droidmon["crypto_data"].add(api_call["result"])

    def _handle_java_lang_reflect_Method_invoke(self, api_call):
        reflection = ""
        if "hooked_class" in api_call:
            reflection = api_call["hooked_class"]+"->"+api_call["hooked_method"]
        else:
            reflection = api_call["hooked_method"]
        self.droidmon["reflection_calls"].add(reflection)

    def _handle_dalvik_system_BaseDexClassLoader_findResource(self, api_call):
        self.lib_pairs(api_call, "findResource")

    def _handle_android_app_Activity_startActivity(self, api_call):
        if "act" in api_call["args"][0]:
            self.droidmon["started_activities"].add(api_call["args"][0]["act"])
        elif "cmp" in api_call["args"][0]:
            self.droidmon["started_activities"].add(api_call["args"][0]["cmp"])

    def _handle_java_lang_Runtime_exec(self, api_call):
        command = api_call["args"][0]
        if type(command) is list:
            self.droidmon["commands"].add(' '.join(command))
        else:
            self.droidmon["commands"].add(command)

    def _handle_java_lang_ProcessBuilder_start(self, api_call):
        command = api_call["this"]["command"]
        self.droidmon["commands"].add(' '.join(command))

    def _handle_libcore_io_IoBridge_open(self, api_call):
        file_name = api_call["args"][0]
        if "/data/misc/keychain/pins" not in file_name and ".DROPPED_FILE" not in file_name:
            self.droidmon["file_accessed"].add(file_name)

    def _handle_android_app_ActivityThread_handleReceiver(self, api_call):
        self.droidmon["handleReceiver"].append(api_call["args"][0])

    def _handle_android_app_ContextImpl_registerReceiver(self, api_call):
        for arg in api_call["args"]:
            if "mActions" in arg:
                for action in arg["mActions"]:
                    self.droidmon["registered_receivers"].add(action)

    def _handle_android_telephony_TelephonyManager_getDeviceId(self, api_call):
        self.droidmon["fingerprint"].add("getDeviceId")

    def _handle_android_telephony_TelephonyManager_getNetworkOperatorName(self, api_call):
        self.droidmon["fingerprint"].add("getNetworkOperatorName")

    def _handle_android_telephony_TelephonyManager_getSubscriberId(self, api_call):
        self.droidmon["fingerprint"].add("getSubscriberId")

    def _handle_android_telephony_TelephonyManager_getLine1Number(self, api_call):
        self.droidmon["fingerprint"].add("getLine1Number")

    def _handle_android_telephony_TelephonyManager_getNetworkOperator(self, api_call):
        self.droidmon["fingerprint"].add("getNetworkOperator")

    def _handle_android_telephony_TelephonyManager_getSimOperatorName(self, api_call):
        self.droidmon["fingerprint"].add("getSimOperatorName")

    def _handle_android_telephony_TelephonyManager_getSimCountryIso(self, api_call):
        self.droidmon["fingerprint"].add("getSimCountryIso")

    def _handle_android_telephony_TelephonyManager_getSimSerialNumber(self, api_call):
        self.droidmon["fingerprint"].add("getSimSerialNumber")

    def _handle_android_telephony_TelephonyManager_getNetworkCountryIso(self, api_call):
        self.droidmon["fingerprint"].add("getNetworkCountryIso")

    def _handle_android_telephony_TelephonyManager_getDeviceSoftwareVersion(self, api_call):
        self.droidmon["fingerprint"].add("getDeviceSoftwareVersion")

    def _handle_android_net_wifi_WifiInfo_getMacAddress(self, api_call):
        self.droidmon["fingerprint"].add("getMacAddress")

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putInt(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putString(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putFloat(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putBoolean(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putLong(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_content_ContentResolver_query(self, api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def _handle_android_content_ContentValues_put(self, api_call):
        self.droidmon["ContentValues"].append(self.get_pair(api_call))

    def _handle_javax_crypto_Mac_doFinal(self, api_call):
        if len(api_call["args"]) > 0:
            self.droidmon["mac_data"].append(api_call["args"][0])
        else:
            if api_call["result"]:
                self.droidmon["mac_data"].append(api_call["result"])

    def _handle_android_util_Base64_encodeToString(self, api_call):
        self.droidmon["encoded_base64"].append(api_call["args"][0])

    def _handle_android_util_Base64_encode(self, api_call):
        self.droidmon["encoded_base64"].append(api_call["result"][0])

    def _handle_android_app_ApplicationPackageManager_setComponentEnabledSetting(self, api_call):
        states = {
            "0": "COMPONENT_ENABLED_STATE_DEFAULT",
            "1": "COMPONENT_ENABLED_STATE_ENABLED",
            "2": "COMPONENT_ENABLED_STATE_DISABLED",
        }

        component = api_call["args"][0]
        state = api_call["args"][1]

        self.droidmon["ComponentEnabledSetting"].append({
            "component_name": component["mPackage"]+"/"+component["mClass"],
            "component_new_state": states.get(state, ""),
        })

    def _handle_android_location_Location_getLatitude(self, api_call):
        self.droidmon["data_leak"].add("location")

    def _handle_android_location_Location_getLongitude(self, api_call):
        self.droidmon["data_leak"].add("location")

    def _handle_android_app_ApplicationPackageManager_getInstalledPackages(self, api_call):
        self.droidmon["data_leak"].add("getInstalledPackages")

    def _handle_dalvik_system_BaseDexClassLoader_findLibrary(self, api_call):
        self.lib_pairs(api_call, "findLibrary")

    def _handle_android_telephony_SmsManager_sendTextMessage(self, api_call):
        self.droidmon["sms"].append({
            "dest_number": api_call["args"][0],
            "content": " ".join(api_call["args"][1]),
        })

    def _handle_android_util_Base64_decode(self, api_call):
        self.droidmon["decoded_base64"].append(api_call["result"])

    def _handle_android_telephony_TelephonyManager_listen(self, api_call):
        description = {
            1: "LISTEN_SERVICE_STATE",
            16: "LISTEN_CELL_LOCATION",
            32: "LISTEN_CALL_STATE",
            64: "LISTEN_DATA_CONNECTION_STATE",
            256: "LISTEN_SIGNAL_STRENGTHS",
        }

        event = api_call["args"][1]
        if event in description:
            self.droidmon["TelephonyManager_listen"].add(description[event])

    def _handle_android_content_ContentResolver_registerContentObserver(self, api_call):
        self.droidmon["registerContentObserver"].add(api_call["args"][0]["uriString"])

    def _handle_android_content_ContentResolver_insert(self, api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def _handle_android_accounts_AccountManager_getAccountsByType(self, api_call):
        self.droidmon["accounts"].add(api_call["args"][0])
        self.droidmon["data_leak"].add("getAccounts")

    def _handle_dalvik_system_BaseDexClassLoader_findResources(self, api_call):
        self.lib_pairs(api_call, "findResource")

    def _handle_android_accounts_AccountManager_getAccounts(self, api_call):
        self.droidmon["data_leak"].add("getAccounts")

    def _handle_android_telephony_SmsManager_sendMultipartTextMessage(self, api_call):
        self.droidmon["sms"].append({
            "dest_number": api_call["args"][0],
            "content": api_call["args"][1][0],
        })

    def _handle_android_content_ContentResolver_delete(self, api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def _handle_android_media_AudioRecord_startRecording(self, api_call):
        self.droidmon["events"].add("mediaRecorder")

    def _handle_android_media_MediaRecorder_start(self, api_call):
        self.droidmon["events"].add("mediaRecorder")

    def _handle_android_content_BroadcastReceiver_abortBroadcast(self, api_call):
        self.droidmon["events"].add("abortBroadcast")

    def _handle_dalvik_system_DexFile_loadDex(self, api_call):
        self.droidmon["loadDex"].add(api_call["args"][0])

    def _handle_dalvik_system_DexClassLoader_dalvik_system_DexClassLoader(self, api_call):
        self.droidmon["DexClassLoader"].append(api_call["args"][0])

    def _handle_dalvik_system_DexFile_dalvik_system_DexFile(self, api_call):
        self.droidmon["DexFile"].append(api_call["args"])

    def _handle_dalvik_system_PathClassLoader_dalvik_system_PathClassLoader(self, api_call):
        for arg in api_call["args"]:
            if type(arg) is str:
                self.droidmon["PathClassLoader"].append(api_call["args"])

    def _handle_android_app_ActivityManager_killBackgroundProcesses(self, api_call):
        self.droidmon["killed_process"].append(api_call["args"][0])

    def _handle_android_os_Process_killProcess(self, api_call):
        self.droidmon["killed_process"].append(api_call["args"][0])

    def _handle_android_net_ConnectivityManager_setMobileDataEnabled(self, api_call):
        self.droidmon["setMobileDataEnabled"].add(api_call["args"][0])

    def _handle_java_lang_Thread_sleep(self, api_call):
        self.droidmon["sleep"].append({"sleep":api_call["args"][0],"process_id":api_call["process_id"]})
    
    def _handle_org_apache_http_impl_client_AbstractHttpClient_execute(self, api_call):
        json = {}
        if type(api_call["args"][0]) is dict:
            json["request"] = api_call["args"][1]
        else:
            json["request"] = api_call["args"][0]
        json["response"] = api_call["result"]
        self.droidmon["httpConnections"].append(json)

    def _handle_java_net_URL_openConnection(self, api_call):
        if("file:" in api_call["this"] or "jar:" in api_call["this"]):
            return

        json = {}
        if api_call["result"] != "":
            json["request"] = api_call["result"]["request_method"] + " " + api_call["this"] + " " + api_call["result"]["version"]
            json["response"] = api_call["result"]["version"] + " " + str(api_call["result"]["response_code"]) + " " + api_call["result"]["response_message"]
        else:
            json["request"] = "GET " + api_call["this"] + " HTTP/1.1"
            json["response"] = ""
        self.droidmon["httpConnections"].append(json)

    def _handle_dalvik_system_DexFile_loadClass(self, api_call):
        self.droidmon["loadClass"].add(api_call["args"][0])

    def _handle_java_io_FileOutputStream_write(self, api_call):
        # self.droidmon["command_objects"].append(api_call)
        commands = api_call["buffer"].split('\n')
        for command in commands:
            self.droidmon["commands"].add(command)

    def _handle_java_io_FileInputStream_read(self, api_call):
        pass
        # self.droidmon["command_objects"].append(api_call)
        self.droidmon["commands_output"].add("read: "+api_call["buffer"])

    def _handle_dalvik_system_DexFile_openDexFile(self, api_call):
        self.droidmon["dropped_dex"].add(api_call["orig"])

    def _handle_java_lang_Runtime_load(self, api_call):
        self.droidmon["dropped_so"].add(api_call["orig"])

    def _handle_android_util_Log_d(self, api_call):
        self.droidmon["logs"].append(api_call["args"][1])

    def _handle_android_util_Log_e(self, api_call):
        self.droidmon["logs"].append(api_call["args"][1])

    def _handle_java_io_File_exists(self, api_call):
        self.droidmon["file_accessed"].add(api_call["this"]["path"])

    def _handle_android_app_ContextImpl_getSystemService(self, api_call):
        self.droidmon["get_system_services"].add(api_call["args"][0])

    def _handle_android_app_Activity_onCreate(self, api_call):
        pass

    def _handle_android_app_Activity_onDestroy(self, api_call):
        pass

    def _handle_android_app_Service_onCreate(self, api_call):
        pass

    def _handle_android_content_ContextWrapper_startService(self, api_call):
        self.droidmon["started_services"].add(api_call["args"][0]["cmp"])

    def _handle_android_content_ContextWrapper_startActivity(self, api_call):
        if "act" in api_call["args"][0]:
            self.droidmon["started_activities"].add(api_call["args"][0]["act"])
        elif "cmp" in api_call["args"][0]:
            self.droidmon["started_activities"].add(api_call["args"][0]["cmp"])

    def _handle_android_content_ContextWrapper_sendBroadcast(self, api_call):
        self.droidmon["sendBroadcast"].add(api_call["args"][0]["act"])

    def _handle_java_net_ProxySelectorImpl_select(self, api_call):
        self.droidmon["connected_urls"].add(api_call["args"][0])   
    
    def _handle_android_provider_Settings_Secure_getString(self, api_call):
        self.droidmon["fingerprint"].add("Secure_getString")   

    def _handle_android_content_res_AssetManager_open(self, api_call):
        self.droidmon["file_accessed"].add("assets/"+api_call["args"][0])
        self.droidmon["assets_open"].add(api_call["args"][0])
    
    def _handle_android_content_ContextWrapper_openFileOutput(self, api_call):
        pass
    
    def get_pair(self, api_call):
        value = None
        if len(api_call["args"]) > 1:
            value = api_call["args"][1]

        return {
            "key": api_call["args"][0],
            "value": value,
        }

    def lib_pairs(self, api_call, key):
        libname = api_call["args"][0]
        for current_key in self.droidmon[key]:
            if libname in current_key["libname"]:
                break
        else:
            self.droidmon[key].append({
                "libname": api_call["args"][0],
                "result": api_call.get("result", ""),
            })

    def keyCleaner(self, d):
        if type(d) is dict:
            for key, value in d.iteritems():
                d[key] = self.keyCleaner(value)
                if '.' in key:
                    d[key.replace('.', '_')] = value
                    del(d[key])
            return d
        if type(d) is list:
            return map(self.keyCleaner, d)
        if type(d) is tuple:
            return tuple(map(self.keyCleaner, d))
        return d

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
        """

        if "file" not in self.task["category"]:
            return self.droidmon

        results = {}
        log_path = self.logs_path + "/droidmon.log"
        if not os.path.exists(log_path):
            return results

        for line in open(log_path, "rb"):
            try:
                api_call = json.loads(line.replace("$", "_"))
            except Exception:
                if line != "\n":
                    self.droidmon["error"].append("Invalid JSON line: %r" % line)
                continue
            self.droidmon["api"][(api_call["class"]+"_"+api_call["method"]).replace(".", "_")] += 1
            if "invoke" in api_call["method"]:
                self.droidmon["reflected_api"][(api_call["hooked_class"]+"_"+api_call["hooked_method"]).replace(".", "_")] += 1
            self.droidmon["types"][api_call["type"]] += 1

            if "raw" in self.options:
                if self.options.raw:
                    self.droidmon["raw"].append(self.keyCleaner(api_call))

            # Construct the function name of the handler for this event.
            api = "_handle_%s_%s" % (api_call["class"], api_call["method"])

            fn = getattr(self, api.replace(".", "_"), None)
            if fn:
                try:
                    fn(api_call)
                except Exception as e:
                    log.warning("problem handling "+api+":"+e.message)
            else:
                self.droidmon["error"].append("Unhandled: %r" % line)

        for key, value in self.droidmon.items():
            if type(value) is set:
                results[key] = list(value)
            else:
                results[key] = value
        results["threads_tree"] = get_threads(log_path)
        return results


def parse_object(obj):
    if type(obj) is unicode:
        return obj
    else:
        new_str = str(obj)
        return new_str[:75]





def flatten_apicall(call):
    new_call = {}
    #new_call["timestamp"] = call["timestamp"]
    new_call["thread_id"] = call["thread_id"]
    new_call["type"] = call["type"]
    new_call["class"] = call["class"]

    new_call["method"] = call["method"]
    new_call["result"] = ""
    new_call["this"] = ""

    if "result" in call:
        new_call["result"] = parse_object(call["result"])
    new_call["args"] = list()

    if "args" in call:
        for arg in call["args"]:
            new_call["args"].append(parse_object(arg))
    if "this" in call:
        new_call["this"] = parse_object(call["this"])

    if "reflection" in call["type"]:
        new_call["class"] = call["hooked_class"]
        new_call["method"] = call["hooked_method"]

    new_call["class_name"] = new_call["class"].split(".")[-1].split("_")[0]
    return new_call

def get_threads(log_path):
    threads = defaultdict(list)
    for line in open(log_path, "rb"):
        try:
            api_call = json.loads(line.replace("$", "_"))
            thread_id = api_call["thread_id"]
            threads[thread_id].append(api_call)
        except Exception:
            if line != "\n":
                log.warning("Invalid JSON line: %r" % line)

    for t in threads:
        threads[t] = sorted(threads[t], key=lambda k: k['timestamp'])

    new_threads = defaultdict(list)
    for t in threads:
        last_hash = ""
        for call in threads[t]:
            new_call = flatten_apicall(call)
            hash_code = hashlib.md5(str(new_call)).hexdigest()
            if "exists" in new_call["method"] :
                if "shared_prefs" in new_call["this"]:
                    continue
            if "open" in new_call["method"]:
                found = False
                for arg in new_call["args"]:
                    if "shared_prefs" in arg or "keychain" in arg:
                        found = True
                        break
                if found:
                    continue
            if hash_code != last_hash:
                new_threads[str(t)].append(new_call)
            last_hash = hash_code

    return new_threads
