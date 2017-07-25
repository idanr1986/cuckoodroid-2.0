from collections import defaultdict
import hashlib
import json
import os

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
        if type(call["result"]) is unicode:
            new_call["result"] = call["result"]
        else:
            new_call["result"] = str(call["result"])
    new_call["args"] = list()

    if "args" in call:

        for arg in call["args"]:
            if type(arg) is unicode:
                new_call["args"].append(arg)
            else:
                new_call["args"].append(str(arg))
    if "this" in call:
        if type(call["this"]) is unicode:
            new_call["this"] = call["this"]
        else:
            new_call["this"] = str(call["this"])

    if "reflection" in call["type"]:
        new_call["class"] = call["hooked_class"]
        new_call["method"] = call["hooked_method"]
    return new_call

results = {}
log_path = "/Users/guardianangel/GitHub/cuckoo/storage/analyses/3/logs/droidmon.log"
threads = defaultdict(list)
for line in open(log_path, "rb"):
    try:
        api_call = json.loads(line.replace("$", "_"))
        thread_id = api_call["thread_id"]
        threads[thread_id].append(api_call)
    except Exception:
        if line != "\n":
            print ("Invalid JSON line: %r" % line)

for t in threads:
    threads[t] = sorted(threads[t], key=lambda k: k['timestamp'])

new_threads = defaultdict(list)
for t in threads:
    last_hash = ""
    getRunningTasks_count = 0
    getRunningTasks_call = None
    for call in threads[t]:
        new_call = flatten_apicall(call)
        hash_code = hashlib.md5(str(new_call)).hexdigest()
        if "getRunningTasks" in new_call["method"]:
            if getRunningTasks_count == 0:
                getRunningTasks_call = new_call
            getRunningTasks_count += 1
            continue
        if hash_code != last_hash:
            new_threads[t].append(new_call)
        last_hash = hash_code
    if getRunningTasks_call:
        getRunningTasks_call["count"] = getRunningTasks_count
        new_threads[t].append(getRunningTasks_call)

with open('threads.json', 'w') as outfile:
    json.dump(new_threads, outfile,indent=4)