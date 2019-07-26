import json
import os
import subprocess

class EventFinder(object):

    # Checks if a vulnerability event is present in the event set
    def containsVulnEvent(self, description, host, port, timestamp):
        search_str = 'python search.py "search '
        query = search_str + description + " SRCHOST=*" + " DSTHOST=" + host + " DSTPORT=" + str(port) + " TIMESTAMP<" + str(timestamp)
        query += '" --username="Imzai" --password="password" --output_mode=json'
        # print(query)
        os.chdir("splunk/examples")
        status, result = subprocess.getstatusoutput(query)
        json_result = json.loads(result)["results"]
        os.chdir("../..")
        if json_result == []:
            return None
        return json_result