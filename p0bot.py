from akkoma import Akkoma
import time
import httpx
import re
import json
import os
import sys
import logging
logger = logging.getLogger(__name__)
logging.basicConfig(filename='p0bot.log', level=logging.INFO)

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

ISSUES_PATH=os.path.join(dname,"issues.txt")

TOKEN_RE=re.compile("'token':\s*'([^']+)'")
CVE_RE = re.compile("CVE-[0-9]{4}-[0-9]+")

akkoma = Akkoma(access_token="app_usercred.txt", api_base_url="https://infosec.place")

r=httpx.get("https://bugs.chromium.org/p/project-zero/issues/list")
token_m=TOKEN_RE.search(r.text)
xsrf_token=token_m.group(1)
headers={"X-Xsrf-Token":xsrf_token,'Accept':"application/json", "Accept-Encoding":"identity"}
data={"projectNames":["project-zero"],"query":"","cannedQuery":1,"pagination":{"maxItems":10},"sortSpec":"-id"}
issues_r=httpx.post('https://bugs.chromium.org/prpc/monorail.Issues/ListIssues', headers=headers, json=data)
json_start=issues_r.content.find(b'{')
issues=json.loads(issues_r.content[json_start:].decode('ascii'));

saved_reports=set()

try:
    with open(ISSUES_PATH,"r") as report_file:
        report_list=[x.strip() for x in list(report_file)]
        saved_reports=set(report_list)
except FileNotFoundError:
    pass

counter=0

try:
    with open(ISSUES_PATH,"a") as db:
        for i in issues["issues"]:
            if str(i["localId"]) in saved_reports:
                continue
            url="https://bugs.chromium.org/p/project-zero/issues/detail?id=%d" % (i["localId"])
            cves=[]
            for l in i["labelRefs"]:
                if l["label"].startswith("CVE-"):
                    cves.append(l["label"])
            msg="New Project Zero issue:\n\n%s\n\n%s\n\n%s" % (i["summary"], url, ",".join(cves))
            logger.info(msg)
            akkoma.status_post(msg)
            time.sleep(5)
            db.write("%d\n" % (i["localId"]))
            # Safety check
            counter += 1
            if counter > 10:
                break 
except:
    logger.exception("Exception during posting")







