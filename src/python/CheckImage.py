
import os
from urllib.parse import urlencode
from urllib import request
import requests
import json
import time

def check_image(image_tag,webhook_url):
    print("Checking image %s" % image_tag)

    anchore_url = os.environ['ANCHORE_CLI_URL']
    anchore_user = os.environ['ANCHORE_CLI_USER']
    anchore_password = os.environ['ANCHORE_CLI_PASS']

    image_name_url = "%s/images?%s&history=false" % (anchore_url,  urlencode({"fulltag":image_tag}))

    image_repo = image_tag[0:image_tag.find(':')]
    print(image_repo)

    r = requests.get(image_name_url, auth=(anchore_user, anchore_password))
    
    if r.status_code == 404:
        print("no image, importing")
        r = requests.post(url="%s/repositories?repository=%s&autosubscribe=True" % (anchore_url , image_repo),auth=(anchore_user, anchore_password))
        if r.status_code == 200:
            print("imported")

            analyzed = False
            num_tries = 100;
            while not analyzed or num_tries <= 100:
                print("Sleeping...")
                time.sleep(10)
                print("...awake")

                r = requests.get(image_name_url, auth=(anchore_user, anchore_password))
                json_of_tag_data = r.text
                tag_data = json.loads(json_of_tag_data)

                analyzed = tag_data[0][u'analysis_status'] == "analyzed"
                num_tries = num_tries + 1
            if analyzed:
                print("import complete")
            else:
                print("import failed")
                return


        else:
            print("import failed")
            print(r.text)
            return
    else:
        json_of_tag_data = r.text
        tag_data = json.loads(json_of_tag_data)

    tag_digest = tag_data[0]["imageDigest"]

    vul_url = "%s/images/%s/vuln/os?vendor_only=True" % (anchore_url,tag_digest)

    r = requests.get(vul_url, auth=(anchore_user, anchore_password))

    tag_cve_data = json.loads(r.text)
    
    cves = tag_cve_data["vulnerabilities"]
    fixes_available = False
    for cve in cves:
        if (cve[u"fix"] != "None"):
            fixes_available = True

    if fixes_available:
        print("Updates to %s available, rebuilding" % image_tag)
        r = requests.post(webhook_url)
        print(r.text)
        

        


    
