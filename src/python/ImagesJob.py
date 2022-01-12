import os
from urllib.parse import urlencode
from urllib import request
import requests
import json
import time
import sys
from CheckImage import check_image_grype
import logging
import http.client as http_client


#http_client.HTTPConnection.debuglevel = 1
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

with open(sys.argv[1],'r') as token_file:
    token = token_file.read().replace('\n','')

crd_url = sys.argv[2]

ca_url = None

if len(sys.argv) == 4:
    ca_url = sys.argv[3]

if (ca_url == None) :
    r = requests.get(crd_url,headers={"Authorization":"Bearer " + token})
else :
    r = requests.get(crd_url,headers={"Authorization":"Bearer " + token},verify=ca_url)


images = json.loads(r.text)

for image in images[u'spec'][u'images']:
    print(image[u'url'])
    check_image_grype(image[u'url'],image[u'webhook'])

