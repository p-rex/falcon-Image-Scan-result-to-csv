from falconpy import ContainerImages
from falconpy import ContainerPackages

import os
import pandas as pd
import datetime



##---------------------------------------------------
## classes
##---------------------------------------------------

class ImageScanResultBase:
    def getResources(self):
        return self.resources
    
    def loopRequest(self, show_progress=True):
        self.offset_cnt = 0
        self.total_cnt = 100 #just tempolary number to start the while loop. 


        while self.offset_cnt < self.total_cnt:
            resp = self.request()
            if(resp['status_code'] != 200):
                print('Not 200OK')
                exit()

            self.resources.extend(resp['body']['resources'])
            self.total_cnt = resp['body']['meta']['pagination']['total']
            limit_cnt = resp['body']['meta']['pagination']['limit']
            self.offset_cnt += limit_cnt

            if(show_progress):
                showProgress(self.offset_cnt, self.total_cnt)

    # for override
    def request(self):
        return



class Images(ImageScanResultBase):
    def __init__(self, falcon_client_id, falcon_client_secret):
        self.resources = [] # Store values of resources section
        self.falcon = ContainerImages(client_id=falcon_client_id, client_secret=falcon_client_secret)
        self.loopRequest()


    def getImageList(self):
        return self.getResources()
    
    def request(self):
#        print('offset', self.offset_cnt)
        return self.falcon.get_combined_images(offset=self.offset_cnt,
                                                sort="first_seen"
                                                )

class Packages(ImageScanResultBase):
    def __init__(self, falcon_client_id, falcon_client_secret):
        self.falcon = ContainerPackages(client_id=falcon_client_id, client_secret=falcon_client_secret)


    def getPackageList(self, digest):
        self.resources = []
        self.filter = f'image_digest:\'{digest}\''   #filter FQL image_digest:'aaaaa'
        self.loopRequest(False)
        return self.getResources()

    def request(self):
        return self.falcon.read_combined(
                                filter=self.filter,
                                only_zero_day_affected=False,
                                offset=self.offset_cnt,
#                                sort="package_name_version"
                                )




##---------------------------------------------------
## functions
##---------------------------------------------------
def showProgress(current, total):
    if(total < current):
        current = total
    print(f"Progress: {current}/{total}", end='\r')

def showMsg(msg, category='primary'):
    if(category == 'primary'):
        print('')
        print(f'=== {msg} ===')
    if(category == 'secondary'):
        print(msg)

def writeToCSV(data, filename):
    df = pd.json_normalize(data)
    df.to_csv(filename, index=False, encoding='utf-8')


##---------------------------------------------------
## main
##---------------------------------------------------

#Set API Credential
falcon_client_id = os.environ['FALCON_CLIENT_ID']
falcon_client_secret = os.environ['FALCON_CLIENT_SECRET']


showMsg('Get Images via API')
img = Images(falcon_client_id, falcon_client_secret)
image_list = img.getImageList()



showMsg('Get Vlulnerable Image digest')
vulnerable_image_digests = []
for image in image_list:
    if(image['vulnerabilities']):
        vulnerable_image_digests.append(image['image_digest'])

#IMDL check if there are vulnerable_image_digest
vulnerable_image_digests = list(set(vulnerable_image_digests))
vulnerable_image_digests_cnt = len(vulnerable_image_digests)
showMsg('Number of unique vulnerable image digest:' + str(vulnerable_image_digests_cnt), 'secondary')


showMsg('Get packages via API')
package_dict = {}
pkg = Packages(falcon_client_id, falcon_client_secret)
for i, image_digest in enumerate(vulnerable_image_digests):
    showProgress(i+1, vulnerable_image_digests_cnt)
    package_dict[image_digest] = pkg.getPackageList(image_digest)



showMsg('Merge image and package')
vuln_all = []
for image in image_list:

    if not image['vulnerabilities']:
        continue

    if not package_dict[image['image_digest']]: #If there are vulns, there should be packages
        exit('Failed. check script')

    for package in package_dict[image['image_digest']]:
        if not package['vulnerabilities']:
            continue

        for vul in package['vulnerabilities']:
            vuln_line = {}
            #from images
            vuln_line['registry']  = image['registry']
            vuln_line['repository'] = image['repository']
            vuln_line['tag'] = image['tag']
            vuln_line['base_os'] = image['base_os']
            vuln_line['image_id'] = image['image_id']
            vuln_line['image_digest'] = image['image_digest']

            #from packages
            vuln_line['type'] = package['type']
            vuln_line['package_name_version'] = package['package_name_version']
            vuln_line['cveid'] = vul['cveid']
            vuln_line['severity']  = vul['severity']
            vuln_line['description']  = vul['description'] 
            vuln_line['fix_resolution']  = vul['fix_resolution'] #IMCL This type is list. multiple resolution may exist

            vuln_all.append(vuln_line)



showMsg('Output to CSV')
dt_now = datetime.datetime.now()
filename = dt_now.strftime('%Y%m%d-%H%M%S_container_vulnerabilities.csv')
writeToCSV(vuln_all, filename)
showMsg(f'file created: {filename}', 'secondary')
