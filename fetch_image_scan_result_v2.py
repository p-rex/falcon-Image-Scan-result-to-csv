from falconpy import ContainerPackages, ContainerVulnerabilities, FalconContainer
import os
import pandas as pd
import datetime
import time
import json
import pprint

##---------------------------------------------------
## Global Vars
##---------------------------------------------------
JOB_CHECK_INTERVAL = 5


##---------------------------------------------------
## Classes
##---------------------------------------------------
class ExportAPI:
# To get a list of vulnerable images, use the Export API which can get up to 1M entries.
# https://falconpy.io/Service-Collections/Falcon-Container.html

    def __init__(
            self, 
            client_id: str, 
            client_secret: str, 
            ssl_verify: bool = True
        ):

        self.falcon = FalconContainer(client_id=falcon_client_id, client_secret=falcon_client_secret, ssl_verify=falcon_ssl_verify)
        self.resp = {}

    def getImageList(self):
        # Create Job
        # https://falconpy.io/Service-Collections/Falcon-Container.html#launchexportjob
        self.resp = self.falcon.launch_export_job(format="json",
                                        resource="images.images-assessment-expanded",
                                        sort="image_digest"
                                        )
        return self.getJobResult()

    def getVuln(self):
        # Create Job
        # https://falconpy.io/Service-Collections/Falcon-Container.html#launchexportjob
        self.resp = self.falcon.launch_export_job(format="json",
                                        resource="images.images-assessment-vulnerabilities-expanded",
                                        sort="image_digest"
                                        )

        return self.getJobResult()

    def  getJobResult(self):
        if self.chkStatusCode() == True:
            showMsg("Export job is created", 'secondary')
        job_id = self.resp['body']['resources'][0]

        while True:
            resp = self.falcon.read_export_jobs(ids = job_id)
            # Check if export job is done.
            # After a Job is created, there may be a case where the status key doesn't exist, so a slightly complex check is performed.
            if (resp.get('body', {}).get('resources', []) and resp['body']['resources'][0].get('status') == 'DONE'):
                showMsg("Export job is done", 'secondary')
                break

            showMsg("Export job is in progress", 'secondary')
            time.sleep(JOB_CHECK_INTERVAL)

        resp = self.falcon.DownloadExportFile(id=job_id)

        # Decode from byte code to string
        json_str = resp.decode('utf-8')

        # Convert from json string to python dictionary
        return json.loads(json_str)
    
    def chkStatusCode(self):
        if self.resp['status_code'] != 200:
            pprint.pprint(self.resp)
            showMsg('API failed', 'error')
            exit()
        return True



##---------------------------------------------------
## functions
##---------------------------------------------------

def getUniqueVulnExpandedList(vuln_expanded_list):
    result = {}
    for vuln_expanded in vuln_expanded_list:
        image_digest = vuln_expanded['Image digest']
        
        # Add if no image digest in the result
        if image_digest not in result:
            result[image_digest] = vuln_expanded
    return result

# This function is for handling API pagination
def getResources(resource_fetcher, offset_cnt=0, show_progress=True):
    resources = []
    total_cnt = 100  # just temporary number to start the while loop

    while offset_cnt < total_cnt:
        resp = resource_fetcher(offset_cnt)
        if resp['status_code'] != 200:
            showMsg('API failed', 'error')
            continue

        resources.extend(resp['body']['resources'])
        total_cnt = resp['body']['meta']['pagination']['total']
        limit_cnt = resp['body']['meta']['pagination']['limit']
        offset_cnt += limit_cnt

        if show_progress:
            showProgress(offset_cnt, total_cnt)
    
    return resources



def getPackageList(falcon_client_id, falcon_client_secret, falcon_ssl_verify, digest):
    # https://falconpy.io/Service-Collections/Container-Packages.html#readpackagescombined
    falcon = ContainerPackages(client_id=falcon_client_id, client_secret=falcon_client_secret, ssl_verify=falcon_ssl_verify)
    
    def fetchPackages(offset_cnt):
        filter_fql = f"image_digest:'{digest}'"
        return falcon.read_combined(
            filter=filter_fql,
            only_zero_day_affected=False,
            offset=offset_cnt,
            sort='package_name_version'
        )
    
    return getResources(fetchPackages, show_progress=False)



def getVulnerabilityList(falcon_client_id, falcon_client_secret, falcon_ssl_verify):
    # https://falconpy.io/Service-Collections/Container-Vulnerabilities.html#readcombinedvulnerabilities
    falcon = ContainerVulnerabilities(client_id=falcon_client_id, client_secret=falcon_client_secret, ssl_verify=falcon_ssl_verify)
    
    def fetchVulnerabilities(offset_cnt):
        return falcon.read_combined_vulnerabilities(offset=offset_cnt, sort='cve_id')

    return getResources(fetchVulnerabilities)



def showProgress(current, total):
    if(current >= total):
        print(f"Progress: {total}/{total}")
    else:
        print(f"Progress: {current}/{total}", end='\r')

def showMsg(msg, category='primary'):
    if(category == 'primary'):
        print('')
        print(f'=== {msg} ===')
    if(category == 'secondary'):
        print(msg)
    if(category == 'error'):
        print(f'Error: {msg}')

def writeToCSV(data, filename):
    df = pd.json_normalize(data)
    df.to_csv(filename, index=False, encoding='utf-8')


##---------------------------------------------------
## main
##---------------------------------------------------

#Set API Credential
falcon_client_id = os.environ['FALCON_CLIENT_ID']
falcon_client_secret = os.environ['FALCON_CLIENT_SECRET']
falcon_ssl_verify = os.environ.get('FALCON_SSL_VERIFY', 'True').lower() == 'true' # Set True if no env var


showMsg('Get Image List - Export API')
eapi = ExportAPI(falcon_client_id, falcon_client_secret, falcon_ssl_verify)
image_list = eapi.getImageList()


# This information is used to extract the image digest of the vulnerable images
# Since this does not include detailed information (such as exploit status), the vulnerability list will be obtained later using the normal API
showMsg('Get All vulnerabilities - Export API')
vuln_expanded_list = eapi.getVuln()

# Extract the image digest of the vulnerable image 
vuln_expanded_list = getUniqueVulnExpandedList(vuln_expanded_list)
vulnerable_image_digests_cnt = len(vuln_expanded_list)
showMsg('Number of unique vulnerable image digest:' + str(vulnerable_image_digests_cnt), 'secondary')


showMsg('Get package list - normal API')
package_dict = {}
for i, image_digest in enumerate(vuln_expanded_list.keys()):
    showProgress(i+1, vulnerable_image_digests_cnt)
    package_dict[image_digest] =  getPackageList(falcon_client_id, falcon_client_secret, falcon_ssl_verify, image_digest)


showMsg('Get Vulnerability list - normal API')
vulnerability_list = getVulnerabilityList(falcon_client_id, falcon_client_secret, falcon_ssl_verify)
showMsg('Change vulnerability list format', 'secondary')
# Add cveid to the dictionary key for easier processing when creating CSV 
# before
#  [{'cve_id': 'CVE-2022-2222', 'severity': 'Low'}, {'cve_id': 'CVE-2020-1111', 'severity': 'High'} ]
# after
#  {'CVE-2022-2222': {'cve_id': 'CVE-2022-2222', 'severity': 'Low'}, 'CVE-2020-1111': {'cve_id': 'CVE-2020-1111', 'severity': 'High'}}
vulnerability_list_cveid = {}
for items in vulnerability_list:
    vulnerability_list_cveid[items['cve_id']] = items

del vulnerability_list



showMsg('Merge data')
vuln_all = []

for image in image_list:
    image_digest = image['Image digest']

    # skip if there is no vulnerabilities
    if image_digest not in vuln_expanded_list.keys():
        continue

    for package in package_dict[image_digest]:
        if not package['vulnerabilities']:
            continue

        for vul in package['vulnerabilities']:
            vuln_line = {}

            # from image
            vuln_line['registry']  = image['Registry']
            vuln_line['repository'] = image['Repository']
            vuln_line['tag'] = image['Tag']
            vuln_line['base_os'] = image['Base OS']
            vuln_line['image_id'] = image['Image ID']
            vuln_line['image_digest'] = image['Image digest']

            #from packages
            vuln_line['type'] = package['type']
            vuln_line['package_name_version'] = package['package_name_version']
            vuln_line['cveid'] = vul['cveid']
            vuln_line['severity']  = vul['severity']

            #from vulnerabilities
            v_dict = vulnerability_list_cveid.get(vul['cveid'])
            if v_dict is None:
                showMsg(f'{vul["cveid"]} is not found in Vulnerability list', 'error')
            else:
                vuln_line['cvss_score']  = v_dict['cvss_score']
                vuln_line['exploited_status_string']  = v_dict['exploited_status_string']
                vuln_line['exprt_rating']  = v_dict['cps_current_rating']

            #from packages
            vuln_line['description']  = vul['description'] 
            vuln_line['fix_resolution']  = vul['fix_resolution'] #IMCL This type is list. multiple resolution may exist

            vuln_all.append(vuln_line)



showMsg('Output to CSV')
dt_now = datetime.datetime.now()
filename = dt_now.strftime('%Y%m%d-%H%M%S_container_vulnerabilities.csv')
writeToCSV(vuln_all, filename)
showMsg(f'file created: {filename}', 'secondary')
