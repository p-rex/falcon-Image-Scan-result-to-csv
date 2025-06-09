from falconpy import ContainerImages, ContainerPackages, ContainerVulnerabilities
import os
import pandas as pd
import datetime


##---------------------------------------------------
## functions
##---------------------------------------------------
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


def getImageList(falcon_client_id, falcon_client_secret, falcon_ssl_verify):
    # https://falconpy.io/Service-Collections/Container-Images.html#getcombinedimages
    falcon = ContainerImages(client_id=falcon_client_id, client_secret=falcon_client_secret, ssl_verify=falcon_ssl_verify)

    def fetchImages(offset_cnt):
        return falcon.get_combined_images(offset=offset_cnt, sort="first_seen")

    return getResources(fetchImages)



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
falcon_ssl_verify = os.environ['FALCON_SSL_VERIFY']


showMsg('Get Image list via API')
image_list = getImageList(falcon_client_id, falcon_client_secret, falcon_ssl_verify)


showMsg('Extract Vlulnerable Image digest')
vulnerable_image_digests = []
for image in image_list:
    if(image['vulnerabilities']):
        vulnerable_image_digests.append(image['image_digest'])

#IMDL check if there are vulnerable_image_digest
vulnerable_image_digests = list(set(vulnerable_image_digests))
vulnerable_image_digests_cnt = len(vulnerable_image_digests)
showMsg('Number of unique vulnerable image digest:' + str(vulnerable_image_digests_cnt), 'secondary')


showMsg('Get package list via API')
package_dict = {}
for i, image_digest in enumerate(vulnerable_image_digests):
    showProgress(i+1, vulnerable_image_digests_cnt)
    package_dict[image_digest] =  getPackageList(falcon_client_id, falcon_client_secret, falcon_ssl_verify, image_digest)


showMsg('Get Vulnerability list via API')
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

    if not image['vulnerabilities']:
        continue

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
