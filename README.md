# falcon-Image-Scan-result-to-csv
This script fetchs image scan results via API and save it locally as CSV.  


## Usage
1. Create an API client in the Falcon console with the following scope.
```
Falcon Container Image: Read
```

2. Set environmental variables. 
```bash
export FALCON_CLIENT_ID=XXXXX
export FALCON_CLIENT_SECRET=YYYYY
export FALCON_SSL_VERIFY=True or False
```

3. Execute.

old version.
```bash
curl -s https://raw.githubusercontent.com/p-rex/falcon-Image-Scan-result-to-csv/main/fetch_image_scan_result.py | python
```

Use v2 if you have more than 10K images.
```bash
curl -s https://raw.githubusercontent.com/p-rex/falcon-Image-Scan-result-to-csv/main/fetch_image_scan_result_v2.py | python
```
  
CSV will be created in the working dir.

## Sample output
### Console
```
=== Get Image list via API ===
Progress: 22/22

=== Extract Vlulnerable Image digest ===
Number of unique vulnerable image digest:22

=== Get package list via API ===
Progress: 22/22

=== Get Vulnerability list via API ===
Progress: 876/876
Change vulnerability list format

=== Merge data ===

=== Output to CSV ===
file created: 20240628-082905_container_vulnerabilities.csv
```

### CSV
```
registry,repository,tag,base_os,image_id,image_digest,type,package_name_version,cveid,severity,cvss_score,exploited_status_string,exprt_rating,description,fix_resolution
cicd,552149689430.dkr.ecr.us-west-2.amazonaws.com/webapp,latest,Ubuntu 18.04,870cf6917d57d9411fad417167dfdce657793c9f4b16c7216c335aa58d7d8903,9558d53457c314604df692e70d191289f5e3a53c6804d904dde6260cd2bef102,os,apparmor 2.12-4ubuntu5.1,CVE-2016-1585,Critical,9.8,Unproven,Low,"In all versions of AppArmor mount rules are accidentally widened when compiled.
",[]
cicd,552149689430.dkr.ecr.us-west-2.amazonaws.com/webapp,latest,Ubuntu 18.04,870cf6917d57d9411fad417167dfdce657793c9f4b16c7216c335aa58d7d8903,9558d53457c314604df692e70d191289f5e3a53c6804d904dde6260cd2bef102,os,avahi 0.7-3.1ubuntu1.3,CVE-2023-38470,Medium,5.5,Unproven,Low,"A vulnerability was found in Avahi. A reachable assertion exists in the avahi_escape_label() function.
",[]
[cicd,552149689430.dkr.ecr.us-west-2.amazonaws.com/webapp,latest,Ubuntu 18.04,870cf6917d57d9411fad417167dfdce657793c9f4b16c7216c335aa58d7d8903,9558d53457c314604df692e70d191289f5e3a53c6804d904dde6260cd2bef102,os,avahi 0.7-3.1ubuntu1.3,CVE-2023-1981,Medium,5.5,Available,Low,"A vulnerability was found in the avahi library. This flaw allows an unprivileged user to make a dbus call, causing the avahi daemon to crash.
",[]](https://registry-1.docker.io (prex55),prex55/cs-streaming-humio-connector,5.5,Ubuntu 20.04,e3f5db6956eb307dbabaaf85f399fb454222c4321d29bcc612575bcef598350a,2a3cf0a4233b8c0c7aeeaeb8dd68d7f0dcd078e2b435c7916f56e6cb43cbe138,os,apache2 2.4.41-4ubuntu3.12,CVE-2019-17567,Medium,5.3,Unproven,Low,"Apache HTTP Server versions 2.4.6 to 2.4.46 mod_proxy_wstunnel configured on an URL that is not necessarily Upgraded by the origin server was tunneling the whole connection regardless, thus allowing for subsequent requests on the same connection to pass through with no HTTP validation, authentication or authorization possibly configured.
",[]
https://registry-1.docker.io (prex55),prex55/cs-streaming-humio-connector,5.5,Ubuntu 20.04,e3f5db6956eb307dbabaaf85f399fb454222c4321d29bcc612575bcef598350a,2a3cf0a4233b8c0c7aeeaeb8dd68d7f0dcd078e2b435c7916f56e6cb43cbe138,os,apache2 2.4.41-4ubuntu3.12,CVE-2022-37436,Medium,5.3,Unproven,Low,"Prior to Apache HTTP Server 2.4.55, a malicious backend can cause the response headers to be truncated early, resulting in some headers being incorporated into the response body. If the later headers have any security purpose, they will not be interpreted by the client.
",['upgrade to version 2.4.41-4ubuntu3.13'])
```
