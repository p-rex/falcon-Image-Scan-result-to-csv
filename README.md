# falcon-Image-Scan-result-to-csv
Fetch image scan results and save it as CSV.  
The csv includes package name.

# Usage
Set environmental variables. 
```bash
export FALCON_CLIENT_ID=XXXXX
export FALCON_CLIENT_SECRET=YYYYY
```

Execute.
```bash
curl -s https://raw.githubusercontent.com/p-rex/falcon-Image-Scan-result-to-csv/main/fetch_image_scan_result.py | python
```
  
CSV will be created in the working dir.

# Sample output
### Console
```
=== Get Image list via API ===
Progress: 1567/1567
=== Extract Vlulnerable Image digest ===
Number of unique vulnerable image digest:736

=== Get package info via API ===
Progress: 736/736
=== Merge image and package info ===

=== Output to CSV ===
file created: 20240614-160313_container_vulnerabilities.csv
```

### CSV
```
registry,repository,tag,base_os,image_id,image_digest,type,package_name_version,cveid,severity,description,fix_resolution
cicd,bsh_nginx,v1,Debian GNU 10,62d49f9bab67f7c70ac3395855bf01389eb3175b374e621f6f191bf31b54cd5b,42bba58a1c5a6e2039af02302ba06ee66c446e9547cbfb0da33f4267638cdb53,os,jbigkit 2.1-3.1,CVE-2022-1210,Medium,"A vulnerability classified as problematic was found in LibTIFF 4.3.0. Affected by this vulnerability is the TIFF File Handler of tiff2ps. Opening a malicious file leads to a denial of service. The attack can be launched remotely but requires user interaction. The exploit has been disclosed to the public and may be used.
",[]
cicd,bsh_nginx,v1,Debian GNU 10,62d49f9bab67f7c70ac3395855bf01389eb3175b374e621f6f191bf31b54cd5b,42bba58a1c5a6e2039af02302ba06ee66c446e9547cbfb0da33f4267638cdb53,os,jbigkit 2.1-3.1,CVE-2017-9937,Medium,"In LibTIFF 4.0.8, there is a memory malloc failure in tif_jbig.c. A crafted TIFF document can lead to an abort resulting in a remote denial of service attack.
",[]
cicd,bsh_nginx,v1,Debian GNU 10,62d49f9bab67f7c70ac3395855bf01389eb3175b374e621f6f191bf31b54cd5b,42bba58a1c5a6e2039af02302ba06ee66c446e9547cbfb0da33f4267638cdb53,os,curl 7.64.0-4+deb10u2,CVE-2023-38546,Low,"This flaw allows an attacker to insert cookies at will into a running program
using libcurl, if the specific series of conditions are met.

libcurl performs transfers. In its API, an application creates ""easy handles""
that are the individual handles for single transfers.

libcurl provides a function call that duplicates en easy handle called
[curl_easy_duphandle](https://curl.se/libcurl/c/curl_easy_duphandle.html).

If a transfer has cookies enabled when the handle is duplicated, the
cookie-enable state is also cloned - but without cloning the actual
cookies. If the source handle did not read any cookies from a specific file on
disk, the cloned version of the handle would instead store the file name as
`none` (using the four ASCII letters, no quotes).

Subsequent use of the cloned handle that does not explicitly set a source to
load cookies from would then inadvertently load cookies from a file named
`none` - if such a file exists and is readable in the current directory of the
program using libcurl. And if using the correct file format of course.
",[]
```
