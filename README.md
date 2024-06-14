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
