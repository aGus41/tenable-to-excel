import time
import requests
import json

access_key = 'key'
secret_key = "key"
my_headers = "accessKey=" + access_key + "; secretKey=" + secret_key

scan_name = "<scan_name>"


def tenable_csv_request():
    r_scans = requests.get('https://cloud.tenable.com/scans',
                           headers={"X-ApiKeys": my_headers})

    scan_json = json.loads(r_scans.text)

    for i in range(len(scan_json)):
        if scan_json[i]['name'] == scan_name:
            scan_id = scan_json[i]['id']
        elif i == len(scan_json) - 1:
            print('scan not found')
            exit()

    print(scan_id)
    r_exportrequest = requests.post("https://cloud.tenable.com/scans/" +
                                    scan_id + "/export", data={'format': 'csv',
                                                               'asset_id': 1, 'chapters': 'vuln_hosts_summary'},
                                    headers={"X-ApiKeys": my_headers})

    file_id = json.loads(r_exportrequest.text)[0]['file']

    print(file_id)
    r_csv = requests.get('https://cloud.tenable.com/scans/' + scan_id + '/export/' + file_id + '/download',
                         headers={"X-ApiKeys": my_headers})
    time.sleep(5)
    open(scan_name.replace(":", "") + '.csv', 'wb').write(r_csv.content)
    return scan_name, r_csv
