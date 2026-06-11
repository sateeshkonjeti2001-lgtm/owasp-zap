# zap_helper.py
from zapv2 import ZAPv2
import time
import requests as req

ZAP_PROXY = 'http://127.0.0.1:8080'
ZAP_API_KEY = 'frtomkn7unao5659t8ners76di'
TARGET = 'http://127.0.0.1:5001'

def connect_zap():
    try:
        zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY}
        )
        version = zap.core.version
        return zap, version, 'Connected ✅'
    except Exception as e:
        return None, 'Unknown', f'Error ❌: {str(e)}'

def run_spider(zap):
    print(f'Spider starting on {TARGET}...')
    scan_id = zap.spider.scan(TARGET, apikey=ZAP_API_KEY)

    # Spider complete అయ్యే వరకు wait చెయ్యి
    while True:
        progress = int(zap.spider.status(scan_id))
        print(f'Spider progress: {progress}%')
        if progress >= 100:
            break
        time.sleep(2)

    urls = zap.spider.results(scan_id)
    print(f'Spider done! {len(urls)} URLs found')
    return urls

def run_passive_scan(zap):
    print('Passive scan running...')

    # Passive scan queue empty అయ్యే వరకు wait
    while True:
        records = int(zap.pscan.records_to_scan)
        print(f'Records left to scan: {records}')
        if records == 0:
            break
        time.sleep(2)

    alerts = zap.core.alerts(baseurl=TARGET)
    print(f'Passive scan done! {len(alerts)} alerts found')
    return alerts

def run_active_scan(zap):
    print(f'Active scan starting on {TARGET}...')
    
    # First access the target so ZAP knows it
    zap.urlopen(TARGET)
    time.sleep(2)
    
    # Start active scan
    scan_id = zap.ascan.scan(TARGET, apikey=ZAP_API_KEY)
    print(f'Scan ID: {scan_id}')
    
    time.sleep(3)

    while True:
        try:
            status = zap.ascan.status(scan_id)
            # Fix — handle 'does_not_exist' error
            if str(status).isdigit():
                progress = int(status)
            else:
                print(f'Scan status: {status} — retrying...')
                time.sleep(3)
                continue

            print(f'Active scan progress: {progress}%')
            if progress >= 100:
                break
            time.sleep(5)

        except Exception as e:
            print(f'Error: {e} — retrying...')
            time.sleep(3)
            continue

    alerts = zap.core.alerts(baseurl=TARGET)

    high   = [a for a in alerts if a['risk'] == 'High']
    medium = [a for a in alerts if a['risk'] == 'Medium']
    low    = [a for a in alerts if a['risk'] == 'Low']
    info   = [a for a in alerts if a['risk'] == 'Informational']

    return {
        'all': alerts,
        'high': high,
        'medium': medium,
        'low': low,
        'info': info
    }

import json
from datetime import datetime

def generate_report(scan_data):
    report = {
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': TARGET,
        'spider_urls': scan_data.get('urls', []),
        'passive_alerts': len(scan_data.get('alerts', [])),
        'active_summary': {
            'high':   len(scan_data.get('active_alerts', {}).get('high', [])),
            'medium': len(scan_data.get('active_alerts', {}).get('medium', [])),
            'low':    len(scan_data.get('active_alerts', {}).get('low', [])),
            'info':   len(scan_data.get('active_alerts', {}).get('info', []))
        },
        'all_alerts': scan_data.get('active_alerts', {}).get('all', [])
    }

    # Save JSON file
    json_path = 'reports/scan_report.json'
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Save HTML file
    html_path = 'reports/scan_report.html'
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZAP Scan Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            h1 {{ color: #333; }}
            .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
            .box {{ padding: 20px; border-radius: 8px; text-align: center; flex: 1; }}
            .high   {{ background: #ffe0e0; border: 2px solid red; }}
            .medium {{ background: #fff3cd; border: 2px solid orange; }}
            .low    {{ background: #e0f7e0; border: 2px solid green; }}
            .info   {{ background: #e0f0ff; border: 2px solid blue; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #333; color: white; padding: 10px; text-align: left; }}
            td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
            .row-High          {{ background: #ffe0e0; }}
            .row-Medium        {{ background: #fff3cd; }}
            .row-Low           {{ background: #e0f7e0; }}
            .row-Informational {{ background: #e0f0ff; }}
        </style>
    </head>
    <body>
        <h1>OWASP ZAP Security Scan Report</h1>
        <p><strong>Date:</strong> {report['date']}</p>
        <p><strong>Target:</strong> {report['target']}</p>
        <p><strong>URLs Discovered:</strong> {len(report['spider_urls'])}</p>
        <p><strong>Passive Alerts:</strong> {report['passive_alerts']}</p>

        <h2>Active Scan Summary</h2>
        <div class="summary">
            <div class="box high">High<br><strong>{report['active_summary']['high']}</strong></div>
            <div class="box medium">Medium<br><strong>{report['active_summary']['medium']}</strong></div>
            <div class="box low">Low<br><strong>{report['active_summary']['low']}</strong></div>
            <div class="box info">Info<br><strong>{report['active_summary']['info']}</strong></div>
        </div>

        <h2>All Alerts</h2>
        <table>
            <tr>
                <th>Risk</th>
                <th>Alert</th>
                <th>URL</th>
                <th>Solution</th>
            </tr>
            {''.join(f"""
            <tr class="row-{a.get('risk','Low')}">
                <td>{a.get('risk','')}</td>
                <td>{a.get('alert','')}</td>
                <td>{a.get('url','')[:50]}</td>
                <td>{a.get('solution','')[:80]}</td>
            </tr>""" for a in report['all_alerts'])}
        </table>
    </body>
    </html>
    """
    with open(html_path, 'w') as f:
        f.write(html)

    return json_path, html_path

def get_intercepted_requests(zap):
    try:
        messages = zap.core.messages(baseurl=TARGET)
        requests_list = []
        for msg in messages:
            # requestHeader నుండి method తీసుకో
            req_header = msg.get('requestHeader', '')
            resp_header = msg.get('responseHeader', '')

            # First line: "GET http://127.0.0.1:5001/ HTTP/1.1"
            method = 'GET'
            url = TARGET
            status_code = 'N/A'

            if req_header:
                first_line = req_header.split('\r\n')[0]
                parts = first_line.strip().split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    url = parts[1]

            # Response header నుండి status code తీసుకో
            if resp_header:
                resp_first = resp_header.split('\r\n')[0]
                resp_parts = resp_first.strip().split(' ')
                if len(resp_parts) >= 2:
                    status_code = resp_parts[1]

            requests_list.append({
                'method': method,
                'url': url[:60],
                'status_code': status_code
            })

        print(f'Intercepted {len(requests_list)} requests')
        return requests_list

    except Exception as e:
        print(f'Proxy error: {e}')
        return []

def run_fuzzing(zap):
    # Test endpoints with crafted payloads
    fuzz_results = []

    # Payloads to test
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1' AND SLEEP(5)--",
        "' UNION SELECT NULL--"
    ]

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>"
    ]

    path_traversal = [
        "../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "%2e%2e%2fetc/passwd"
    ]

    # Test search endpoint with SQL injection
    print('Fuzzing search endpoint...')
    for payload in sqli_payloads:
        try:
            response = req.get(
                f'{TARGET}/search',
                params={'q': payload},
                timeout=5
            )
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'SQL Injection',
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'result': 'Responded' if response.status_code == 200
                          else 'Blocked'
            })
        except Exception as e:
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'SQL Injection',
                'payload': payload,
                'status_code': 'Error',
                'response_length': 0,
                'result': str(e)
            })

    # Test search endpoint with XSS
    print('Fuzzing XSS payloads...')
    for payload in xss_payloads:
        try:
            response = req.get(
                f'{TARGET}/search',
                params={'q': payload},
                timeout=5
            )
            # Check if payload reflected in response
            reflected = payload in response.text
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'XSS',
                'payload': payload[:40],
                'status_code': response.status_code,
                'response_length': len(response.text),
                'result': '⚠️ REFLECTED' if reflected else 'Not Reflected'
            })
        except Exception as e:
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'XSS',
                'payload': payload[:40],
                'status_code': 'Error',
                'response_length': 0,
                'result': str(e)
            })

    # Test login with path traversal
    print('Fuzzing path traversal...')
    for payload in path_traversal:
        try:
            response = req.post(
                f'{TARGET}/login',
                data={'username': payload, 'password': 'test'},
                timeout=5
            )
            fuzz_results.append({
                'endpoint': '/login',
                'type': 'Path Traversal',
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'result': 'Responded'
            })
        except Exception as e:
            fuzz_results.append({
                'endpoint': '/login',
                'type': 'Path Traversal',
                'payload': payload,
                'status_code': 'Error',
                'response_length': 0,
                'result': str(e)
            })

    print(f'Fuzzing done! {len(fuzz_results)} tests run')
    return fuzz_results

def run_auth_testing(zap):
    auth_results = []

    # Test credentials
    test_credentials = [
        {'username': 'admin',  'password': 'admin123',   'expected': 'success'},
        {'username': 'user',   'password': 'password123','expected': 'success'},
        {'username': 'admin',  'password': 'wrongpass',  'expected': 'fail'},
        {'username': 'hacker', 'password': 'hacker123',  'expected': 'fail'},
        {'username': 'admin',  'password': '',           'expected': 'fail'},
        {'username': '',       'password': 'admin123',   'expected': 'fail'},
        {'username': 'admin',  'password': 'admin',      'expected': 'fail'},
        {'username': "' OR '1'='1", 'password': 'any',  'expected': 'fail'},
    ]

    import requests as req
    for cred in test_credentials:
        try:
            response = req.post(
                f'{TARGET}/login',
                data={
                    'username': cred['username'],
                    'password': cred['password']
                },
                timeout=5
            )
            # Check response for success/failure
            if 'SUCCESS' in response.text:
                actual = 'success'
            else:
                actual = 'fail'

            # Check if result matches expected
            if actual == cred['expected']:
                result = '✅ Expected'
            else:
                result = '⚠️ UNEXPECTED'

            auth_results.append({
                'username': cred['username'][:20],
                'password': cred['password'][:15],
                'expected': cred['expected'],
                'actual':   actual,
                'status':   response.status_code,
                'result':   result
            })
            print(f"Auth test: {cred['username']} "
                  f"— {actual} — {result}")

        except Exception as e:
            auth_results.append({
                'username': cred['username'][:20],
                'password': cred['password'][:15],
                'expected': cred['expected'],
                'actual':   'error',
                'status':   'Error',
                'result':   str(e)[:30]
            })

    print(f'Auth testing done! {len(auth_results)} tests')
    return auth_results


def scan_api_endpoints(zap):
    api_results = []
    import requests as req

    # API endpoints to test
    endpoints = [
        {'url': f'{TARGET}/api/users',       'method': 'GET'},
        {'url': f'{TARGET}/api/user/admin',  'method': 'GET'},
        {'url': f'{TARGET}/api/user/test',   'method': 'GET'},
        {'url': f'{TARGET}/api/user/hacker', 'method': 'GET'},
        {'url': f'{TARGET}/api/status',      'method': 'GET'},
    ]

    for ep in endpoints:
        try:
            response = req.get(ep['url'], timeout=5)

            # Try to parse JSON
            try:
                json_data = response.json()
                data_preview = str(json_data)[:60]
            except:
                data_preview = response.text[:60]

            api_results.append({
                'url':          ep['url'].replace(TARGET, ''),
                'method':       ep['method'],
                'status_code':  response.status_code,
                'response':     data_preview,
                'accessible':   '⚠️ EXPOSED' if response.status_code == 200
                                else '✅ Protected'
            })
            print(f"API test: {ep['url']} "
                  f"— {response.status_code}")

        except Exception as e:
            api_results.append({
                'url':         ep['url'].replace(TARGET, ''),
                'method':      ep['method'],
                'status_code': 'Error',
                'response':    str(e)[:40],
                'accessible':  '❌ Error'
            })

    print(f'API scan done! {len(api_results)} endpoints tested')
    return api_results