# app.py
from zap_helper import connect_zap, run_spider, run_passive_scan, run_active_scan, generate_report, get_intercepted_requests, run_fuzzing, run_auth_testing, scan_api_endpoints
from remediation_db import get_remediation  # ← NEW
from flask import Flask, render_template, redirect, url_for, send_file, request, jsonify
import sqlite3, datetime, json  # ← NEW
import markupsafe
from risk_assessment import get_risk_data, calculate_overall_risk

app = Flask(__name__)

scan_data = {
    'urls': [],
    'alerts': [],
    'spider_done': False,
    'passive_done': False,
    'active_done': False,
    'proxy_done': False,        
    'fuzz_done': False,
    'auth_done': False,
    'api_done': False,
    'proxy_requests': [],
    'fuzz_results': [],
    'auth_results': [],
    'api_results': [],
    'active_alerts': {
        'all': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
}

# ─── NEW: Security Headers ─────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Server'] = 'WebServer'
    return response

# ─── NEW: DB Init ──────────────────────────────────────────
def init_db():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_date TEXT, scan_type TEXT, target_url TEXT,
        high_count INTEGER, medium_count INTEGER,
        low_count INTEGER, info_count INTEGER,
        total_alerts INTEGER, alerts_json TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS fix_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_name TEXT UNIQUE, status TEXT,
        fixed_date TEXT, notes TEXT
    )''')
    conn.commit()
    conn.close()

init_db()  # runs on startup

# ─── NEW: Helper functions ─────────────────────────────────
def get_fix_status(vuln_name):
    try:
        conn = sqlite3.connect('scan_history.db')
        c = conn.cursor()
        c.execute('SELECT status FROM fix_status WHERE vuln_name = ?', (vuln_name,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else 'pending'
    except:
        return 'pending'

def save_scan_to_db(scan_type='manual'):
    try:
        alerts = scan_data['active_alerts']
        high   = len(alerts.get('high', []))
        medium = len(alerts.get('medium', []))
        low    = len(alerts.get('low', []))
        info   = len(alerts.get('info', []))
        conn = sqlite3.connect('scan_history.db')
        c = conn.cursor()
        c.execute('''INSERT INTO scan_results
            (scan_date, scan_type, target_url, high_count, medium_count,
             low_count, info_count, total_alerts, alerts_json)
            VALUES (?,?,?,?,?,?,?,?,?)''', (
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            scan_type, 'http://127.0.0.1:5001',
            high, medium, low, info,
            high + medium + low + info,
            json.dumps(alerts.get('all', [])[:10])
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB save error: {e}")

# ─── EXISTING ROUTES (unchanged) ───────────────────────────
@app.route('/')
def home():
    zap, version, status = connect_zap()
    return render_template('index.html',
        zap_status=status,
        zap_version=version,
        scan_data=scan_data
    )

@app.route('/spider')
def spider():
    zap, version, status = connect_zap()
    if zap:
        urls = run_spider(zap)
        scan_data['urls'] = urls
        scan_data['spider_done'] = True
    return redirect(url_for('home'))

@app.route('/passive')
def passive():
    zap, version, status = connect_zap()
    if zap:
        alerts = run_passive_scan(zap)
        scan_data['alerts'] = alerts
        scan_data['passive_done'] = True
    return redirect(url_for('home'))

@app.route('/active')
def active():
    zap, version, status = connect_zap()
    if zap:
        results = run_active_scan(zap)
        scan_data['active_alerts'] = results
        scan_data['active_done'] = True
        save_scan_to_db('initial')  # ← NEW: save to DB after active scan
    return redirect(url_for('home'))

@app.route('/report')
def report():
    json_path, html_path = generate_report(scan_data)
    return send_file(html_path, as_attachment=True)

@app.route('/proxy')
def proxy():
    zap, version, status = connect_zap()
    if zap:
        requests_list = get_intercepted_requests(zap)
        scan_data['proxy_requests'] = requests_list
        scan_data['proxy_done'] = True
    return redirect(url_for('home'))

@app.route('/fuzz')
def fuzz():
    zap, version, status = connect_zap()
    if zap:
        results = run_fuzzing(zap)
        scan_data['fuzz_results'] = results
        scan_data['fuzz_done'] = True
    return redirect(url_for('home'))

@app.route('/auth')
def auth():
    zap, version, status = connect_zap()
    if zap:
        results = run_auth_testing(zap)
        scan_data['auth_results'] = results
        scan_data['auth_done'] = True
    return redirect(url_for('home'))

@app.route('/api-scan')
def api_scan():
    zap, version, status = connect_zap()
    if zap:
        results = scan_api_endpoints(zap)
        scan_data['api_results'] = results
        scan_data['api_done'] = True
    return redirect(url_for('home'))

# ─── NEW ROUTES ────────────────────────────────────────────

@app.route('/remediation')
def remediation():
    alerts = scan_data['active_alerts'].get('all', [])
    vuln_list = []
    for alert in alerts:
        name = alert.get('alert', alert.get('name', 'Unknown'))
        guide = get_remediation(name)
        vuln_list.append({
            'name': name,
            'risk': alert.get('risk', guide['risk']),
            'url': alert.get('url', 'N/A'),
            'description': guide['description'],
            'root_cause': guide['root_cause'],
            'steps': guide['steps'],
            'fix_code': markupsafe.Markup(guide['fix_code'].replace('{{', '{ {').replace('}}', '} }')),  # ← ADD THIS
            'fix_file': guide['fix_file'],
            'references': guide['references'],
            'verify_command': guide['verify_command'],
            'status': get_fix_status(name)
        })
    fixed = sum(1 for v in vuln_list if v['status'] == 'fixed')
    return render_template('remediation.html',
                           vulns=vuln_list,
                           total=len(vuln_list),
                           fixed=fixed)

@app.route('/mark-fixed', methods=['POST'])
def mark_fixed():
    vuln_name = request.form.get('vuln_name')
    notes = request.form.get('notes', '')
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO fix_status
                 (vuln_name, status, fixed_date, notes)
                 VALUES (?, 'fixed', ?, ?)''',
              (vuln_name, datetime.datetime.now().strftime('%Y-%m-%d %H:%M'), notes))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/rescan')
def rescan():
    zap, version, status = connect_zap()
    if not zap:
        return redirect(url_for('home'))
    # Run all scans fresh
    scan_data['urls'] = run_spider(zap)
    scan_data['spider_done'] = True
    scan_data['alerts'] = run_passive_scan(zap)
    scan_data['passive_done'] = True
    results = run_active_scan(zap)
    scan_data['active_alerts'] = results
    scan_data['active_done'] = True
    save_scan_to_db('rescan')  # ← saves rescan result to DB
    return redirect(url_for('compare'))

@app.route('/compare')
def compare():
    conn = sqlite3.connect('scan_history.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scan_results ORDER BY scan_date ASC LIMIT 2')
    rows = c.fetchall()
    conn.close()
    before, after, improvement = None, None, None
    if len(rows) >= 1:
        before = {'date': rows[0][1], 'high': rows[0][4],
                  'medium': rows[0][5], 'low': rows[0][6], 'total': rows[0][8]}
    if len(rows) >= 2:
        after  = {'date': rows[1][1], 'high': rows[1][4],
                  'medium': rows[1][5], 'low': rows[1][6], 'total': rows[1][8]}
    if before and after:
        improvement = {
            'high_diff':   before['high']   - after['high'],
            'medium_diff': before['medium'] - after['medium'],
            'low_diff':    before['low']    - after['low'],
            'total_diff':  before['total']  - after['total']
        }
    return render_template('compare.html',
                           before=before, after=after,
                           improvement=improvement)




@app.route('/risk-assessment')
def risk_assessment():
    alerts = scan_data['active_alerts'].get('all', [])

    seen = set()
    vuln_list = []

    for alert in alerts:
        name = alert.get('alert', alert.get('name', 'Unknown'))
        if name in seen:
            continue
        seen.add(name)

        risk = get_risk_data(name)
        vuln_list.append({
            'name': name,
            'cvss_score': risk['cvss_score'],
            'attack_scenario': risk['attack_scenario'],
            'real_world_analogy': risk['real_world_analogy'],
            'what_attacker_can_do': risk['what_attacker_can_do'],
            'impact': risk['impact'],
            'likelihood': risk['likelihood'],
            'affected_assets': risk['affected_assets'],
            'risk_score': risk['risk_score'],
            'risk_level': risk['risk_level'],
            'urgency': risk['urgency']
        })

    # Sort by risk score descending (highest risk first)
    vuln_list.sort(key=lambda x: x['risk_score'], reverse=True)

    # Count by level
    counts = {
        'critical': sum(1 for v in vuln_list if v['risk_level'] == 'Critical'),
        'high':     sum(1 for v in vuln_list if v['risk_level'] == 'High'),
        'medium':   sum(1 for v in vuln_list if v['risk_level'] == 'Medium'),
        'low':      sum(1 for v in vuln_list if v['risk_level'] == 'Low'),
    }

    # Overall risk score
    active = scan_data['active_alerts']
    overall = calculate_overall_risk(
        len(active.get('high', [])),
        len(active.get('medium', [])),
        len(active.get('low', []))
    )

    return render_template('risk_assessment.html',
                           vulns=vuln_list,
                           total=len(alerts),
                           vuln_count=len(vuln_list),
                           overall=overall,
                           counts=counts)

if __name__ == '__main__':
    app.run(debug=True, port=5000)