REMEDIATION_GUIDE = {
    "Missing Anti-clickjacking Header": {
        "risk": "Medium",
        "description": "The X-Frame-Options header is not set. Attackers can embed your app in an iframe on a malicious site to trick users into clicking hidden buttons (Clickjacking attack).",
        "root_cause": "Flask does not add security headers by default. No X-Frame-Options header is being sent in HTTP responses.",
        "steps": [
            "Open your app.py file",
            "Add the after_request function to inject security headers into every response",
            "Set X-Frame-Options to DENY to block all iframe embedding",
            "Restart Flask and re-scan to verify the header appears in responses"
        ],
        "fix_code": """# Add this to your app.py (after creating the Flask app)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
""",
        "fix_file": "app.py",
        "references": [
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ],
        "verify_command": "curl -I http://127.0.0.1:5001/ | grep -i x-frame"
    },

    "Content Security Policy (CSP) Header Not Set": {
        "risk": "Medium",
        "description": "No Content-Security-Policy header is set. This allows browsers to load resources from any source, increasing XSS risk since malicious scripts can be injected and executed.",
        "root_cause": "No CSP header defined in Flask responses. Without CSP, browsers have no policy restricting which scripts, styles, or resources can load.",
        "steps": [
            "Open your app.py file",
            "Add Content-Security-Policy to the after_request security headers function",
            "Start with a strict policy and relax only what your app needs",
            "Re-scan to confirm the CSP header is present in responses"
        ],
        "fix_code": """# Add inside your after_request function in app.py

response.headers['Content-Security-Policy'] = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self';"
)
""",
        "fix_file": "app.py",
        "references": [
            "https://owasp.org/www-community/controls/Content_Security_Policy",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        ],
        "verify_command": "curl -I http://127.0.0.1:5001/ | grep -i content-security"
    },

    "X-Content-Type-Options Header Missing": {
        "risk": "Low",
        "description": "The X-Content-Type-Options header is missing. Without it, browsers may perform MIME-type sniffing which can lead to content injection attacks where a file uploaded as an image is executed as JavaScript.",
        "root_cause": "Flask does not set X-Content-Type-Options by default. This is a simple one-line header fix.",
        "steps": [
            "Open your app.py file",
            "Add X-Content-Type-Options: nosniff inside the after_request function",
            "This tells browsers to always respect the declared Content-Type",
            "Re-scan to verify the header is present"
        ],
        "fix_code": """# Add inside your after_request function in app.py

response.headers['X-Content-Type-Options'] = 'nosniff'
""",
        "fix_file": "app.py",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
        "verify_command": "curl -I http://127.0.0.1:5001/ | grep -i x-content-type"
    },

    "Server Leaks Version Information": {
        "risk": "Low",
        "description": "The HTTP Server response header reveals Flask and Python version numbers. Attackers can use this to find known CVEs for the exact versions you are running.",
        "root_cause": "Flask/Werkzeug automatically adds a Server header like 'Werkzeug/3.1.0 Python/3.13.0' to all responses.",
        "steps": [
            "Open your app.py file",
            "Override the Server header in the after_request function",
            "Replace the real version with a generic value or remove it entirely",
            "Re-scan to confirm the version number is no longer exposed"
        ],
        "fix_code": """# Add inside your after_request function in app.py

response.headers['Server'] = 'WebServer'
# This hides the real Flask/Python version from attackers
""",
        "fix_file": "app.py",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://httpd.apache.org/docs/current/mod/core.html#servertokens"
        ],
        "verify_command": "curl -I http://127.0.0.1:5001/ | grep -i server"
    },

    "HTTP Only Site": {
        "risk": "Medium",
        "description": "The application is running on HTTP instead of HTTPS. All traffic including login credentials, session cookies, and sensitive data is transmitted in plain text and can be intercepted by attackers using a Man-in-the-Middle attack.",
        "root_cause": "No SSL/TLS certificate is configured. The Flask app is started with app.run() without ssl_context, and no HTTPS redirect is in place.",
        "steps": [
            "For local testing: generate a self-signed SSL certificate using OpenSSL",
            "Run: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes",
            "Update app.run() to use ssl_context=(cert.pem, key.pem)",
            "For production: use Let's Encrypt with certbot for a free trusted certificate",
            "Add HTTP to HTTPS redirect to force all traffic over HTTPS"
        ],
        "fix_code": """# Option 1: Quick fix for local testing in app.py

if __name__ == '__main__':
    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000,
        ssl_context=('cert.pem', 'key.pem')  # Generate with openssl
    )

# Option 2: Add HTTP to HTTPS redirect
@app.before_request
def redirect_to_https():
    from flask import request, redirect
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
""",
        "fix_file": "app.py",
        "references": [
            "https://owasp.org/www-community/controls/Transport_Layer_Security_Cheat_Sheet",
            "https://letsencrypt.org/getting-started/"
        ],
        "verify_command": "curl -I https://127.0.0.1:5001/ --insecure | grep -i strict"
    },

    "Cross Site Scripting (Reflected)": {
        "risk": "High",
        "description": "A reflected XSS vulnerability was confirmed in the /search endpoint. User input from the 'q' parameter is reflected in the response without sanitization, allowing JavaScript execution in the victim's browser. Impact: cookie theft, session hijacking, page defacement.",
        "root_cause": "The /search route in target_app.py directly renders user input into the HTML template without escaping. The Jinja2 template may be using {{ q | safe }} or the input is injected into a raw HTML string.",
        "steps": [
            "Open target_app.py and locate the /search route",
            "Find where the 'q' parameter is used in the response",
            "Remove any | safe filter from Jinja2 templates — Jinja2 auto-escapes by default",
            "Add server-side input validation to reject suspicious input",
            "Use bleach library to sanitize HTML if you must allow some HTML",
            "Re-scan and run the XSS fuzzer payload again to verify it is blocked"
        ],
        "fix_code": """# In target_app.py - /search route fix

from markupsafe import escape

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Sanitize input - escape HTML special characters
    safe_q = escape(q)
    
    # Never do this: return f"<p>Results for: {q}</p>"  (XSS vulnerable)
    # Do this instead:
    return render_template('search.html', query=safe_q)

# In search.html template - use {{ query }} NOT {{ query | safe }}
# Jinja2 auto-escapes {{ query }} by default - this is safe
""",
        "fix_file": "target_app.py",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
        "verify_command": "curl 'http://127.0.0.1:5001/search?q=<script>alert(1)</script>' | grep -i script"
    },

    "SQL Injection": {
        "risk": "High",
        "description": "SQL Injection vulnerability detected. Attackers can manipulate database queries by injecting malicious SQL code through user input fields, potentially accessing, modifying, or deleting all data in the database.",
        "root_cause": "User input is directly concatenated into SQL queries without parameterization or prepared statements.",
        "steps": [
            "Open target_app.py and find all database query locations",
            "Replace string concatenation in SQL queries with parameterized queries",
            "Use ? placeholders in SQLite or %s in MySQL/PostgreSQL",
            "Never use f-strings or .format() to build SQL queries",
            "Add input validation to reject obviously malicious input",
            "Re-scan to verify the SQLi payloads are no longer effective"
        ],
        "fix_code": """# In target_app.py - SQL query fix

# VULNERABLE (never do this):
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# SAFE - use parameterized queries:
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

# For multiple parameters:
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
""",
        "fix_file": "target_app.py",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
        "verify_command": "Run ZAP Active Scan again and check SQL injection alerts"
    },

    "Absence of Anti-CSRF Tokens": {
        "risk": "Medium",
        "description": "No CSRF protection tokens found on forms. Attackers can trick authenticated users into submitting malicious requests (e.g., changing passwords, making purchases) by embedding hidden requests on attacker-controlled websites.",
        "root_cause": "Flask forms do not include CSRF tokens by default. The login and comment forms in target_app.py have no token validation.",
        "steps": [
            "Install Flask-WTF: pip install flask-wtf",
            "Set a SECRET_KEY in your Flask app configuration",
            "Add CSRFProtect to your app initialization",
            "Add {{ form.hidden_tag() }} to all HTML forms",
            "Validate CSRF token on all POST routes",
            "Re-scan to confirm CSRF tokens are present in form responses"
        ],
        "fix_code": """# In app.py - add CSRF protection

from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-this'
csrf = CSRFProtect(app)

# In your HTML template forms - add this inside every <form> tag:
# {{ csrf_token() }}

# Example in login.html:
# <form method="POST" action="/login">
#     <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#     ... rest of form fields
# </form>
""",
        "fix_file": "app.py",
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://flask-wtf.readthedocs.io/en/stable/csrf.html"
        ],
        "verify_command": "Run ZAP Passive Scan again and check for CSRF token alerts"
    }
}


def get_remediation(alert_name):
    for key in REMEDIATION_GUIDE:
        if key.lower() in alert_name.lower() or alert_name.lower() in key.lower():
            return REMEDIATION_GUIDE[key]
    return {
        "risk": "Unknown",
        "description": f"No specific remediation guide found for: {alert_name}",
        "root_cause": "Please refer to the OWASP Testing Guide for this vulnerability type.",
        "steps": [
            "Research this vulnerability type on OWASP.org",
            "Check the ZAP alert description for solution hints",
            "Apply the recommended fix from OWASP guidelines",
            "Re-scan to verify the fix"
        ],
        "fix_code": "# Refer to OWASP guidelines for this vulnerability type",
        "fix_file": "Varies",
        "references": ["https://owasp.org/www-project-top-ten/"],
        "verify_command": "Re-run ZAP scan after applying fix"
    }


def get_all_vuln_names():
    return list(REMEDIATION_GUIDE.keys())