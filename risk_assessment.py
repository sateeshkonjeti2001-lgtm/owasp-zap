RISK_DATA = {
    "Missing Anti-clickjacking Header": {
        "cvss_score": 6.1,
        "attack_scenario": "An attacker creates a fake website and loads your application inside an invisible iframe. When the victim visits the attacker's site, they unknowingly click buttons on your hidden app — like confirming a money transfer or changing their password.",
        "real_world_analogy": "Imagine your shop glass door is transparent. A thief puts a fake poster over it showing 'FREE GIFT — CLICK HERE'. When customers push the fake button, they are actually pushing the real door open for the thief to walk in.",
        "what_attacker_can_do": [
            "Trick users into clicking hidden buttons without their knowledge",
            "Force users to submit forms, transfer funds, or change account settings",
            "Steal sensitive actions performed by logged-in users",
            "Deface your website appearance for victims"
        ],
        "impact": {
            "confidentiality": "Low — attacker cannot directly read data",
            "integrity": "High — attacker can modify user actions and data",
            "availability": "Low — service remains available",
            "business_impact": "Users lose trust, financial transactions get manipulated, legal liability for unauthorized actions"
        },
        "likelihood": "Medium — requires social engineering to lure victim to attacker site",
        "affected_assets": ["Login page", "Payment pages", "Account settings", "Any authenticated page"],
        "risk_score": 62,
        "risk_level": "Medium",
        "urgency": "Fix within 7 days"
    },

    "Content Security Policy (CSP) Header Not Set": {
        "cvss_score": 6.1,
        "attack_scenario": "An attacker injects malicious JavaScript into your page through a comment box, search field, or third-party script. Since there is no CSP, the browser executes any script from any source — including the attacker's server — stealing cookies and session tokens.",
        "real_world_analogy": "Imagine your office has no security guard and no entry policy. Anyone can walk in, sit at an employee's desk, read files, and walk out. No one checks if they belong there. CSP is the security guard who checks IDs at the door.",
        "what_attacker_can_do": [
            "Inject and execute malicious scripts in victim's browser",
            "Steal session cookies and hijack user accounts",
            "Load malware from external attacker-controlled servers",
            "Redirect users to phishing pages silently",
            "Keylog everything the user types on your site"
        ],
        "impact": {
            "confidentiality": "High — session tokens and personal data exposed",
            "integrity": "High — page content and user actions can be modified",
            "availability": "Medium — attacker can crash or redirect the page",
            "business_impact": "Account takeovers, data theft, regulatory fines (GDPR), severe reputation damage"
        },
        "likelihood": "High — XSS is the #1 most exploited web vulnerability (OWASP Top 10)",
        "affected_assets": ["All web pages", "User session data", "Authentication cookies", "Form data"],
        "risk_score": 74,
        "risk_level": "High",
        "urgency": "Fix within 48 hours"
    },

    "X-Content-Type-Options Header Missing": {
        "cvss_score": 4.3,
        "attack_scenario": "An attacker uploads a file disguised as an image (e.g., malware.jpg that is actually a JavaScript file). Without this header, the browser sniffs the file and executes it as JavaScript instead of displaying it as an image, running the attacker's code.",
        "real_world_analogy": "Imagine a security guard at a building who never checks what people carry in bags. Someone walks in with a weapon disguised as an umbrella. Without bag checking (MIME sniffing protection), dangerous items get through unchecked.",
        "what_attacker_can_do": [
            "Upload malicious files disguised as harmless images or documents",
            "Force browsers to execute uploaded files as scripts",
            "Bypass file upload validation through MIME type confusion",
            "Execute drive-by malware through innocent-looking files"
        ],
        "impact": {
            "confidentiality": "Medium — user data can be accessed via script execution",
            "integrity": "Medium — malicious code execution possible",
            "availability": "Low — direct service disruption unlikely",
            "business_impact": "Malware distribution through your platform, legal liability, user device compromise"
        },
        "likelihood": "Low to Medium — requires file upload functionality to be present",
        "affected_assets": ["File upload features", "Image display pages", "Document download endpoints"],
        "risk_score": 43,
        "risk_level": "Low",
        "urgency": "Fix within 30 days"
    },

    "Server Leaks Version Information": {
        "cvss_score": 5.3,
        "attack_scenario": "Your server response headers reveal 'Werkzeug/3.1.0 Python/3.13.0'. An attacker searches for known CVEs (public vulnerabilities) for exactly these versions and finds an unpatched exploit. They now have a precise roadmap to attack your server.",
        "real_world_analogy": "Imagine a bank that puts a sign outside saying 'We use Safe Model XYZ-2000 with firmware 1.2.3'. A thief looks up that exact safe model online, finds the known bypass technique for firmware 1.2.3, and comes back at night with the exact tools needed to crack it.",
        "what_attacker_can_do": [
            "Look up known CVEs for your exact framework and Python version",
            "Target specific unpatched vulnerabilities with ready-made exploits",
            "Skip generic attacks and go straight to version-specific exploits",
            "Plan a precise attack without any guessing or scanning"
        ],
        "impact": {
            "confidentiality": "Medium — enables targeted attacks on sensitive data",
            "integrity": "Medium — version-specific exploits can modify system behavior",
            "availability": "Medium — known DoS vulnerabilities can be exploited",
            "business_impact": "Targeted attacks become easier, reduces attacker effort by 80%, increases successful breach probability"
        },
        "likelihood": "High — attackers routinely collect version fingerprints as first recon step",
        "affected_assets": ["Web server", "Application framework", "All endpoints"],
        "risk_score": 53,
        "risk_level": "Medium",
        "urgency": "Fix within 14 days"
    },

    "Cross Site Scripting (Reflected)": {
        "cvss_score": 8.1,
        "attack_scenario": "An attacker sends a victim a specially crafted URL containing JavaScript code in the search parameter. When the victim clicks the link, your server reflects the malicious script back in the response and the victim's browser executes it — stealing their session cookie and sending it to the attacker.",
        "real_world_analogy": "Imagine a post office that delivers whatever letter you write without checking the contents. An attacker sends a letter to a victim saying 'Sign this form'. The form actually says 'Transfer all your money to attacker'. The victim signs thinking it is from the post office. Your server is the post office delivering the attacker's malicious message.",
        "what_attacker_can_do": [
            "Steal session cookies and completely take over victim accounts",
            "Perform any action the victim can do — post, delete, transfer, purchase",
            "Redirect victim to phishing site that looks identical to yours",
            "Install browser-based keylogger to capture passwords",
            "Perform actions on behalf of admin users if admin clicks malicious link"
        ],
        "impact": {
            "confidentiality": "High — full session and credential theft",
            "integrity": "High — complete account takeover and data manipulation",
            "availability": "Medium — can be used to lock users out of accounts",
            "business_impact": "Complete account compromise, financial fraud, mass user data theft, GDPR violation fines up to 4% annual revenue"
        },
        "likelihood": "High — XSS confirmed by active scan with payloads reflected in response",
        "affected_assets": ["Search functionality", "All URL parameters", "User accounts", "Admin panel if admin clicks link"],
        "risk_score": 88,
        "risk_level": "Critical",
        "urgency": "Fix IMMEDIATELY — within 24 hours"
    },

    "SQL Injection": {
        "cvss_score": 9.8,
        "attack_scenario": "An attacker types ' OR 1=1-- into your login form. Your database executes this as a SQL command instead of treating it as text, bypassing authentication entirely. The attacker logs in as admin without a password, then dumps your entire user database including passwords, emails, and payment details.",
        "real_world_analogy": "Imagine a bank teller who follows any instruction written on a note, no matter who gives it. A thief writes on a deposit slip: 'Also transfer all money from account 12345 to my account'. The teller follows both instructions. SQL Injection is giving your database instructions it was never supposed to receive — and it obeys.",
        "what_attacker_can_do": [
            "Bypass login authentication entirely without valid credentials",
            "Extract the entire database — all users, passwords, emails, payment data",
            "Modify or delete all records in the database",
            "Execute system commands on the database server",
            "Use the database server as a pivot to attack internal network"
        ],
        "impact": {
            "confidentiality": "Critical — full database dump including all user PII",
            "integrity": "Critical — all data can be modified or destroyed",
            "availability": "Critical — entire database can be wiped",
            "business_impact": "Complete data breach, regulatory fines (GDPR, IT Act), criminal liability, business shutdown risk, loss of all customer trust"
        },
        "likelihood": "High — automated tools can exploit SQLi in minutes once discovered",
        "affected_assets": ["User database", "All application data", "Admin accounts", "Payment records", "Database server OS"],
        "risk_score": 98,
        "risk_level": "Critical",
        "urgency": "Fix IMMEDIATELY — stop the application if needed"
    },

    "Absence of Anti-CSRF Tokens": {
        "cvss_score": 6.5,
        "attack_scenario": "A victim is logged into your banking app. They visit an attacker's site which has a hidden form that auto-submits to your server: 'Transfer Rs.50,000 to attacker account'. Since the victim is already logged in, your server accepts the request as legitimate. The transfer happens without the victim knowing.",
        "real_world_analogy": "Imagine someone forges a letter with your signature and sends it to your bank saying 'Transfer all my money'. The bank recognises your account but cannot verify you actually signed the letter. CSRF tokens are like a secret handshake code that only you and the bank know — forged letters cannot have it.",
        "what_attacker_can_do": [
            "Force logged-in users to perform actions without their knowledge",
            "Transfer funds, change passwords, or modify account settings silently",
            "Post content, delete data, or make purchases on behalf of users",
            "Target admin users to perform privileged actions like creating admin accounts"
        ],
        "impact": {
            "confidentiality": "Low — cannot read data directly",
            "integrity": "High — all state-changing operations can be forged",
            "availability": "Medium — account lockout or data deletion possible",
            "business_impact": "Unauthorized financial transactions, account modification, legal liability for actions users did not perform"
        },
        "likelihood": "Medium — requires victim to visit attacker-controlled page while logged in",
        "affected_assets": ["Login form", "Account settings", "Payment forms", "Any POST action while authenticated"],
        "risk_score": 65,
        "risk_level": "Medium",
        "urgency": "Fix within 7 days"
    },

    "HTTP Only Site": {
        "cvss_score": 7.4,
        "attack_scenario": "A user on public WiFi (cafe, airport) connects to your site over HTTP. An attacker on the same network intercepts all traffic using a tool like Wireshark. They can see the login credentials, session cookies, and all data in plain text — then reuse the session cookie to log in as the victim.",
        "real_world_analogy": "Imagine sending a postcard with your bank password written on it. Every postman who handles it, every sorting office it passes through, can read it. HTTPS is like sending the same message in a locked sealed envelope that only the recipient can open.",
        "what_attacker_can_do": [
            "Intercept all data in plain text on shared networks (cafes, airports, hotels)",
            "Steal login credentials and session tokens via man-in-the-middle attack",
            "Modify data in transit — inject ads, malware, or fake content",
            "Perform session hijacking by replaying captured cookies",
            "Silently monitor all user activity on your site"
        ],
        "impact": {
            "confidentiality": "Critical — all data transmitted is visible to network attackers",
            "integrity": "High — data can be modified in transit without detection",
            "availability": "Low — service itself remains up",
            "business_impact": "Mass credential theft, session hijacking at scale, Google Chrome marks site as 'Not Secure' reducing user trust and SEO ranking"
        },
        "likelihood": "High — tools like Wireshark make this trivial on shared networks",
        "affected_assets": ["All pages and data", "Login credentials", "Session cookies", "Personal and payment data"],
        "risk_score": 79,
        "risk_level": "High",
        "urgency": "Fix within 48 hours"
    }
}


def calculate_overall_risk(high_count, medium_count, low_count):
    score = (high_count * 30) + (medium_count * 10) + (low_count * 3)
    score = min(score, 100)
    if score >= 75:
        level = "Critical"
        color = "critical"
        message = "Immediate action required — system is at serious risk"
    elif score >= 50:
        level = "High"
        color = "high"
        message = "Urgent fixes needed — significant vulnerabilities present"
    elif score >= 25:
        level = "Medium"
        color = "medium"
        message = "Moderate risk — schedule fixes in next sprint"
    else:
        level = "Low"
        color = "low"
        message = "Low risk — monitor and fix when possible"
    return {"score": score, "level": level, "color": color, "message": message}


def get_risk_data(alert_name):
    for key in RISK_DATA:
        if key.lower() in alert_name.lower() or alert_name.lower() in key.lower():
            return RISK_DATA[key]
    return {
        "cvss_score": 5.0,
        "attack_scenario": f"An attacker exploits the '{alert_name}' vulnerability to gain unauthorised access or manipulate application behaviour.",
        "real_world_analogy": "Like leaving a window open in your house — it may seem minor but gives an attacker a way in that should not exist.",
        "what_attacker_can_do": [
            "Exploit the vulnerability to gain unauthorised access",
            "Use it as a stepping stone to find deeper vulnerabilities",
            "Combine with other vulnerabilities for a chained attack"
        ],
        "impact": {
            "confidentiality": "Unknown — requires detailed analysis",
            "integrity": "Unknown — requires detailed analysis",
            "availability": "Unknown — requires detailed analysis",
            "business_impact": "Potential data exposure, reputation damage, or service disruption"
        },
        "likelihood": "Medium — depends on attacker skill and access",
        "affected_assets": ["Application endpoints", "User data", "Server resources"],
        "risk_score": 50,
        "risk_level": "Medium",
        "urgency": "Assess and fix within 14 days"
    }