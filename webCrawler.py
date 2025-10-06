

import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import json

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
    with open("dvwa_crawler_output.json", "w") as f:
        json.dump(result, f, indent=4)
    print("Pages found:", len(result["pages"]))
    print("Forms found:", len(result["forms"]))
    print("\nSample Forms:")
    for f in result["forms"][:5]:
        print(f)
    print("\nResults saved in dvwa_crawler_output.json")


