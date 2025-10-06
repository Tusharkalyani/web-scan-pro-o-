#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import re, time, json, requests
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from collections import deque


AUTHORIZATION_CONFIRMED = False     
TARGET_BASE = "http://localhost/setup.php"
LOGIN_PATH = "/login.php"
USERNAME = "admin"
PASSWORD = "password"
CRAWL_SAVE = "dvwa_crawl.json"
FINDINGS_SAVE = "week6_access_control_findings.json"

MAX_PAGES = 40
REQUEST_TIMEOUT = 6
PASSIVE_DELAY = 0.05
ACTIVE_DELAY = 0.5
MAX_ID_PROBES_PER_ENDPOINT = 5
ID_PARAM_HINTS = re.compile(r"(?:^|_|\b)(id|user|order|invoice|file|doc|profile|acct|account)(?:$|\b)", re.I)


session = requests.Session()
session.headers.update({"User-Agent":"Week6-IDOR-Tester/1.0"})
findings = []


try:
        return BeautifulSoup(html, "lxml")
         except Exception:
          return BeautifulSoup(html, "html.parser")

def full_target(path):
    return urljoin(TARGET_BASE, path)

def save_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def is_uuid_like(s):
    return bool(re.match(r"^[0-9a-fA-F\-]{8,36}$", s))


def dvwa_login(username=USERNAME, password=PASSWORD):
    login_url = full_target(LOGIN_PATH)
    payload = {"username": username, "password": password, "Login": "Login"}
    try:
        r = session.post(login_url, data=payload, timeout=REQUEST_TIMEOUT)

        body = (r.text or "").lower()
        if any(x in body for x in ["logout", "dvwa", "security level"] ) or r.status_code in (302,303):
            print("[+] Login appears successful.")
            return True
        else:
            print("[!] Login response received but success not clearly detected. Check manually.")
            return True  # still return True so crawler can run; you can adjust logic
    except Exception as e:
        print("[!] Login failed:", e)
        return False


def extract_links(html, base_url):
    soup = make_soup(html)
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("javascript:") or href.startswith("#"):
            continue
        absolute = urljoin(base_url, href)
        links.append(absolute)
    return links

def extract_forms(html, page_url):
    soup = make_soup(html)
    forms = []
    for f in soup.find_all("form"):
        action = f.get("action") or page_url
        action = urljoin(page_url, action)
        method = (f.get("method") or "GET").upper()
        inputs = []
        for inp in f.find_all(["input","textarea","select"]):
            name = inp.get("name")
            typ = (inp.get("type") or inp.name or "").lower()
            value = inp.get("value", "")
            inputs.append({"name": name, "type": typ, "value": value})
        forms.append({"page": page_url, "action": action, "method": method, "inputs": inputs})
    return forms

def crawl(start=TARGET_BASE, max_pages=MAX_PAGES, delay=PASSIVE_DELAY):
    visited = set()
    pages = {}
    forms = []
    q = deque([start])
    while q and len(visited) < max_pages:
        url = q.popleft()
        if url in visited:
            continue


# In[ ]:



