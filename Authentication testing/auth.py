

from typing import List, Dict, Optional, Tuple, Any
import time
import re
import requests
from http.cookies import SimpleCookie
from urllib.parse import urljoin

# Conservative default credential list (short): callers should replace with their own list
DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("test", "test"),
]

# Common keyword sets for detecting username/password fields
USERNAME_KEYWORDS = ("user", "email", "login", "username", "userid")
PASSWORD_KEYWORDS = ("pass", "password")
CSRF_KEYWORDS = ("csrf", "token", "authenticity_token", "xsrf")


class AuthTester:
    def __init__(self, session: Optional[requests.Session] = None, timeout: float = 10.0,
                 delay_between_attempts: float = 0.2, max_attempts: int = 50,
                 verbose: bool = False):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.delay = delay_between_attempts
        self.max_attempts = max_attempts
        self.findings: List[Dict[str, Any]] = []
        self.verbose = verbose

    def _log(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def _normalize_method(self, method: Optional[str]) -> str:
        return (method or "get").strip().lower()

    def _parse_set_cookie_headers(self, response: requests.Response) -> List[Dict[str, Any]]:
       
        raw_value = None
        cookies_raw = []

        # try multiple ways to access raw headers
        try:
            # urllib3 RawHeaders available via response.raw when using requests with HTTPAdapter
            if getattr(response, "raw", None) is not None:
                raw_headers = getattr(response.raw, "headers", None)
                if raw_headers is not None and hasattr(raw_headers, "get_all"):
                    cookies_raw = raw_headers.get_all("Set-Cookie") or []
        except Exception:
            pass

        # fallback to response.headers which often concatenates/keeps only one Set-Cookie
        if not cookies_raw:
            header_val = response.headers.get("Set-Cookie")
            if header_val:
                # try to split multiple cookies conservatively. Splitting Set-Cookie by comma is
                # risky because cookie values may contain commas; we split only when a comma is
                # followed by a space and a token with '=' which is typical of multiple Set-Cookie lines
                parts = re.split(r", (?=[^=]+=)", header_val)
                cookies_raw = parts

        parsed = []
        for raw in cookies_raw:
            try:
                sc = SimpleCookie()
                sc.load(raw)
                # SimpleCookie stores keys -> Morsel
                for k, morsel in sc.items():
                    attr = {"name": k, "value": morsel.value}
                    # Morsel has attributes in its coded form; copy common attributes if present
                    for a in ("httponly", "secure", "path", "domain", "samesite", "expires"):
                        # morsel may not expose these as attributes directly; check the output string
                        v = None
                        if a == "httponly":
                            v = ("HttpOnly" in raw) or ("httponly" in raw.lower())
                        elif a == "secure":
                            v = ("Secure" in raw) or ("secure" in raw.lower())
                        else:
                            # naive parse for other attributes
                            m = re.search(rf"{a}=([^;]+)", raw, flags=re.I)
                            v = m.group(1) if m else None
                        attr[a] = v
                    parsed.append(attr)
            except Exception:
                # final fallback: put raw string through as evidence
                parsed.append({"name": None, "raw": raw})
        return parsed

    def check_cookie_flags(self, response: requests.Response) -> List[Dict[str, Any]]:
       
        parsed = self._parse_set_cookie_headers(response)
        issues = []
        for p in parsed:
            # if raw fallback used, p may only have 'raw'
            if "raw" in p and p.get("raw"):
                issues.append({"issue": "Unable to parse Set-Cookie fully", "evidence": p.get("raw")})
                continue
            name = p.get("name")
            missing = []
            if not p.get("httponly"):
                missing.append("HttpOnly")
            if not p.get("secure"):
                missing.append("Secure")
            samesite = p.get("samesite")
            if not samesite or str(samesite).lower() not in ("lax", "strict"):
                missing.append("SameSite (Lax/Strict recommended)")

            if missing:
                issues.append({"cookie": name, "missing": missing, "raw": p})
        if issues:
            self.findings.append({"type": "cookie_flags", "issues": issues})
        return issues

    def _guess_form_fields(self, inputs: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
     
        data = {}
        usr_field = None
        pwd_field = None
        csrf_field = None
        for inp in inputs:
            name = (inp.get("name") or "").strip()
            lname = name.lower()
            value = inp.get("value", "")
            data[name] = value
            if any(k in lname for k in USERNAME_KEYWORDS) and not usr_field:
                usr_field = name
            if any(k in lname for k in PASSWORD_KEYWORDS) and not pwd_field:
                pwd_field = name
            if any(k in lname for k in CSRF_KEYWORDS) and not csrf_field:
                csrf_field = name
        # fallback heuristics
        if not (usr_field and pwd_field):
            keys = [k for k in data.keys() if k]
            if len(keys) >= 2:
                # choose first as username-like and second as password-like
                if not usr_field:
                    usr_field = keys[0]
                if not pwd_field:
                    pwd_field = keys[1]
        return usr_field, pwd_field, data

    def try_default_credentials(self, login_url: str, login_form: Dict[str, Any],
                                credentials: Optional[List[Tuple[str, str]]] = None,
                                max_trials: Optional[int] = None) -> List[Dict[str, Any]]:
     
        successes = []
        credentials = credentials or DEFAULT_CREDENTIALS
        max_trials = max_trials or self.max_attempts

        usr_field, pwd_field, base_data = self._guess_form_fields(login_form.get("inputs", []))
        if not usr_field or not pwd_field:
            self._log("Could not determine username/password fields for form at", login_url)
            return []

        method = self._normalize_method(login_form.get("method"))
        action = login_form.get("action") or login_url
        action_url = urljoin(login_url, action)

        trials = 0
        for username, password in credentials:
            if trials >= max_trials:
                break
            trials += 1
            data = dict(base_data)
            data[usr_field] = username
            data[pwd_field] = password

            try:
                if method == "post":
                    resp = self.session.post(action_url, data=data, timeout=self.timeout)
                else:
                    resp = self.session.get(action_url, params=data, timeout=self.timeout)
            except requests.RequestException as e:
                self._log("request error for", action_url, e)
                time.sleep(self.delay)
                continue

            # heuristics for success detection
            success = False
            evidence = {}
            if resp.status_code in (302, 303, 301) and resp.headers.get("Location"):
                success = True
                evidence["reason"] = f"redirect {resp.status_code} to {resp.headers.get('Location')}"
            body = (resp.text or "").lower()
            if any(term in body for term in ("logout", "sign out", "welcome", "dashboard", "my account")):
                success = True
                evidence.setdefault("reason", "body contains login-like keywords")

            if success:
                finding = {"type": "credential_success", "endpoint": action_url,
                           "username": username, "password": password, "evidence": evidence}
                self.findings.append(finding)
                successes.append(finding)

            # conservative delay
            time.sleep(self.delay)
        return successes

    def detect_session_fixation(self, login_url: str, login_form: Dict[str, Any],
                                 valid_credentials: Optional[Tuple[str, str]] = None,
                                 attacker_cookie: Optional[Tuple[str, str]] = None) -> Dict[str, Any]:
       
        result = {"endpoint": login_url, "evidence": [], "vulnerable": False}

        # fetch the page to capture initial cookies / hidden tokens
        try:
            initial_resp = self.session.get(login_url, timeout=self.timeout)
        except requests.RequestException as e:
            result["error"] = f"initial GET failed: {e}"
            return result

        cookies_before = requests.utils.dict_from_cookiejar(self.session.cookies)
        result["cookies_before"] = dict(cookies_before)

        # option: set attacker cookie
        if attacker_cookie:
            name, val = attacker_cookie
            self.session.cookies.set(name, val)
            result["attacker_cookie_set"] = {name: val}

        # perform successful login if valid_credentials provided
        if valid_credentials:
            username, password = valid_credentials
            usr_field, pwd_field, base_data = self._guess_form_fields(login_form.get("inputs", []))
            if not (usr_field and pwd_field):
                result["error"] = "Could not identify username/password fields for fixation test"
                return result
            data = dict(base_data)
            data[usr_field] = username
            data[pwd_field] = password
            method = self._normalize_method(login_form.get("method"))
            action = login_form.get("action") or login_url
            action_url = urljoin(login_url, action)
            try:
                if method == "post":
                    resp = self.session.post(action_url, data=data, timeout=self.timeout)
                else:
                    resp = self.session.get(action_url, params=data, timeout=self.timeout)
            except requests.RequestException as e:
                result["error"] = f"login POST failed: {e}"
                return result

            cookies_after = requests.utils.dict_from_cookiejar(self.session.cookies)
            result["cookies_after"] = dict(cookies_after)

            # crude check: if any cookie value matches the attacker cookie value, possibly vulnerable
            if attacker_cookie:
                name, val = attacker_cookie
                if cookies_after.get(name) == val:
                    result["vulnerable"] = True
                    result["evidence"].append(f"session cookie {name} preserved after login (value matches attacker token)")
            else:
                # if no attacker cookie set, check whether server rotated session id
                # we try to detect common session cookie names
                session_names = ["session", "sessionid", "sid", "jsessionid", "phpsessid"]
                before_vals = {k: v for k, v in cookies_before.items() if k.lower() in session_names}
                after_vals = {k: v for k, v in cookies_after.items() if k.lower() in session_names}
                if before_vals and not after_vals:
                    # session cookie disappeared; server may have rotated — good
                    result["evidence"].append("session cookie before login disappeared after login (possible rotation)")
                elif before_vals and after_vals and before_vals == after_vals:
                    result["vulnerable"] = True
                    result["evidence"].append("session cookie(s) identical before and after login — possible fixation")
                else:
                    result["evidence"].append("no clear fixation detected by heuristics")

            return result

        else:
            # No valid credentials provided: limited checks only
            result["note"] = "No valid credentials provided; only best-effort checks performed."
            # submit a dummy form to see if cookies change
            usr_field, pwd_field, base_data = self._guess_form_fields(login_form.get("inputs", []))
            data = dict(base_data)
            if usr_field:
                data[usr_field] = "test"
            if pwd_field:
                data[pwd_field] = "test"
            method = self._normalize_method(login_form.get("method"))
            action = login_form.get("action") or login_url
            action_url = urljoin(login_url, action)
            try:
                if method == "post":
                    resp = self.session.post(action_url, data=data, timeout=self.timeout)
                else:
                    resp = self.session.get(action_url, params=data, timeout=self.timeout)
                cookies_after = requests.utils.dict_from_cookiejar(self.session.cookies)
                result["cookies_after"] = dict(cookies_after)
                if cookies_before and (cookies_before == cookies_after):
                    result["evidence"].append("cookies identical before and after dummy submit — cannot conclude fixation")
                else:
                    result["evidence"].append("cookies changed after dummy submit — manual review recommended")
            except requests.RequestException as e:
                result["error"] = f"dummy submit failed: {e}"
            return result

if __name__ == "__main__":
    tester = AuthTester(verbose=True)

    # Example: a form dict captured by your crawler for https://example.com/login
    example_form = {
        "action": "/login",
        "method": "POST",
        "inputs": [
            {"name": "username", "value": ""},
            {"name": "password", "value": ""},
            {"name": "csrf_token", "value": ""},
        ]
    }

    # IMPORTANT: Replace the following with a real URL you are authorized to test
    url = "https://example.com/login"

    # 1) attempt default credentials (short list here)
    print("Trying default credentials (short list)...")
    successes = tester.try_default_credentials(url, example_form)
    print("Successes:", successes)

    # 2) check cookie flags on a response (do a GET to the page first)
    try:
        resp = tester.session.get(url, timeout=5)
        issues = tester.check_cookie_flags(resp)
        print("Cookie issues:", issues)
    except Exception as e:
        print("Could not fetch page for cookie flags check:", e)

    # 3) detect session fixation (manual attacker cookie)
    fixation_result = tester.detect_session_fixation(url, example_form, attacker_cookie=("session", "attacker-123"))
    print("Fixation test result:", fixation_result)
