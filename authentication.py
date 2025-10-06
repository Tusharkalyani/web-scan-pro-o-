#!/usr/bin/env python
# coding: utf-8

# In[4]:


import requests

class AuthTester:
    def __init__(self, session=None, timeout=5):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []

    def test_default_credentials(self, login_url, test_users):

        for username, password in test_users:
            try:
                resp = self.session.post(login_url, data={
                    "username": username,
                    "password": password
                }, timeout=self.timeout)

                if "Logout" in resp.text or resp.status_code == 200 and "dashboard" in resp.text.lower():
                    finding = {
                        "type": "Weak Credentials",
                        "username": username,
                        "password": password
                    }
                    self.findings.append(finding)
                    print(f"[+] Logged in with weak creds: {username}/{password}")
            except Exception as e:
                print("Error testing creds:", e)

    def test_insecure_cookies(self, url):

        try:
            resp = self.session.get(url, timeout=self.timeout)
            cookies = resp.cookies
            for cookie in cookies:
                if not cookie.secure:
                    self.findings.append({
                        "type": "Insecure Cookie",
                        "cookie": cookie.name,
                        "issue": "Missing Secure flag"
                    })

            if "Set-Cookie" in resp.headers:
                if "HttpOnly" not in resp.headers["Set-Cookie"]:
                    self.findings.append({
                        "type": "Insecure Cookie",
                        "cookie": "Unknown",
                        "issue": "Missing HttpOnly flag"
                    })
        except Exception as e:
            print("Error checking cookies:", e)

    def test_session_fixation(self, login_url, valid_user):

        try:

            pre_cookie = self.session.get(login_url, timeout=self.timeout).cookies.get_dict()


            self.session.post(login_url, data=valid_user, timeout=self.timeout)
            post_cookie = self.session.cookies.get_dict()

            if pre_cookie == post_cookie:
                self.findings.append({
                    "type": "Session Fixation",
                    "issue": "Session ID did not change after login"
                })
        except Exception as e:
            print("Error testing session fixation:", e)

    def run(self, login_url, test_users, valid_user):
        self.test_default_credentials(login_url, test_users)
        self.test_insecure_cookies(login_url)
        self.test_session_fixation(login_url, valid_user)
        return self.findings


if __name__ == "__main__":
    login_url =  "http://localhost:9090/dvwa/login.php"
    tester = AuthTester()

    test_users = [
        ("admin", "admin"),
        ("root", "toor"),
        ("test", "test123")
    ]
    valid_user = {"username": "admin", "password": "password"}

    results = tester.run(login_url, test_users, valid_user)

    print("\n Findings:")
    for r in results:
        print(r)
