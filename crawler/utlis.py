# utils.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin, urldefrag, urlparse
from bs4 import BeautifulSoup


def get_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "wesitelink)",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        absolute = urljoin(base_url, href)
        # Remove(#section)
        absolute, _ = urldefrag(absolute)
        links.add(absolute)

    return list(links)


def extract_forms(html, page_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        form_details = {
            "method": form.get("method", "get").lower(),
            "action": urljoin(page_url, form.get("action", "")),
            "inputs": []
        }

        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_type = input_tag.get("type", "text")
            input_name = input_tag.get("name")
            input_value = input_tag.get("value", "")

            form_details["inputs"].append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })

        forms.append(form_details)

    return forms


def is_same_domain(base, url):
    base_domain = urlparse(base).netloc.lower()
    url_domain = urlparse(url).netloc.lower()
    return base_domain == url_domain
