#to pause the program means delay
import time 
#urlib is standard library for handling URLs
from urllib.parse import urlparse, urljoin, urlencode, quote, unquote , urldefrag
#beautifulsoup to extact html data
from bs4 import BeautifulSoup
#request is third-party library in Python for making HTTP requests easily
import requests
#inbuild libraries 
from .utlis import get_session, extract_links, extract_forms, is_same_domain
#to show progreess
from tqdm import tqdm


class crawler:
    def __init__(self,base,max_pages=50,delay=1,session=None):
        self.base = base.rstrip("/")  # normalize base
        self.max_pages = max_pages
        self.delay = delay
        self.session = session or get_session() 
        self.visited = set()       
        self.queue = [self.base]    
        self.pages = {}            
        self.forms = {}
    
    def crawl(self):
        while self.queue and len(self.visited) < self.max_pages:
            url = self.queue.pop(0).rstrip("/")   # FIFO pop  normalize
            
# Skip already visited
            if url in self.visited:
                continue

# Skip off-domain URLs
            if not is_same_domain(self.base, url):
                continue

            try:
# Fetch page
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                html = resp.text
            except Exception as e:
                print(f"[!] Error fetching {url}: {e}")
                self.visited.add(url)
                continue

# Store raw HTML
            self.pages[url] = html
# Extract and store forms
            page_forms = extract_forms(html, url)
            if page_forms:
                self.forms[url] = page_forms
            links = extract_links(html, url)

            for link in links:
                if not link:  
                    continue
                link, _ = urldefrag(link)
                link = link.rstrip("/")
                if (
                    link not in self.visited
                    and link not in self.queue
                    and is_same_domain(self.base, link)
                ):
                    self.queue.append(link)
            self.visited.add(url)
            time.sleep(self.delay)

        return self.pages, self.forms
