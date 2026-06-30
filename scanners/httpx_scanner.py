import httpx
from bs4 import BeautifulSoup


def run_httpx_scan(url: str, timeout: int = 10, verify_ssl: bool = False):
    """
    Basic HTTP evidence collector using httpx.
    """

    evidence = {
        "url": url,
        "status_code": None,
        "headers": {},
        "redirect_chain": [],
        "body": "",
        "title": "",
        "final_url": ""
    }

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            verify=verify_ssl
        ) as client:

            response = client.get(url)

            evidence["status_code"] = response.status_code
            evidence["headers"] = dict(response.headers)
            evidence["body"] = response.text
            evidence["final_url"] = str(response.url)

            # Redirect chain
            evidence["redirect_chain"] = [
                str(r.url) for r in response.history
            ]

            # HTML title extraction
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            evidence["title"] = title

    except Exception as e:
        evidence["error"] = str(e)

    return evidence