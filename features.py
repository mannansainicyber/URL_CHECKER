import re
from urllib.parse import urlparse


def extract_features(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    url_length = len(url)
    domain_length = len(domain)
    special_chars = len(re.findall(r"[^a-zA-Z0-9]", url))

    return {
        "url_length_ratio": min(url_length, 120) / 120,
        "domain_length_ratio": min(domain_length, 80) / 80,

        "dot_count": min(url.count("."), 10),
        "hyphen_count_domain": min(domain.count("-"), 5),
        "special_char_ratio": min(special_chars, 20) / 20,

        "path_length_ratio": min(len(path), 60) / 60,
        "query_length_ratio": min(len(query), 60) / 60,
        "path_segment_count": min(path.count("/"), 10),

        "has_ip_domain": int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain))),
        "has_at_symbol": int("@" in url),
        "starts_with_www": int(domain.startswith("www")),
        "contains_login": int("login" in url.lower()),
        "contains_verify": int("verify" in url.lower()),
        "contains_secure": int("secure" in url.lower()),
        "contains_update": int("update" in url.lower()),
        "contains_account": int("account" in url.lower()),
    }
