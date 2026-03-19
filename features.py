import re
import math
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "confirm", "banking", "password", "signin", "webscr",
    "ebayisapi", "paypal", "wallet", "support", "suspend"
]

ABUSED_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "pw", "top",
    "xyz", "club", "online", "site", "live", "click"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly"
}

BRAND_NAMES = {
    "paypal", "google", "apple", "amazon", "microsoft",
    "facebook", "netflix", "instagram", "twitter", "chase",
    "wellsfargo", "bankofamerica", "linkedin", "dropbox"
}

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    p = [v / len(s) for v in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p)

def _normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def _length_features(url, domain, path, query):
    return {
        "url_length_ratio":    min(len(url), 200) / 200,
        "domain_length_ratio": min(len(domain), 80) / 80,
        "path_length_ratio":   min(len(path), 100) / 100,
        "query_length_ratio":  min(len(query), 100) / 100,
    }

def _char_features(url, domain):
    special = len(re.findall(r"[^a-zA-Z0-9]", url))
    digits_in_domain = sum(c.isdigit() for c in domain)
    return {
        "special_char_ratio": min(special, 30) / 30,
        "digit_ratio_url":    sum(c.isdigit() for c in url) / max(len(url), 1),
        "digit_ratio_domain": digits_in_domain / max(len(domain), 1),
        "letter_ratio_url":   sum(c.isalpha() for c in url) / max(len(url), 1),
    }

def _structural_features(url, domain, path):
    subdomains = domain.split(".")
    return {
        "dot_count":           min(url.count("."), 10),
        "hyphen_count_domain": min(domain.count("-"), 8),
        "hyphen_count_url":    min(url.count("-"), 10),
        "path_segment_count":  min(path.count("/"), 10),
        "subdomain_count":     max(len(subdomains) - 2, 0),
        "query_param_count":   min(url.count("&") + 1 if "?" in url else 0, 10),
        "underscore_count":    min(url.count("_"), 5),
        "equal_sign_count":    min(url.count("="), 5),
    }

def _entropy_features(url, domain, path):
    return {
        "domain_entropy": round(_entropy(domain), 4),
        "url_entropy":    round(_entropy(url), 4),
        "path_entropy":   round(_entropy(path), 4),
    }

def _heuristic_features(url, domain):
    tld = domain.split(".")[-1] if "." in domain else ""
    hostname = domain.replace("www.", "")
    return {
        "has_ip_domain":       int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+", domain))),
        "has_at_symbol":       int("@" in url),
        "has_double_slash":    int("//" in url[8:]),
        "starts_with_www":     int(domain.startswith("www")),
        "is_https":            int(url.startswith("https")),
        "abused_tld":          int(tld in ABUSED_TLDS),
        "is_url_shortener":    int(any(s in domain for s in URL_SHORTENERS)),
        "has_port":            int(bool(re.search(r":\d{2,5}", domain))),
        "has_hex_encoding":    int("%2" in url.lower() or "%3" in url.lower()),
        "punycode_domain":     int("xn--" in domain),
        "brand_in_subdomain":  int(any(b in hostname.split(".")[0] for b in BRAND_NAMES)
                                   if len(hostname.split(".")) > 2 else False),
        "brand_in_path":       int(any(b in url.lower().split("/", 3)[-1] for b in BRAND_NAMES)),
        "has_redirect":        int(url.count("http") > 1),
    }

def _keyword_features(url):
    url_lower = url.lower()
    return {f"kw_{kw}": int(kw in url_lower) for kw in SUSPICIOUS_KEYWORDS}

def extract_features(url: str) -> dict:
    url = _normalize(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]  # strip port
    path   = parsed.path
    query  = parsed.query

    features = {}
    features.update(_length_features(url, domain, path, query))
    features.update(_char_features(url, domain))
    features.update(_structural_features(url, domain, path))
    features.update(_entropy_features(url, domain, path))
    features.update(_heuristic_features(url, domain))
    features.update(_keyword_features(url))
    return features