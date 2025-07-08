import re
import pandas as pd
from urllib.parse import urlparse

def extract_features(url):
    features = {}

    # --- Basic Features (already in your code) ---
    features['url_length'] = len(url)
    features['count_dot'] = url.count('.')
    features['count_at'] = url.count('@')
    features['count_hyphen'] = url.count('-')
    features['count_slash'] = url.count('/')
    features['has_https'] = 1 if url.lower().startswith('https') else 0
    features['has_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_login_word'] = 1 if any(word in url.lower() for word in ['login', 'secure', 'verify']) else 0
    features['is_gov_domain'] = 1 if ('.gov.in' in url or '.nic.in' in url) else 0
    # --- 🔥 NEW FEATURES 🔥 ---

    # 1. Suspicious TLD check
    suspicious_tlds = ['.ru', '.cn', '.tk', '.top', '.xyz']
    features['has_suspicious_tld'] = int(any(url.lower().endswith(tld) for tld in suspicious_tlds))

    # 2. Presence of known brand (lookalike attack)
    brand_keywords = ['paypal', 'google', 'apple', 'amazon', 'bofa', 'facebook', 'github', 'bank', 'login']
    features['has_brand_name'] = int(any(brand in url.lower() for brand in brand_keywords))

    # 3. URL has digits (common in fakes like "paytm123.com")
    features['count_digits'] = sum(c.isdigit() for c in url)

    # 4. URL path length
    parsed = urlparse(url)
    features['path_length'] = len(parsed.path)

    # 5. Suspicious subdomain depth (e.g., "login.verify.update.bankofamerica.com")
    features['subdomain_count'] = len(parsed.netloc.split('.')) - 2  # root + tld

    return features
