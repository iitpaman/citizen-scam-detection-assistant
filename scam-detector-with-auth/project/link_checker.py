"""
link_checker.py
Checks links inside a message WITHOUT opening them.
Fully rule-based: no internet or extra packages required.

NOTE: The trusted-domain lists below are not exhaustive.
Verify any domain before adding it, and update the lists regularly.
"""

import re
import ipaddress
from urllib.parse import urlparse

# =====================================================================
# 1. BRAND KEYWORDS -> OFFICIAL DOMAINS
#    If a link uses a brand name but is NOT one of its official
#    domains, it is flagged as a fake brand website.
# =====================================================================

BRANDS = {
    # ---------- Regulators / payment networks ----------
    "rbi": ["rbi.org.in"],
    "npci": ["npci.org.in"],
    "bhim": ["bhimupi.org.in", "npci.org.in"],

    # ---------- Public sector banks ----------
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbilife.co.in", "sbimf.com"],
    "pnb": ["pnbindia.in"],
    "bankofbaroda": ["bankofbaroda.in"],
    "canarabank": ["canarabank.com"],
    "unionbank": ["unionbankofindia.co.in"],
    "bankofindia": ["bankofindia.co.in"],
    "indianbank": ["indianbank.in"],
    "centralbank": ["centralbankofindia.co.in"],
    "ucobank": ["ucobank.com"],
    "bankofmaharashtra": ["bankofmaharashtra.in"],
    "iob": ["iob.in"],

    # ---------- Private sector banks ----------
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcfund.com"],
    "icici": ["icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com"],
    "axis": ["axisbank.com"],
    "axisbank": ["axisbank.com"],
    "kotak": ["kotak.com", "kotaksecurities.com"],
    "idbi": ["idbibank.in"],
    "yesbank": ["yesbank.in"],
    "indusind": ["indusind.com"],
    "idfc": ["idfcfirstbank.com"],
    "federalbank": ["federalbank.co.in"],
    "rblbank": ["rblbank.com"],
    "bandhan": ["bandhanbank.com"],
    "aubank": ["aubank.in"],

    # ---------- UPI / wallets / payments ----------
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["pay.google.com"],
    "googlepay": ["pay.google.com"],
    "mobikwik": ["mobikwik.com"],
    "cred": ["cred.club"],
    "razorpay": ["razorpay.com"],

    # ---------- Investments ----------
    "zerodha": ["zerodha.com"],
    "groww": ["groww.in"],
    "upstox": ["upstox.com"],
    "angelone": ["angelone.in"],
    "nseindia": ["nseindia.com"],
    "bseindia": ["bseindia.com"],
    "sebi": ["sebi.gov.in"],

    # ---------- Insurance ----------
    "lic": ["licindia.in"],
    "licindia": ["licindia.in"],

    # ---------- Shopping / food delivery ----------
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "myntra": ["myntra.com"],
    "meesho": ["meesho.com"],
    "ajio": ["ajio.com"],
    "nykaa": ["nykaa.com"],
    "snapdeal": ["snapdeal.com"],
    "bigbasket": ["bigbasket.com"],
    "blinkit": ["blinkit.com"],
    "jiomart": ["jiomart.com"],
    "tatacliq": ["tatacliq.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],

    # ---------- Travel ----------
    "irctc": ["irctc.co.in"],
    "makemytrip": ["makemytrip.com"],
    "goibibo": ["goibibo.com"],
    "redbus": ["redbus.in"],
    "ola": ["olacabs.com"],
    "uber": ["uber.com"],
    "indigo": ["goindigo.in"],
    "airindia": ["airindia.com"],

    # ---------- Telecom ----------
    "jio": ["jio.com"],
    "airtel": ["airtel.in"],
    "myvi": ["myvi.in"],
    "bsnl": ["bsnl.co.in"],

    # ---------- Government services ----------
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "indiapost": ["indiapost.gov.in"],
    "passport": ["passportindia.gov.in"],
    "digilocker": ["digilocker.gov.in"],
    "pmkisan": ["pmkisan.gov.in"],
    "parivahan": ["parivahan.gov.in"],
    "gst": ["gst.gov.in"],
    "mygov": ["mygov.in"],
    "umang": ["umang.gov.in"],
    "cybercrime": ["cybercrime.gov.in"],
    "sancharsaathi": ["sancharsaathi.gov.in"],

    # ---------- Global platforms ----------
    "google": ["google.com", "google.co.in"],
    "youtube": ["youtube.com", "youtu.be"],
    "gmail": ["gmail.com"],
    "whatsapp": ["whatsapp.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "telegram": ["telegram.org"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
}

# Short brand names that also appear inside normal English words
# (e.g. "lic" in "public"). These only match as a separate word.
EXACT_WORD_BRANDS = {
    "lic", "jio", "ola", "uber", "gst", "cred", "bhim", "ajio",
    "iob", "axis", "gpay", "apple", "umang",
}

# =====================================================================
# 2. OTHER TRUSTED DOMAINS (no brand keyword needed)
# =====================================================================

TRUSTED_DOMAINS = {
    "wikipedia.org", "github.com", "x.com", "twitter.com",
    "india.gov.in", "wa.me",
}

# Endings reserved for government / banks / academic institutions
TRUSTED_ENDINGS = (".gov.in", ".nic.in", ".bank.in", ".ac.in")

# =====================================================================
# 3. PLATFORMS WHERE ANYONE CAN CREATE A PAGE
#    Checked BEFORE the trusted list: sites.google.com belongs to
#    Google, but a scammer can still host a fake page there.
# =====================================================================

USER_HOSTED = {
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
    "storage.googleapis.com", "amazonaws.com", "firebaseapp.com", "web.app",
    "github.io", "netlify.app", "vercel.app", "pages.dev", "blogspot.com",
    "wixsite.com", "weebly.com", "000webhostapp.com",
}

# =====================================================================
# 4. OTHER RED-FLAG LISTS
# =====================================================================

# URL shortener services (hide the real destination)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd",
    "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "t.ly", "s.id", "v.gd",
}

# Cheap domain endings commonly abused in scams
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "info", "buzz", "live", "icu",
    "work", "click", "link", "loan", "win", "rest", "shop", "vip", "cyou",
    "cfd", "sbs",
}

# Scam-related words inside a URL
URL_KEYWORDS = [
    "kyc", "verify", "update", "login", "reward", "refund", "bonus", "free",
    "claim", "lottery", "prize", "gift", "block", "otp", "winner",
]

# =====================================================================
# Link extraction
# =====================================================================

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
    r"\.(?:com|in|net|org|co|io|me|ly|gl|gle|at|cc|be|dev|app|club|xyz|top|"
    r"online|site|info|buzz|live|icu|work|click|link|loan|win|rest|shop|vip|"
    r"cyou|cfd|sbs|sbi)"
    r"\b(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)


def extract_links(message):
    """Extracts all unique links from a message."""
    links = []
    for match in URL_PATTERN.finditer(message):
        url = match.group(0).rstrip(".,;:!?)]}'\"")
        if url and url not in links:
            links.append(url)
    return links


# =====================================================================
# Helper checks
# =====================================================================

def _matches(domain, root):
    """True if domain is root itself or a subdomain of root."""
    return domain == root or domain.endswith("." + root)


def _is_user_hosted(domain):
    return any(_matches(domain, host) for host in USER_HOSTED)


def _is_trusted(domain):
    if domain.endswith(TRUSTED_ENDINGS):
        return True
    if any(_matches(domain, d) for d in TRUSTED_DOMAINS):
        return True
    for official_list in BRANDS.values():
        if any(_matches(domain, d) for d in official_list):
            return True
    return False


def _find_brand(domain):
    """Returns the brand name used in the domain, or None."""
    words = set(re.split(r"[.\-]", domain))
    for brand in BRANDS:
        if brand in EXACT_WORD_BRANDS:
            if brand in words:
                return brand
        elif brand in domain:
            return brand
    return None


# =====================================================================
# Single link check
# =====================================================================

def check_link(url):
    """Checks one link and returns its risk level and reasons."""
    full_url = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    parsed = urlparse(full_url)
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]

    if not domain:
        return {"url": url, "domain": "", "risk": "Suspicious",
                "reasons": ["The link format looks unusual"]}

    reasons = []
    score = 0
    path = parsed.path.lower()

    # Anyone can create pages on these platforms
    if _is_user_hosted(domain):
        reasons.append("Hosted on a free platform where anyone can create a page - "
                       "check carefully before entering any details")
        score += 2

    # Official / trusted domain: no further checks needed
    elif _is_trusted(domain) and "@" not in parsed.netloc:
        return {"url": url, "domain": domain, "risk": "Safe",
                "reasons": ["This appears to be an official domain "
                            "(still, never share your OTP/PIN)"]}

    # 1. Android app (.apk) download - most dangerous
    if path.endswith(".apk"):
        reasons.append("The link downloads an app (.apk) that could compromise your phone")
        score += 3

    # 2. IP address instead of a domain name
    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
        reasons.append("Uses a numeric IP address instead of a website name")
        score += 3
    except ValueError:
        pass

    # 3. '@' trick - hides the real website
    if "@" in parsed.netloc:
        reasons.append("Contains '@', a trick used to hide the real website")
        score += 3

    # 4. Fake brand domain (e.g. sbi-kyc-update.xyz)
    if not _is_user_hosted(domain):
        brand = _find_brand(domain)
        if brand:
            reasons.append(f"Uses the name '{brand.upper()}' but is not its official website")
            score += 3

    # 5. Government-like name without a government domain
    if "gov" in domain and not domain.endswith(TRUSTED_ENDINGS):
        reasons.append("Looks like a government site but the domain is not .gov.in")
        score += 3

    # 6. Shortened link
    if domain in SHORTENERS:
        reasons.append("Shortened link - the real destination is hidden")
        score += 2

    # 7. Cheap domain ending
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Uses the '.{tld}' domain ending, commonly abused in scams")
        score += 2

    # 8. Not using https
    if url.lower().startswith("http://"):
        reasons.append("Not a secure (https) link")
        score += 1

    # 9. Too many hyphens
    if domain.count("-") >= 2:
        reasons.append("Website name contains multiple hyphens '-'")
        score += 1

    # 10. Long subdomain chain
    if not is_ip and domain.count(".") >= 3:
        reasons.append("Website name is unusually long or complex")
        score += 1

    # 11. Scam-related words in the link
    found = [w for w in URL_KEYWORDS if w in (domain + path)]
    if found:
        reasons.append("Scam-related words in the link: " + ", ".join(found))
        score += 1

    if score >= 3:
        risk = "High Risk"
    elif score >= 1:
        risk = "Suspicious"
    else:
        risk = "Safe"
        reasons.append("No major red flags found (still, be careful with unknown links)")

    return {"url": url, "domain": domain, "risk": risk, "reasons": reasons}


# =====================================================================
# Full message
# =====================================================================

RISK_ORDER = {"Safe": 0, "Suspicious": 1, "High Risk": 2}


def analyze_links(message):
    """
    Checks all links in a message.
    Returns: (results_list, highest_risk)
    If no links are found: ([], None)
    """
    results = [check_link(url) for url in extract_links(message)]
    if not results:
        return [], None
    worst = max(results, key=lambda r: RISK_ORDER[r["risk"]])["risk"]
    return results, worst


# =====================================================================
# Test
# =====================================================================

if __name__ == "__main__":
    test_messages = [
        "Aapka SBI account block ho jayega. Turant KYC update karein: http://sbi-kyc-update.xyz/login",
        "PM Kisan ki agli kist ke liye yahan register karein: https://pmkisan-gov-scheme.online/apply",
        "Bijli bill pending hai, aaj raat connection kat jayega. Pay karein: http://103.45.67.89/pay",
        "Paytm cashback 5000 pane ke liye yeh app install karein: https://paytm-bonus.club/paytm.apk",
        "Aapka parcel address galat hai, update karein: https://indiapost.gov.in.parcel-update.site/track",
        "Amazon order confirm karne ke liye login karein: https://www.amazon.in@secure-verify.xyz/login",
        "Jio recharge offer, abhi claim karein: https://jio-offer.top/claim",
        "Congratulations! Aapne iPhone jeeta hai. Details: bit.ly/win-iphone26",
        "KYC form yahan bharein: https://sites.google.com/view/sbi-kyc-form",
        "Your SBI statement is ready. Visit https://www.onlinesbi.sbi",
        "Aadhaar download karne ke liye: https://myaadhaar.uidai.gov.in",
        "Pay your credit card bill on https://cred.club",
        "Read the public notice at https://www.public-notice.com",
        "Check your bank's new website: https://sbi.bank.in",
        "Kal meeting 5 baje hai, office time pe aa jana",
    ]

    for msg in test_messages:
        print("=" * 70)
        print("MESSAGE:", msg)
        results, worst = analyze_links(msg)
        if not results:
            print("  No links found")
            continue
        for r in results:
            print(f"  -> {r['url']}  [{r['risk']}]")
            for reason in r["reasons"]:
                print("       -", reason)