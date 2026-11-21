
import requests
import ipaddress
import tldextract

from urllib.parse import urlsplit


BAD_DOMAINS = set()
BAD_URLS = set()

# Store which feed reported each domain
THREAT_SOURCES = {}

# Use the bundled public suffix list.
# This avoids downloading the suffix list during deployment.
domain_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def normalize_domain(value):

    try:
        if not value:
            return None

        value = value.strip().lower()

        if not value.startswith(("http://", "https://")):
            value = "http://" + value

        parsed = urlsplit(value)
        domain = parsed.hostname

        if not domain:
            return None

        domain = domain.lower().rstrip(".")

        # Remove www. only from the beginning
        if domain.startswith("www."):
            domain = domain[4:]

        # Convert internationalized domains to ASCII
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None

        return domain

    except Exception as e:
        print("Domain normalization failed:", e)
        return None


def is_valid_threat_domain(domain):

    if not domain:
        return False

    try:
        # IP addresses are handled separately
        ipaddress.ip_address(domain)
        return False

    except ValueError:
        pass

    try:
        extracted = domain_extractor(domain)

        # Reject public suffixes such as:
        # com, org, co.uk
        if not extracted.domain or not extracted.suffix:
            return False

        return True

    except Exception as e:
        print("Domain validation failed:", domain, e)
        return False


def statistical_report(url):

    domain = normalize_domain(url)

    if not domain:
        return 1, None

    url_lower = url.strip().lower()

    # Check exact URL match
    if url_lower in BAD_URLS:
        source = THREAT_SOURCES.get(domain, "Threat Feed")
        return -1, source

    # Only perform domain matching on valid registrable domains
    if is_valid_threat_domain(domain):

        for bad in BAD_DOMAINS:

            if domain == bad or domain.endswith("." + bad):

                source = THREAT_SOURCES.get(
                    bad, "Threat Feed"
                )

                print("THREAT MATCH:", domain)
                print("MATCHED ENTRY:", bad)
                print("SOURCE:", source)

                return -1, source

    # No threat found
    return 1, None


def load_threat_feeds():

    global BAD_DOMAINS, BAD_URLS, THREAT_SOURCES

    if BAD_DOMAINS:
        print("Threat feeds already loaded.")
        return

    text_feeds = [
        "https://openphish.com/feed.txt",
        "https://phishing.army/download/phishing_army_blocklist.txt",
        "https://urlhaus.abuse.ch/downloads/text/"
    ]

    for feed_url in text_feeds:

        try:

            response = requests.get(feed_url, timeout=15)
            response.raise_for_status()

            for line in response.text.splitlines():

                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                # Get the first field
                line = line.split()[0].strip(" ,;")

                domain = normalize_domain(line)

                if not domain:
                    continue

                # Preserve full URL matching
                BAD_URLS.add(line.lower())

                # Only accept valid registrable domains
                if is_valid_threat_domain(domain):

                    BAD_DOMAINS.add(domain)

                    THREAT_SOURCES.setdefault(
                        domain, feed_url
                    )

        except Exception as e:

            print("Feed load failed:", feed_url, e)

    # -------- PHISHTANK --------

    try:

        response = requests.get(
            "https://data.phishtank.com/data/online-valid.json",
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        for entry in data:

            phishing_url = entry.get("url")

            if not phishing_url:
                continue

            phishing_url = phishing_url.strip().lower()

            domain = normalize_domain(phishing_url)

            if not domain:
                continue

            BAD_URLS.add(phishing_url)

            if is_valid_threat_domain(domain):

                BAD_DOMAINS.add(domain)

                THREAT_SOURCES.setdefault(
                    domain, "PhishTank"
                )

    except Exception as e:

        print("PhishTank load failed:", e)

    print(
        "Threat feeds loaded:",
        len(BAD_DOMAINS),
        "valid domains"
    )
