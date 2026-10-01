"""URL cleaning, normalisation (entity identification) and domain extraction."""
import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

_HOST_OK = re.compile(r"^[a-z0-9.\-_]+$")
_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True)


def is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # decimal / hex encoded IPv4 such as http://3232235777/ or http://0xC0A80001/
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def clean_url(raw) -> tuple[str | None, str | None]:
    """Return (cleaned_url, None) or (None, reason_it_is_malformed)."""
    if not isinstance(raw, str):
        return None, "empty"
    u = raw.strip().strip('"').strip("'")
    if not u:
        return None, "empty"
    if len(u) > 2048:
        return None, "too_long"
    if re.search(r"\s", u):
        return None, "whitespace"
    if "://" not in u:
        u = "http://" + u
    scheme = u.split("://", 1)[0].lower()
    if scheme not in ("http", "https"):
        return None, "non_http_scheme"
    try:
        parts = urlsplit(u)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a bad port
    except ValueError:
        return None, "unparseable"
    if not host:
        return None, "no_host"
    try:
        host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        return None, "bad_host"
    if not is_ip(host) and ("." not in host or not _HOST_OK.match(host)):
        return None, "bad_host"
    return u, None


def normalize_key(url: str) -> str:
    """Canonical form used to decide whether two URLs are the same entity.

    Ignores: scheme (http vs https), letter case of the host, a leading 'www.',
    default ports, the fragment, and a trailing '/'.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    # Keep any "user@" part: "http://paypal.com@evil.com" is a classic phishing trick and
    # is not the same URL as "http://evil.com".
    userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
    if host.startswith("www."):
        host = host[4:]
    port = parts.port
    port_s = f":{port}" if port and port not in (80, 443) else ""
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{userinfo}{host}{port_s}{path}{query}"


@lru_cache(maxsize=None)
def split_host(host: str) -> tuple[str, str, str]:
    """(subdomain, registered_domain, suffix). Private suffixes in the Public Suffix List,
    such as vercel.app or github.io, count as public suffixes, so each site on them is its
    own domain. Platforms not on that list (weebly.com, godaddysites.com) are one domain."""
    if is_ip(host):
        return "", host, ""
    ext = _EXTRACT(host)
    reg = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    return ext.subdomain, (reg or host), ext.suffix


def registered_domain(url: str) -> str:
    return split_host((urlsplit(url).hostname or "").rstrip("."))[1]


# Free website builders and hosting platforms. Anyone can create a site on these in minutes,
# and much of today's phishing lives on them.
FREE_HOSTING = (
    "weebly.com", "weeblysite.com", "wixsite.com", "wixstudio.com", "vercel.app", "netlify.app",
    "github.io", "gitlab.io", "godaddysites.com", "000webhostapp.com", "firebaseapp.com",
    "web.app", "pages.dev", "workers.dev", "blogspot.com", "glitch.me", "herokuapp.com",
    "repl.co", "replit.app", "replit.dev", "wordpress.com", "square.site", "webflow.io",
    "ngrok-free.app", "ngrok.io", "ngrok.app", "duckdns.org", "azurewebsites.net", "appspot.com",
    "r2.dev", "ipfs.io", "dweb.link", "myshopify.com", "jimdosite.com", "yolasite.com",
    "mystrikingly.com", "carrd.co", "bubbleapps.io", "framer.app", "framer.website",
    "gitbook.io", "notion.site", "webnode.page", "site123.me", "wcomhost.com", "yzz.me",
    "sites.google.com", "storage.googleapis.com", "surge.sh", "onrender.com", "fly.dev",
    "translate.goog", "ukit.me", "tilda.ws", "hpage.com", "mobirisesite.com", "teachable.com",
)


def on_free_hosting(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in FREE_HOSTING)


def site_key(host: str) -> str:
    """The unit used when capping URLs per site. Normally the registered domain, but on a
    shared hosting platform each hosted site counts separately (abc.weebly.com and
    xyz.weebly.com are different sites run by different people)."""
    host = host.removeprefix("www.")
    return host if on_free_hosting(host) else split_host(host)[1]
