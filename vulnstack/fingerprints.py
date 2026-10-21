"""Static, data-driven technology fingerprint definitions.

Fingerprints are plain data so they can be maintained and extended without
touching the detection engine (see :mod:`vulnstack.fingerprinting`). Each
:class:`Fingerprint` describes one technology and a list of :class:`Matcher`
rules. A matcher inspects one kind of HTTP evidence (a header, the HTML body,
a meta-generator tag, a script/stylesheet URL, or a cookie name) and may
optionally capture a version string via a regular-expression group.

Confidence reflects how strongly the *evidence* implies the technology — e.g.
a ``Server`` header naming Apache is high confidence for "a server reported
Apache", while a jQuery script URL is high confidence for jQuery but says
nothing about any backend framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Matcher methods
M_HEADER = "header"          # header value regex (target = header name)
M_HEADER_PRESENT = "header_present"  # header merely present (target = header name)
M_HTML = "html"              # regex against HTML body
M_META_GENERATOR = "meta_generator"  # regex against <meta name=generator> content
M_SCRIPT = "script_src"      # regex against <script src> URLs
M_LINK = "link_href"         # regex against <link href> URLs
M_COOKIE = "cookie"          # regex against Set-Cookie cookie names


@dataclass(frozen=True)
class Matcher:
    method: str
    pattern: str
    target: str = ""               # header/cookie name where applicable
    version_group: int | None = None  # regex group holding the version, if any
    confidence: str = MEDIUM


@dataclass(frozen=True)
class Fingerprint:
    name: str                      # canonical display name
    category: str
    vendor: str = ""
    matchers: list[Matcher] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fingerprint catalogue
# ---------------------------------------------------------------------------

FINGERPRINTS: list[Fingerprint] = [
    # --- Web servers -------------------------------------------------------
    Fingerprint(
        "Apache HTTP Server", "Web server", "Apache",
        [
            Matcher(M_HEADER, r"Apache(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Nginx", "Web server", "Nginx",
        [
            Matcher(M_HEADER, r"nginx(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Microsoft IIS", "Web server", "Microsoft",
        [
            Matcher(M_HEADER, r"Microsoft-IIS(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "LiteSpeed", "Web server", "LiteSpeed Technologies",
        [
            Matcher(M_HEADER, r"LiteSpeed(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    # --- Languages / runtimes ---------------------------------------------
    Fingerprint(
        "PHP", "Programming language", "PHP",
        [
            Matcher(M_HEADER, r"PHP/([0-9]+(?:\.[0-9]+)+)", "X-Powered-By", 1, HIGH),
            Matcher(M_HEADER, r"PHP/([0-9]+(?:\.[0-9]+)+)", "Server", 1, MEDIUM),
            Matcher(M_COOKIE, r"^PHPSESSID$", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "ASP.NET", "Web framework", "Microsoft",
        [
            Matcher(M_HEADER, r"ASP\.NET", "X-Powered-By", None, HIGH),
            Matcher(M_HEADER, r"([0-9]+(?:\.[0-9]+)+)", "X-AspNet-Version", 1, HIGH),
            Matcher(M_COOKIE, r"^ASP\.NET_SessionId$", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Node.js", "Runtime", "OpenJS Foundation",
        [
            Matcher(M_HEADER, r"Express", "X-Powered-By", None, MEDIUM),
        ],
    ),
    # --- CMS / application platforms --------------------------------------
    Fingerprint(
        "WordPress", "CMS", "WordPress",
        [
            Matcher(M_META_GENERATOR, r"WordPress(?:\s+([0-9]+(?:\.[0-9]+)+))?", version_group=1, confidence=HIGH),
            Matcher(M_LINK, r"/wp-content/", confidence=HIGH),
            Matcher(M_SCRIPT, r"/wp-includes/", confidence=HIGH),
            Matcher(M_HTML, r"/wp-json/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Drupal", "CMS", "Drupal",
        [
            Matcher(M_META_GENERATOR, r"Drupal(?:\s+([0-9]+(?:\.[0-9]+)*))?", version_group=1, confidence=HIGH),
            Matcher(M_HEADER_PRESENT, r".", "X-Generator", None, MEDIUM),
            Matcher(M_HTML, r"/sites/(?:all|default)/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Joomla", "CMS", "Joomla",
        [
            Matcher(M_META_GENERATOR, r"Joomla!?(?:\s+([0-9]+(?:\.[0-9]+)*))?", version_group=1, confidence=HIGH),
            Matcher(M_HTML, r"/media/jui/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Laravel", "Web framework", "Laravel",
        [
            Matcher(M_COOKIE, r"^laravel_session$", confidence=HIGH),
            Matcher(M_COOKIE, r"^XSRF-TOKEN$", confidence=LOW),
        ],
    ),
    Fingerprint(
        "Django", "Web framework", "Django",
        [
            Matcher(M_COOKIE, r"^(?:csrftoken|django_language)$", confidence=MEDIUM),
            Matcher(M_COOKIE, r"^sessionid$", confidence=LOW),
        ],
    ),
    Fingerprint(
        "Flask", "Web framework", "Pallets",
        [
            Matcher(M_HEADER, r"Werkzeug(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, MEDIUM),
        ],
    ),
    Fingerprint(
        "Express", "Web framework", "OpenJS Foundation",
        [
            Matcher(M_HEADER, r"Express", "X-Powered-By", None, HIGH),
        ],
    ),
    # --- Frontend libraries (client-side only!) ---------------------------
    Fingerprint(
        "jQuery", "JavaScript library", "jQuery",
        [
            Matcher(M_SCRIPT, r"jquery[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js", version_group=1, confidence=HIGH),
            Matcher(M_SCRIPT, r"jquery(?:\.min)?\.js", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Bootstrap", "CSS framework", "Bootstrap",
        [
            Matcher(M_LINK, r"bootstrap[.-]?([0-9]+(?:\.[0-9]+)+)?(?:\.min)?\.css", version_group=1, confidence=HIGH),
            Matcher(M_SCRIPT, r"bootstrap(?:\.bundle)?(?:\.min)?\.js", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "React", "JavaScript library", "Meta",
        [
            Matcher(M_SCRIPT, r"react(?:\.production|\.development)?(?:\.min)?\.js", confidence=MEDIUM),
            Matcher(M_HTML, r"data-reactroot", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Angular", "JavaScript framework", "Google",
        [
            Matcher(M_HTML, r"ng-version=\"([0-9]+(?:\.[0-9]+)+)\"", version_group=1, confidence=HIGH),
            Matcher(M_HTML, r"\bng-app\b", confidence=LOW),
        ],
    ),
    Fingerprint(
        "Vue.js", "JavaScript framework", "Vue.js",
        [
            Matcher(M_SCRIPT, r"vue(?:\.min|\.runtime)?[.-]?([0-9]+(?:\.[0-9]+)+)?(?:\.min)?\.js", version_group=1, confidence=MEDIUM),
            Matcher(M_HTML, r"data-v-[0-9a-f]{8}", confidence=LOW),
        ],
    ),
    # --- Infrastructure hints ---------------------------------------------
    Fingerprint(
        "Cloudflare", "CDN / reverse proxy", "Cloudflare",
        [
            Matcher(M_HEADER_PRESENT, r".", "CF-Ray", None, HIGH),
            Matcher(M_HEADER, r"cloudflare", "Server", None, HIGH),
        ],
    ),
]
