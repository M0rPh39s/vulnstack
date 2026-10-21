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


_VER = r"v?([0-9]+(?:\.[0-9]+)+)"
_SUFFIX = r"(?:\.(?:min|slim|bundle|production|development))*"


def lib_matchers(name: str, method: str = M_SCRIPT) -> list[Matcher]:
    """Matchers for a versioned asset URL of a client-side library.

    Covers ``name-1.2.3.min.js``, CDN paths such as ``/name/1.2.3/`` and
    ``name@1.2.3/``, and the unversioned ``name.min.js`` (version unknown).
    ``name`` is a regex fragment; the lookbehind keeps ``moment`` from matching
    ``xmoment.js`` or ``date-moment.js``.
    """
    ext = r"\.js" if method == M_SCRIPT else r"\.css"
    pre = r"(?<![\w.-])"
    return [
        Matcher(method, rf"{pre}{name}[.-]{_VER}{_SUFFIX}{ext}", version_group=1, confidence=HIGH),
        Matcher(method, rf"{pre}{name}[/@]{_VER}[/.]", version_group=1, confidence=HIGH),
        Matcher(method, rf"{pre}{name}{_SUFFIX}{ext}", confidence=MEDIUM),
    ]


# ---------------------------------------------------------------------------
# Fingerprint catalogue
# ---------------------------------------------------------------------------

FINGERPRINTS: list[Fingerprint] = [
    # --- Web servers -------------------------------------------------------
    Fingerprint(
        "Apache HTTP Server", "Web server", "Apache",
        [
            # Not "Apache-Coyote" / "Apache Tomcat", which are Tomcat, not httpd.
            Matcher(M_HEADER, r"\bApache(?!-|\s+Tomcat)(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
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
            Matcher(M_HEADER, r"(?<!Open)LiteSpeed(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
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
            Matcher(M_HEADER, r"Drupal(?:\s+([0-9]+(?:\.[0-9]+)*))?", "X-Generator", 1, HIGH),
            Matcher(M_HEADER_PRESENT, r".", "X-Drupal-Cache", None, MEDIUM),
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
            Matcher(M_SCRIPT, rf"(?<![\w.-])jquery[/@]{_VER}[/.]", version_group=1, confidence=HIGH),
        ],
    ),
    Fingerprint(
        "Bootstrap", "CSS framework", "Bootstrap",
        [
            Matcher(M_LINK, r"bootstrap[.-]?([0-9]+(?:\.[0-9]+)+)?(?:\.min)?\.css", version_group=1, confidence=HIGH),
            Matcher(M_SCRIPT, r"bootstrap(?:\.bundle)?(?:\.min)?\.js", confidence=MEDIUM),
            *lib_matchers("bootstrap")[:2],
            *lib_matchers("bootstrap", M_LINK)[:2],
        ],
    ),
    Fingerprint(
        "React", "JavaScript library", "Meta",
        [
            Matcher(M_SCRIPT, r"react(?:\.production|\.development)?(?:\.min)?\.js", confidence=MEDIUM),
            Matcher(M_HTML, r"data-reactroot", confidence=MEDIUM),
            Matcher(M_SCRIPT, rf"(?<![\w.-])react[/@]{_VER}[/.]", version_group=1, confidence=HIGH),
        ],
    ),
    Fingerprint(
        "Angular", "JavaScript framework", "Google",
        [
            Matcher(M_HTML, r"ng-version=\"([0-9]+(?:\.[0-9]+)+)\"", version_group=1, confidence=HIGH),
        ],
    ),
    Fingerprint(
        "AngularJS", "JavaScript framework", "Google",
        [
            *lib_matchers(r"angular(?:js)?"),
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
    # --- Additional web servers / proxies / libraries ----------------------
    Fingerprint(
        "Apache Tomcat", "Web server", "Apache",
        [
            Matcher(M_HEADER, r"Apache[ -]Tomcat(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
            # Coyote is Tomcat's connector; its version is NOT the Tomcat version.
            Matcher(M_HEADER, r"Apache-Coyote", "Server", None, MEDIUM),
            Matcher(M_HTML, r"Apache Tomcat/([0-9]+(?:\.[0-9]+)+)", version_group=1, confidence=HIGH),
        ],
    ),
    Fingerprint(
        "Eclipse Jetty", "Web server", "Eclipse",
        [
            Matcher(M_HEADER, r"Jetty(?:[(/]([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Caddy", "Web server", "Caddy",
        [
            Matcher(M_HEADER, r"^Caddy\b", "Server", None, HIGH),
        ],
    ),
    Fingerprint(
        "Lighttpd", "Web server", "Lighttpd",
        [
            Matcher(M_HEADER, r"lighttpd(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "OpenResty", "Web server", "OpenResty",
        [
            Matcher(M_HEADER, r"openresty(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "OpenLiteSpeed", "Web server", "LiteSpeed Technologies",
        [
            Matcher(M_HEADER, r"OpenLiteSpeed(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Gunicorn", "Web server", "Gunicorn",
        [
            Matcher(M_HEADER, r"gunicorn(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Tornado", "Web framework", "Tornado",
        [
            Matcher(M_HEADER, r"TornadoServer(?:/([0-9]+(?:\.[0-9]+)+))?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Phusion Passenger", "Application server", "Phusion",
        [
            Matcher(M_HEADER, r"Phusion[ _]Passenger(?:\(R\))?[ /]?([0-9]+(?:\.[0-9]+)+)?", "X-Powered-By", 1, HIGH),
            Matcher(M_HEADER, r"Phusion[ _]Passenger(?:\(R\))?[ /]?([0-9]+(?:\.[0-9]+)+)?", "Server", 1, HIGH),
        ],
    ),
    Fingerprint(
        "Varnish", "CDN / reverse proxy", "Varnish Software",
        [
            Matcher(M_HEADER, r"\bvarnish\b", "Via", None, MEDIUM),
            Matcher(M_HEADER, r"Varnish/([0-9]+(?:\.[0-9]+)+)", "Via", 1, HIGH),
            Matcher(M_HEADER_PRESENT, r".", "X-Varnish", None, MEDIUM),
        ],
    ),
    Fingerprint(
        "OpenSSL", "Library", "OpenSSL",
        [
            Matcher(M_HEADER, r"OpenSSL/([0-9]+(?:\.[0-9]+)+[a-z]?)", "Server", 1, HIGH),
        ],
    ),
    # --- Additional CMS / platforms ---------------------------------------
    Fingerprint(
        "Magento", "CMS", "Adobe",
        [
            Matcher(M_COOKIE, r"^(?:mage-cache-sessid|mage-messages|private_content_version)$", confidence=HIGH),
            Matcher(M_HEADER_PRESENT, r".", "X-Magento-Tags", None, HIGH),
            Matcher(M_HTML, r"/static/version[0-9]+/frontend/|/skin/frontend/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "PrestaShop", "CMS", "PrestaShop",
        [
            Matcher(M_META_GENERATOR, r"PrestaShop", confidence=HIGH),
            Matcher(M_COOKIE, r"^PrestaShop-[0-9a-f]+$", confidence=HIGH),
            Matcher(M_HTML, r"var prestashop\s*=", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "TYPO3", "CMS", "TYPO3",
        [
            Matcher(M_META_GENERATOR, r"TYPO3(?:\s+CMS)?(?:\s+([0-9]+(?:\.[0-9]+)*))?", version_group=1, confidence=HIGH),
            Matcher(M_COOKIE, r"^fe_typo_user$", confidence=HIGH),
            Matcher(M_HTML, r"/typo3(?:conf|temp)/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Ghost", "CMS", "Ghost",
        [
            Matcher(M_META_GENERATOR, r"^Ghost(?:\s+([0-9]+(?:\.[0-9]+)*))?$", version_group=1, confidence=HIGH),
        ],
    ),
    Fingerprint(
        "MediaWiki", "CMS", "Wikimedia",
        [
            Matcher(M_META_GENERATOR, r"MediaWiki(?:\s+([0-9]+(?:\.[0-9]+)+))?", version_group=1, confidence=HIGH),
        ],
    ),
    Fingerprint(
        "Moodle", "CMS", "Moodle",
        [
            Matcher(M_COOKIE, r"^MoodleSession", confidence=HIGH),
            Matcher(M_HTML, r"/theme/yui_combo\.php", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "phpBB", "CMS", "phpBB",
        [
            Matcher(M_COOKIE, r"^phpbb3_[a-z0-9]+_(?:u|k|sid)$", confidence=HIGH),
            Matcher(M_HTML, r"Powered by <a[^>]*>phpBB", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "OpenCart", "CMS", "OpenCart",
        [
            Matcher(M_COOKIE, r"^OCSESSID$", confidence=HIGH),
            Matcher(M_HTML, r"catalog/view/theme/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Craft CMS", "CMS", "Pixel & Tonic",
        [
            Matcher(M_HEADER, r"Craft CMS", "X-Powered-By", None, HIGH),
            Matcher(M_COOKIE, r"^CraftSessionId$", confidence=HIGH),
        ],
    ),
    Fingerprint(
        "DokuWiki", "CMS", "DokuWiki",
        [
            Matcher(M_META_GENERATOR, r"DokuWiki", confidence=HIGH),
        ],
    ),
    Fingerprint(
        "Discourse", "CMS", "Discourse",
        [
            Matcher(M_META_GENERATOR, r"Discourse(?:\s+([0-9]+(?:\.[0-9]+)+))?", version_group=1, confidence=HIGH),
        ],
    ),
    # --- Additional frameworks --------------------------------------------
    Fingerprint(
        "Ruby on Rails", "Web framework", "Rails",
        [
            Matcher(M_HTML, r"<meta[^>]+name=[\"']csrf-param[\"'][^>]*authenticity_token", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Symfony", "Web framework", "Symfony",
        [
            Matcher(M_HEADER_PRESENT, r".", "X-Debug-Token", None, HIGH),
            Matcher(M_COOKIE, r"^sf_redirect$", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "CodeIgniter", "Web framework", "CodeIgniter",
        [
            Matcher(M_COOKIE, r"^ci_session$", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Next.js", "Web framework", "Vercel",
        [
            Matcher(M_HEADER, r"Next\.js", "X-Powered-By", None, HIGH),
            Matcher(M_HTML, r"/_next/static/", confidence=MEDIUM),
        ],
    ),
    Fingerprint(
        "Strapi", "CMS", "Strapi",
        [
            Matcher(M_HEADER, r"Strapi", "X-Powered-By", None, HIGH),
        ],
    ),
    Fingerprint(
        "ASP.NET MVC", "Web framework", "Microsoft",
        [
            Matcher(M_HEADER, r"([0-9]+(?:\.[0-9]+)+)", "X-AspNetMvc-Version", 1, HIGH),
        ],
    ),
    # --- Additional frontend libraries (client-side only!) -----------------
    Fingerprint("Lodash", "JavaScript library", "Lodash", lib_matchers("lodash")),
    Fingerprint("Moment.js", "JavaScript library", "Moment.js", lib_matchers(r"moment(?:\.js)?")),
    Fingerprint("Underscore.js", "JavaScript library", "Underscore.js", lib_matchers(r"underscore")),
    Fingerprint("jQuery UI", "JavaScript library", "jQuery", lib_matchers(r"jquery[-.]?ui")),
    Fingerprint("Handlebars", "JavaScript library", "Handlebars", lib_matchers(r"handlebars(?:\.js)?")),
    Fingerprint("Axios", "JavaScript library", "Axios", lib_matchers("axios")),
    Fingerprint("TinyMCE", "JavaScript library", "Tiny", lib_matchers("tinymce")),
    Fingerprint("CKEditor", "JavaScript library", "CKSource", lib_matchers("ckeditor")),
    Fingerprint("DataTables", "JavaScript library", "DataTables", lib_matchers(r"(?:jquery\.)?dataTables")),
    Fingerprint("Highcharts", "JavaScript library", "Highsoft", lib_matchers("highcharts")),
    Fingerprint("Prototype", "JavaScript library", "Prototype", lib_matchers(r"prototype")),
    Fingerprint("Modernizr", "JavaScript library", "Modernizr", lib_matchers("modernizr")),
    Fingerprint("Backbone.js", "JavaScript library", "Backbone.js", lib_matchers(r"backbone(?:\.js)?")),
    Fingerprint("Knockout", "JavaScript library", "Knockout", lib_matchers(r"knockout")),
    # --- Infrastructure hints ---------------------------------------------
    Fingerprint(
        "Cloudflare", "CDN / reverse proxy", "Cloudflare",
        [
            Matcher(M_HEADER_PRESENT, r".", "CF-Ray", None, HIGH),
            Matcher(M_HEADER, r"cloudflare", "Server", None, HIGH),
        ],
    ),
]
