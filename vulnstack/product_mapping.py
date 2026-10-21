"""Deterministic product normalization and CPE resolution.

Technology display names ("Apache HTTP Server") must be mapped to the vendor /
product identifiers and CPE fields used by vulnerability feeds
("apache" / "http_server"). This module keeps that mapping *explicit*: an alias
registry drives resolution, so two products are never merged merely because
their names look similar.

A resolution may be ambiguous (several candidate products). We preserve the
ambiguity and let the search engine classify the result rather than guessing a
single product to force a match.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProductIdentity:
    canonical: str          # canonical display name
    cpe_vendor: str         # CPE 2.3 vendor field
    cpe_product: str        # CPE 2.3 product field
    version_scheme: str = "generic"


@dataclass
class ResolvedProduct:
    source_name: str                       # the detected technology name
    candidates: list[ProductIdentity] = field(default_factory=list)
    ambiguous: bool = False

    @property
    def resolved(self) -> bool:
        return bool(self.candidates)


# Canonical identities keyed by canonical display name.
_IDENTITIES: dict[str, ProductIdentity] = {
    "Apache HTTP Server": ProductIdentity("Apache HTTP Server", "apache", "http_server"),
    "Nginx": ProductIdentity("Nginx", "nginx", "nginx"),
    "Microsoft IIS": ProductIdentity("Microsoft IIS", "microsoft", "internet_information_services"),
    "LiteSpeed": ProductIdentity("LiteSpeed", "litespeedtech", "litespeed_web_server"),
    "PHP": ProductIdentity("PHP", "php", "php", version_scheme="pep440_like"),
    "ASP.NET": ProductIdentity("ASP.NET", "microsoft", "asp.net"),
    "Node.js": ProductIdentity("Node.js", "nodejs", "node.js"),
    "WordPress": ProductIdentity("WordPress", "wordpress", "wordpress"),
    "Drupal": ProductIdentity("Drupal", "drupal", "drupal"),
    "Joomla": ProductIdentity("Joomla", "joomla", "joomla!"),
    "Laravel": ProductIdentity("Laravel", "laravel", "laravel"),
    "Django": ProductIdentity("Django", "djangoproject", "django"),
    "Flask": ProductIdentity("Flask", "palletsprojects", "flask"),
    "Express": ProductIdentity("Express", "openjsf", "express"),
    "jQuery": ProductIdentity("jQuery", "jquery", "jquery"),
    "Bootstrap": ProductIdentity("Bootstrap", "getbootstrap", "bootstrap"),
    "React": ProductIdentity("React", "facebook", "react"),
    "Angular": ProductIdentity("Angular", "angular", "angular"),
    "Vue.js": ProductIdentity("Vue.js", "vuejs", "vue.js"),
    "Apache Tomcat": ProductIdentity("Apache Tomcat", "apache", "tomcat"),
    "Eclipse Jetty": ProductIdentity("Eclipse Jetty", "eclipse", "jetty"),
    "Caddy": ProductIdentity("Caddy", "caddyserver", "caddy"),
    "Lighttpd": ProductIdentity("Lighttpd", "lighttpd", "lighttpd"),
    "OpenResty": ProductIdentity("OpenResty", "openresty", "openresty"),
    "OpenLiteSpeed": ProductIdentity("OpenLiteSpeed", "litespeedtech", "openlitespeed"),
    "Gunicorn": ProductIdentity("Gunicorn", "gunicorn", "gunicorn"),
    "Tornado": ProductIdentity("Tornado", "tornadoweb", "tornado"),
    "Phusion Passenger": ProductIdentity("Phusion Passenger", "phusion", "passenger"),
    "Varnish": ProductIdentity("Varnish", "varnish-cache", "varnish"),
    "OpenSSL": ProductIdentity("OpenSSL", "openssl", "openssl"),
    "Magento": ProductIdentity("Magento", "magento", "magento"),
    "PrestaShop": ProductIdentity("PrestaShop", "prestashop", "prestashop"),
    "TYPO3": ProductIdentity("TYPO3", "typo3", "typo3"),
    "Ghost": ProductIdentity("Ghost", "ghost", "ghost"),
    "MediaWiki": ProductIdentity("MediaWiki", "mediawiki", "mediawiki"),
    "Moodle": ProductIdentity("Moodle", "moodle", "moodle"),
    "phpBB": ProductIdentity("phpBB", "phpbb", "phpbb"),
    "OpenCart": ProductIdentity("OpenCart", "opencart", "opencart"),
    "Craft CMS": ProductIdentity("Craft CMS", "craftcms", "craft_cms"),
    "DokuWiki": ProductIdentity("DokuWiki", "dokuwiki", "dokuwiki"),
    "Discourse": ProductIdentity("Discourse", "discourse", "discourse"),
    "Ruby on Rails": ProductIdentity("Ruby on Rails", "rubyonrails", "rails"),
    "Symfony": ProductIdentity("Symfony", "symfony", "symfony"),
    "CodeIgniter": ProductIdentity("CodeIgniter", "codeigniter", "codeigniter"),
    "Next.js": ProductIdentity("Next.js", "vercel", "next.js"),
    "Strapi": ProductIdentity("Strapi", "strapi", "strapi"),
    "ASP.NET MVC": ProductIdentity("ASP.NET MVC", "microsoft", "asp.net_mvc"),
    "AngularJS": ProductIdentity("AngularJS", "angularjs", "angular.js"),
    "Lodash": ProductIdentity("Lodash", "lodash", "lodash"),
    "Moment.js": ProductIdentity("Moment.js", "momentjs", "moment"),
    "Underscore.js": ProductIdentity("Underscore.js", "underscorejs", "underscore"),
    "jQuery UI": ProductIdentity("jQuery UI", "jqueryui", "jquery_ui"),
    "Handlebars": ProductIdentity("Handlebars", "handlebarsjs", "handlebars"),
    "Axios": ProductIdentity("Axios", "axios", "axios"),
    "TinyMCE": ProductIdentity("TinyMCE", "tiny", "tinymce"),
    "CKEditor": ProductIdentity("CKEditor", "ckeditor", "ckeditor"),
    "DataTables": ProductIdentity("DataTables", "datatables", "datatables"),
    "Highcharts": ProductIdentity("Highcharts", "highcharts", "highcharts"),
    "Prototype": ProductIdentity("Prototype", "prototypejs", "prototype"),
    "Modernizr": ProductIdentity("Modernizr", "modernizr", "modernizr"),
    "Backbone.js": ProductIdentity("Backbone.js", "backbonejs", "backbone"),
    "Knockout": ProductIdentity("Knockout", "knockoutjs", "knockout"),
}

# Alias registry: lowercased alias -> canonical name. Explicit, not fuzzy.
_ALIASES: dict[str, str] = {
    "apache": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "apache httpd": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "nginx": "Nginx",
    "microsoft iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "microsoft-iis": "Microsoft IIS",
    "internet information services": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "php": "PHP",
    "asp.net": "ASP.NET",
    "aspnet": "ASP.NET",
    "node.js": "Node.js",
    "nodejs": "Node.js",
    "node": "Node.js",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "joomla!": "Joomla",
    "laravel": "Laravel",
    "django": "Django",
    "flask": "Flask",
    "express": "Express",
    "expressjs": "Express",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "react": "React",
    "react.js": "React",
    "reactjs": "React",
    "angular": "Angular",
    "angularjs": "AngularJS",
    "angular.js": "AngularJS",
    "vue": "Vue.js",
    "vue.js": "Vue.js",
    "vuejs": "Vue.js",
    "tomcat": "Apache Tomcat",
    "apache tomcat": "Apache Tomcat",
    "jetty": "Eclipse Jetty",
    "eclipse jetty": "Eclipse Jetty",
    "caddy": "Caddy",
    "lighttpd": "Lighttpd",
    "lighty": "Lighttpd",
    "openresty": "OpenResty",
    "openlitespeed": "OpenLiteSpeed",
    "gunicorn": "Gunicorn",
    "tornado": "Tornado",
    "tornadoserver": "Tornado",
    "passenger": "Phusion Passenger",
    "phusion passenger": "Phusion Passenger",
    "varnish": "Varnish",
    "varnish cache": "Varnish",
    "openssl": "OpenSSL",
    "magento": "Magento",
    "adobe commerce": "Magento",
    "prestashop": "PrestaShop",
    "typo3": "TYPO3",
    "typo3 cms": "TYPO3",
    "ghost": "Ghost",
    "mediawiki": "MediaWiki",
    "moodle": "Moodle",
    "phpbb": "phpBB",
    "opencart": "OpenCart",
    "craft cms": "Craft CMS",
    "craftcms": "Craft CMS",
    "dokuwiki": "DokuWiki",
    "discourse": "Discourse",
    "ruby on rails": "Ruby on Rails",
    "rails": "Ruby on Rails",
    "symfony": "Symfony",
    "codeigniter": "CodeIgniter",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "strapi": "Strapi",
    "asp.net mvc": "ASP.NET MVC",
    "lodash": "Lodash",
    "moment": "Moment.js",
    "moment.js": "Moment.js",
    "momentjs": "Moment.js",
    "underscore": "Underscore.js",
    "underscore.js": "Underscore.js",
    "jquery ui": "jQuery UI",
    "jqueryui": "jQuery UI",
    "handlebars": "Handlebars",
    "handlebars.js": "Handlebars",
    "axios": "Axios",
    "tinymce": "TinyMCE",
    "ckeditor": "CKEditor",
    "datatables": "DataTables",
    "highcharts": "Highcharts",
    "prototype": "Prototype",
    "prototypejs": "Prototype",
    "modernizr": "Modernizr",
    "backbone": "Backbone.js",
    "backbone.js": "Backbone.js",
    "knockout": "Knockout",
    "knockoutjs": "Knockout",
}


def all_identities() -> list[ProductIdentity]:
    return list(_IDENTITIES.values())


def alias_pairs() -> list[tuple[str, str]]:
    """Return (alias, canonical) pairs for seeding the database."""
    return sorted(_ALIASES.items())


def normalize_name(name: str) -> str:
    return name.strip().lower()


def resolve(name: str) -> ResolvedProduct:
    """Resolve a detected technology name to candidate product identities."""
    key = normalize_name(name)
    canonical = _ALIASES.get(key)
    if canonical is None:
        # Try the identity table directly (exact canonical match).
        for ident in _IDENTITIES.values():
            if ident.canonical.lower() == key:
                return ResolvedProduct(source_name=name, candidates=[ident])
        return ResolvedProduct(source_name=name, candidates=[], ambiguous=False)
    ident = _IDENTITIES[canonical]
    return ResolvedProduct(source_name=name, candidates=[ident], ambiguous=False)


def identity_for_canonical(canonical: str) -> ProductIdentity | None:
    return _IDENTITIES.get(canonical)
