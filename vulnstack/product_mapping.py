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
    "angularjs": "Angular",
    "vue": "Vue.js",
    "vue.js": "Vue.js",
    "vuejs": "Vue.js",
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
