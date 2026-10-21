"""One test case per catalogue signature, plus false-positive regressions."""

import pytest

from tests.conftest import make_response
from vulnstack import product_mapping
from vulnstack.fingerprinting import fingerprint
from vulnstack.fingerprints import FINGERPRINTS


def _script(src):
    return f'<html><body><script src="{src}"></script></body></html>'


def _meta(content):
    return f'<html><head><meta name="generator" content="{content}"></head></html>'


def _detect(name, **kw):
    techs = fingerprint(make_response(**kw))
    return next((t for t in techs if t.name == name), None)


# (technology, response kwargs, expected version)
CASES = [
    # servers / proxies / libraries
    ("Apache Tomcat", dict(headers={"Server": "Apache Tomcat/9.0.50"}), "9.0.50"),
    ("Apache Tomcat", dict(headers={"Server": "Apache-Coyote/1.1"}), None),
    ("Apache Tomcat", dict(body="<h3>Apache Tomcat/8.5.78</h3>"), "8.5.78"),
    ("Eclipse Jetty", dict(headers={"Server": "Jetty(9.4.43.v20210629)"}), "9.4.43"),
    ("Eclipse Jetty", dict(headers={"Server": "Jetty/10.0.2"}), "10.0.2"),
    ("Caddy", dict(headers={"Server": "Caddy"}), None),
    ("Lighttpd", dict(headers={"Server": "lighttpd/1.4.55"}), "1.4.55"),
    ("OpenResty", dict(headers={"Server": "openresty/1.19.3.1"}), "1.19.3.1"),
    ("OpenLiteSpeed", dict(headers={"Server": "OpenLiteSpeed"}), None),
    ("Gunicorn", dict(headers={"Server": "gunicorn/20.1.0"}), "20.1.0"),
    ("Tornado", dict(headers={"Server": "TornadoServer/6.1"}), "6.1"),
    ("Phusion Passenger", dict(headers={"X-Powered-By": "Phusion Passenger(R) 6.0.4"}), "6.0.4"),
    ("Varnish", dict(headers={"Via": "1.1 varnish (Varnish/6.0)"}), "6.0"),
    ("Varnish", dict(headers={"X-Varnish": "32770 32769"}), None),
    ("OpenSSL", dict(headers={"Server": "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips"}), "1.0.2k"),
    # CMS / platforms
    ("Magento", dict(headers={"Set-Cookie": "mage-cache-sessid=true; path=/"}), None),
    ("Magento", dict(headers={"X-Magento-Tags": "cms_b"}), None),
    ("Magento", dict(body='<link href="/static/version1650000/frontend/x.css">'), None),
    ("PrestaShop", dict(body=_meta("PrestaShop")), None),
    ("PrestaShop", dict(headers={"Set-Cookie": "PrestaShop-a1b2c3=xyz; path=/"}), None),
    ("TYPO3", dict(body=_meta("TYPO3 CMS")), None),
    ("TYPO3", dict(body=_meta("TYPO3 CMS 11.5")), "11.5"),
    ("TYPO3", dict(headers={"Set-Cookie": "fe_typo_user=abc; path=/"}), None),
    ("Ghost", dict(body=_meta("Ghost 5.2")), "5.2"),
    ("MediaWiki", dict(body=_meta("MediaWiki 1.39.1")), "1.39.1"),
    ("Moodle", dict(headers={"Set-Cookie": "MoodleSession=abc; path=/"}), None),
    ("phpBB", dict(headers={"Set-Cookie": "phpbb3_x1y2_sid=abc; path=/"}), None),
    ("phpBB", dict(body='Powered by <a href="https://www.phpbb.com/">phpBB</a>'), None),
    ("OpenCart", dict(headers={"Set-Cookie": "OCSESSID=abc; path=/"}), None),
    ("Craft CMS", dict(headers={"X-Powered-By": "Craft CMS"}), None),
    ("DokuWiki", dict(body=_meta("DokuWiki")), None),
    ("Discourse", dict(body=_meta("Discourse 3.0.0")), "3.0.0"),
    # frameworks
    ("Ruby on Rails", dict(body='<meta name="csrf-param" content="authenticity_token" />'), None),
    ("Symfony", dict(headers={"X-Debug-Token": "abc123"}), None),
    ("CodeIgniter", dict(headers={"Set-Cookie": "ci_session=abc; path=/"}), None),
    ("Next.js", dict(headers={"X-Powered-By": "Next.js"}), None),
    ("Next.js", dict(body=_script("/_next/static/chunks/main.js") + '/_next/static/'), None),
    ("Strapi", dict(headers={"X-Powered-By": "Strapi <strapi.io>"}), None),
    ("ASP.NET MVC", dict(headers={"X-AspNetMvc-Version": "5.2"}), "5.2"),
    # client-side libraries
    ("AngularJS", dict(body=_script("/js/angular-1.8.2.min.js")), "1.8.2"),
    ("AngularJS", dict(body='<html ng-app="x"></html>'), None),
    ("Lodash", dict(body=_script("/js/lodash-4.17.21.min.js")), "4.17.21"),
    ("Lodash", dict(body=_script("https://cdn.jsdelivr.net/npm/lodash@4.17.20/lodash.min.js")), "4.17.20"),
    ("Moment.js", dict(body=_script("https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js")), "2.29.4"),
    ("Underscore.js", dict(body=_script("/static/underscore-1.13.1.min.js")), "1.13.1"),
    ("jQuery UI", dict(body=_script("/js/jquery-ui-1.12.1.min.js")), "1.12.1"),
    ("Handlebars", dict(body=_script("/js/handlebars-4.7.7.min.js")), "4.7.7"),
    ("Axios", dict(body=_script("https://unpkg.com/axios@0.21.1/dist/axios.min.js")), "0.21.1"),
    ("TinyMCE", dict(body=_script("/tinymce/5.10.0/tinymce.min.js")), "5.10.0"),
    ("CKEditor", dict(body=_script("/ckeditor/4.16.0/ckeditor.js")), "4.16.0"),
    ("DataTables", dict(body=_script("/js/jquery.dataTables.min.js")), None),
    ("Highcharts", dict(body=_script("https://code.highcharts.com/highcharts-9.1.0.js")), "9.1.0"),
    ("Prototype", dict(body=_script("/js/prototype-1.7.3.js")), "1.7.3"),
    ("Modernizr", dict(body=_script("/js/modernizr-2.8.3.min.js")), "2.8.3"),
    ("Backbone.js", dict(body=_script("/js/backbone-1.4.0.min.js")), "1.4.0"),
    ("Knockout", dict(body=_script("/js/knockout-3.5.1.js")), "3.5.1"),
    # improved versions for existing libraries
    ("jQuery", dict(body=_script("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js")), "3.6.0"),
    ("jQuery", dict(body=_script("https://unpkg.com/jquery@3.5.1/dist/jquery.js")), "3.5.1"),
    ("Bootstrap", dict(body=_script("https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js")), "5.3.0"),
    ("Bootstrap", dict(body=_script("/js/bootstrap-4.6.0.min.js")), "4.6.0"),
    ("React", dict(body=_script("https://unpkg.com/react@17.0.2/umd/react.production.min.js")), "17.0.2"),
    ("Drupal", dict(headers={"X-Generator": "Drupal 9 (https://www.drupal.org)"}), "9"),
]


@pytest.mark.parametrize("name,kwargs,version", CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_signature_detects(name, kwargs, version):
    tech = _detect(name, **kwargs)
    assert tech is not None, f"{name} not detected"
    assert tech.version == version


def test_every_fingerprint_has_a_case():
    covered = {c[0] for c in CASES}
    # Pre-existing fingerprints are covered by the older test modules.
    legacy = {
        "Apache HTTP Server", "Nginx", "Microsoft IIS", "LiteSpeed", "PHP", "ASP.NET",
        "Node.js", "WordPress", "Joomla", "Laravel", "Django", "Flask", "Express",
        "Angular", "Vue.js", "Cloudflare",
    }
    missing = {fp.name for fp in FINGERPRINTS} - covered - legacy
    assert not missing, f"fingerprints without a test case: {sorted(missing)}"


def test_fingerprint_names_unique():
    names = [fp.name for fp in FINGERPRINTS]
    assert len(names) == len(set(names))


def test_every_fingerprint_maps_to_a_cpe_identity():
    # Cloudflare is an infrastructure hint with no vulnerability product.
    for fp in FINGERPRINTS:
        if fp.name == "Cloudflare":
            continue
        resolved = product_mapping.resolve(fp.name)
        assert resolved.resolved, f"{fp.name} has no CPE mapping"
        ident = resolved.candidates[0]
        assert ident.cpe_vendor and ident.cpe_product


@pytest.mark.parametrize("alias,canonical", [
    ("tomcat", "Apache Tomcat"), ("jetty", "Eclipse Jetty"), ("rails", "Ruby on Rails"),
    ("nextjs", "Next.js"), ("angularjs", "AngularJS"), ("moment", "Moment.js"),
    ("typo3 cms", "TYPO3"), ("adobe commerce", "Magento"),
])
def test_new_aliases(alias, canonical):
    assert product_mapping.resolve(alias).candidates[0].canonical == canonical


def test_angularjs_and_angular_have_distinct_cpes():
    ajs = product_mapping.resolve("AngularJS").candidates[0]
    ng = product_mapping.resolve("Angular").candidates[0]
    assert (ajs.cpe_vendor, ajs.cpe_product) == ("angularjs", "angular.js")
    assert (ng.cpe_vendor, ng.cpe_product) == ("angular", "angular")


# ---- regressions for earlier false positives --------------------------------

def test_tomcat_not_reported_as_apache_httpd():
    for server in ("Apache-Coyote/1.1", "Apache Tomcat/9.0.50"):
        assert _detect("Apache HTTP Server", headers={"Server": server}) is None


def test_real_apache_still_detected_next_to_modules():
    t = _detect("Apache HTTP Server", headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1"})
    assert t.version == "2.4.49"
    assert _detect("Apache HTTP Server", headers={"Server": "Apache"}).version is None


def test_openlitespeed_not_reported_as_litespeed():
    assert _detect("LiteSpeed", headers={"Server": "OpenLiteSpeed"}) is None
    assert _detect("LiteSpeed", headers={"Server": "LiteSpeed"}) is not None


def test_arbitrary_x_generator_is_not_drupal():
    assert _detect("Drupal", headers={"X-Generator": "Something Else"}) is None


def test_ng_app_is_angularjs_not_angular():
    body = '<html ng-app="x"></html>'
    assert _detect("Angular", body=body) is None
    assert _detect("AngularJS", body=body) is not None


def test_ng_version_is_angular():
    assert _detect("Angular", body='<app-root ng-version="15.2.1"></app-root>').version == "15.2.1"


@pytest.mark.parametrize("src", ["/js/xmoment.js", "/js/date-moment.min.js", "/js/momentum.js"])
def test_lookbehind_prevents_substring_false_positives(src):
    assert _detect("Moment.js", body=_script(src)) is None


def test_jquery_ui_not_confused_with_jquery():
    techs = fingerprint(make_response(body=_script("/js/jquery-ui-1.12.1.min.js")))
    jq = next((t for t in techs if t.name == "jQuery"), None)
    assert jq is None
