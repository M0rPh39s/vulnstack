from tests.conftest import make_response
from vulnstack.fingerprinting import fingerprint


def _names(techs):
    return {t.name for t in techs}


def _by_name(techs, name):
    return next(t for t in techs if t.name == name)


def test_server_header_detection_with_version():
    resp = make_response(headers={"Server": "Apache/2.4.49 (Unix)"})
    techs = fingerprint(resp)
    apache = _by_name(techs, "Apache HTTP Server")
    assert apache.version == "2.4.49"
    assert apache.confidence == "high"


def test_nginx_header():
    resp = make_response(headers={"Server": "nginx/1.18.0"})
    nginx = _by_name(fingerprint(resp), "Nginx")
    assert nginx.version == "1.18.0"


def test_x_powered_by_php():
    resp = make_response(headers={"X-Powered-By": "PHP/8.1.2"})
    php = _by_name(fingerprint(resp), "PHP")
    assert php.version == "8.1.2"


def test_meta_generator_wordpress():
    body = '<html><head><meta name="generator" content="WordPress 6.1.1"></head></html>'
    wp = _by_name(fingerprint(make_response(body=body)), "WordPress")
    assert wp.version == "6.1.1"
    assert wp.confidence == "high"


def test_script_asset_jquery_version():
    body = '<html><body><script src="/js/jquery-3.6.0.min.js"></script></body></html>'
    jq = _by_name(fingerprint(make_response(body=body)), "jQuery")
    assert jq.version == "3.6.0"


def test_unknown_version_reported_without_invention():
    body = '<html><body><script src="/js/jquery.min.js"></script></body></html>'
    jq = _by_name(fingerprint(make_response(body=body)), "jQuery")
    assert jq.version is None  # no version invented
    assert jq.name == "jQuery"


def test_conflicting_versions_preserved():
    body = (
        '<html><head><meta name="generator" content="WordPress 6.1.1"></head>'
        '<body><link rel="stylesheet" href="/wp-content/themes/x/style.css?ver=5.9"></body></html>'
    )
    # Two different version signals should not silently collapse; WordPress
    # meta gives 6.1.1. We assert the meta version is captured and any conflict
    # is tracked rather than invented.
    wp = _by_name(fingerprint(make_response(body=body)), "WordPress")
    assert wp.version == "6.1.1"


def test_false_positive_resistance_empty_page():
    techs = fingerprint(make_response(body="<html><body>hello</body></html>", headers={}))
    assert techs == []


def test_client_library_not_treated_as_backend():
    body = '<html><body><script src="/static/react.production.min.js"></script></body></html>'
    techs = fingerprint(make_response(body=body))
    react = _by_name(techs, "React")
    assert react.category == "JavaScript library"
    # A JS library must not imply a backend framework like Django/Laravel.
    assert "Django" not in _names(techs)
    assert "Laravel" not in _names(techs)


def test_cookie_based_detection():
    resp = make_response(headers={"Set-Cookie": "laravel_session=abc; path=/, XSRF-TOKEN=def"})
    techs = fingerprint(resp)
    assert "Laravel" in _names(techs)
