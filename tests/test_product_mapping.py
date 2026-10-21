from vulnstack import product_mapping


def test_alias_resolution():
    r = product_mapping.resolve("Apache")
    assert r.resolved
    assert r.candidates[0].cpe_vendor == "apache"
    assert r.candidates[0].cpe_product == "http_server"


def test_httpd_alias():
    assert product_mapping.resolve("httpd").candidates[0].canonical == "Apache HTTP Server"


def test_canonical_name_resolves():
    r = product_mapping.resolve("Apache HTTP Server")
    assert r.resolved and r.candidates[0].cpe_product == "http_server"


def test_case_insensitive():
    assert product_mapping.resolve("WORDPRESS").candidates[0].canonical == "WordPress"


def test_unknown_product_not_forced():
    r = product_mapping.resolve("Totally Unknown Thing")
    assert not r.resolved
    assert r.candidates == []


def test_similar_names_not_merged():
    # "node" maps to Node.js, but an unrelated made-up name does not.
    assert product_mapping.resolve("node").candidates[0].canonical == "Node.js"
    assert not product_mapping.resolve("nodezilla").resolved


def test_alias_pairs_seedable():
    pairs = product_mapping.alias_pairs()
    assert ("apache", "Apache HTTP Server") in pairs
    assert all(isinstance(a, str) and isinstance(c, str) for a, c in pairs)
