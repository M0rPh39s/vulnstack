import json
from datetime import datetime, timezone

import pytest

from vulnstack.cve import cve_json, providers
from vulnstack.cve.cve_json import CveListProvider, parse_record
from vulnstack.cve.providers import ProviderError


def _record(cve_id="CVE-2021-41773", *, updated="2023-11-07T03:38:00.000Z", affected=None, **cna_extra):
    cna = {
        "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server."}],
        "affected": affected if affected is not None else [{
            "vendor": "Apache Software Foundation",
            "product": "Apache HTTP Server",
            "cpes": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
            "versions": [{"version": "2.4.49", "status": "affected"}],
        }],
    }
    cna.update(cna_extra)
    return {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED",
                        "datePublished": "2021-10-05T09:15:00.000Z", "dateUpdated": updated},
        "containers": {"cna": cna},
    }


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def _ids(provider, **kw):
    kw.setdefault("modified_since", None)
    kw.setdefault("full", False)
    return [v.cve_id for v in provider.fetch(**kw)]


# ---- parse_record ----------------------------------------------------------

def test_parse_basic_record():
    v = parse_record(_record())
    assert v.cve_id == "CVE-2021-41773"
    assert v.source == "cvelist"
    assert v.status == "PUBLISHED"
    assert v.description.startswith("Path traversal")
    assert v.published == "2021-10-05T09:15:00.000Z"
    assert v.affected[0].version == "2.4.49"


def test_cpe_taken_from_record_not_guessed_from_names():
    """Display names must not leak into the CPE vendor/product used for matching."""
    ap = parse_record(_record()).affected[0]
    assert (ap.cpe_vendor, ap.cpe_product) == ("apache", "http_server")
    assert ap.vendor == "Apache Software Foundation"
    assert ap.cpe23.startswith("cpe:2.3:a:apache:http_server")


def test_cpe_falls_back_to_normalized_names_without_cpes():
    rec = _record(affected=[{"vendor": "Acme Corp", "product": "Road Runner",
                             "versions": [{"version": "1.0", "status": "affected"}]}])
    ap = parse_record(rec).affected[0]
    assert (ap.cpe_vendor, ap.cpe_product) == ("acme_corp", "road_runner")
    assert ap.cpe23 is None


@pytest.mark.parametrize("bad", [None, [], "x", 5, {}, {"cveMetadata": {}}])
def test_parse_rejects_non_records(bad):
    assert parse_record(bad) is None


def test_version_ranges():
    rec = _record(affected=[{
        "vendor": "v", "product": "p",
        "versions": [
            {"version": "2.4.0", "lessThan": "2.4.52", "status": "affected", "versionType": "semver"},
            {"version": "0", "lessThanOrEqual": "1.9", "status": "affected"},
            {"version": "3.0", "status": "unaffected"},   # ignored
        ],
    }])
    ap = parse_record(rec).affected[0]
    first, second = ap.ranges
    assert (first.version_start, first.version_start_type) == ("2.4.0", "including")
    assert (first.version_end, first.version_end_type) == ("2.4.52", "excluding")
    assert first.version_scheme == "semver"
    # "0" means "from the beginning": no lower bound; lessThanOrEqual is inclusive.
    assert second.version_start is None and second.version_start_type is None
    assert (second.version_end, second.version_end_type) == ("1.9", "including")
    assert ap.version is None  # unaffected entries never become the concrete version


def test_wildcard_versions_are_not_concrete():
    rec = _record(affected=[{"vendor": "v", "product": "p",
                             "versions": [{"version": "*", "status": "affected"},
                                          {"version": "-", "status": "affected"}]}])
    assert parse_record(rec).affected[0].version is None


def test_metrics_prefer_v31_and_weaknesses_and_references():
    rec = _record(
        metrics=[{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "high",
                               "vectorString": "CVSS:3.1/AV:N"}}],
        problemTypes=[{"descriptions": [{"cweId": "cwe-22"}, {"description": "no id"}]}],
        references=[{"url": "https://example.com/a", "tags": ["vendor", "patch"]}, {"name": "no url"}],
    )
    v = parse_record(rec)
    assert (v.cvss_score, v.cvss_version, v.severity) == (7.5, "3.1", "HIGH")
    assert v.cvss_vector == "CVSS:3.1/AV:N"
    assert v.weaknesses == ["CWE-22"]
    assert [(r.url, r.ref_type) for r in v.references] == [("https://example.com/a", "vendor,patch")]


def test_metrics_fall_back_to_v2():
    rec = _record(metrics=[{"cvssV2_0": {"baseScore": 5.0, "vectorString": "AV:N"}}])
    v = parse_record(rec)
    assert (v.cvss_score, v.cvss_version, v.severity) == (5.0, "2.0", None)


def test_non_english_only_description_is_empty():
    rec = _record(descriptions=[{"lang": "de", "value": "nur deutsch"}])
    assert parse_record(rec).description == ""


# ---- provider --------------------------------------------------------------

def test_provider_requires_path():
    with pytest.raises(ProviderError):
        CveListProvider()


def test_provider_registered():
    assert "cvelist" in providers.available()
    assert isinstance(providers.get_provider("cvelist", path="/nonexistent"), CveListProvider)


def test_missing_path_raises_provider_error(tmp_path):
    provider = CveListProvider(path=str(tmp_path / "nope"))
    with pytest.raises(ProviderError, match="does not exist"):
        _ids(provider)


def test_single_file_and_directory_tree(tmp_path):
    single = _write(tmp_path, "CVE-1.json", _record("CVE-2021-0001"))
    assert _ids(CveListProvider(path=str(single))) == ["CVE-2021-0001"]

    tree = tmp_path / "cves" / "2021" / "0xxx"
    tree.mkdir(parents=True)
    _write(tree, "CVE-2021-0002.json", _record("CVE-2021-0002"))
    _write(tree, "CVE-2021-0003.json", _record("CVE-2021-0003"))
    _write(tree, "notes.json", _record("CVE-2021-9999"))  # not CVE-*.json: ignored
    assert _ids(CveListProvider(path=str(tmp_path / "cves"))) == ["CVE-2021-0002", "CVE-2021-0003"]


def test_bad_files_are_skipped_not_fatal(tmp_path):
    _write(tmp_path, "CVE-2021-0001.json", "{ not json")
    _write(tmp_path, "CVE-2021-0002.json", "[1, 2, 3]")       # valid JSON, not a record
    _write(tmp_path, "CVE-2021-0003.json", {"cveMetadata": {}})  # no cveId
    _write(tmp_path, "CVE-2021-0004.json", _record("CVE-2021-0004"))
    assert _ids(CveListProvider(path=str(tmp_path))) == ["CVE-2021-0004"]


def test_latest_source_modified_tracks_newest(tmp_path):
    _write(tmp_path, "CVE-2021-0001.json", _record("CVE-2021-0001", updated="2022-01-01T00:00:00.000Z"))
    _write(tmp_path, "CVE-2021-0002.json", _record("CVE-2021-0002", updated="2023-05-05T00:00:00.000Z"))
    provider = CveListProvider(path=str(tmp_path))
    assert provider.latest_source_modified() is None
    _ids(provider)
    assert provider.latest_source_modified() == "2023-05-05T00:00:00.000Z"


def test_modified_since_does_not_hide_local_records(tmp_path):
    """A local mirror is imported in full, including on a bootstrap run."""
    _write(tmp_path, "CVE-2021-0001.json", _record("CVE-2021-0001", updated="2022-01-01T00:00:00.000Z"))
    since = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert _ids(CveListProvider(path=str(tmp_path)), modified_since=since) == ["CVE-2021-0001"]


def test_progress_callback_every_hundred(tmp_path):
    for i in range(101):
        _write(tmp_path, f"CVE-2021-{i:04d}.json", _record(f"CVE-2021-{i:04d}"))
    calls = []
    list(CveListProvider(path=str(tmp_path)).fetch(
        modified_since=None, full=False, progress=lambda n, total: calls.append((n, total))))
    assert calls == [(100, None)]


def test_end_to_end_ingest_then_correlate(tmp_db, tmp_path):
    """cvelist record -> updater -> DB -> search: the CPE fix makes it findable."""
    from vulnstack.cve.search import Classification, SearchQuery, VulnerabilitySearch
    from vulnstack.cve.updater import Updater

    _write(tmp_path, "CVE-2021-41773.json", _record())
    result = Updater(tmp_db, CveListProvider(path=str(tmp_path))).run(full=False)
    assert result.status == "success" and result.inserted == 1
    report = VulnerabilitySearch(tmp_db).search([SearchQuery("Apache HTTP Server", "2.4.49")])
    assert [f.classification for f in report.findings] == [Classification.MATCHED_AFFECTED_RANGE]
