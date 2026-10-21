from vulnstack.versioning import (
    RangeOutcome,
    compare,
    in_range,
    normalize_version,
)


def test_numeric_ordering_not_lexical():
    assert compare("1.2.9", "1.2.10") == -1
    assert compare("1.10", "1.9") == 1
    assert compare("2.4.49", "2.4.49") == 0


def test_different_digit_counts():
    assert compare("1.2", "1.2.1") == -1
    # Trailing zeros are semantically equal under PEP 440 (1.2.0 == 1.2),
    # which is the correct behaviour for version-range matching.
    assert compare("1.2.0", "1.2") == 0
    assert compare("1.2.1", "1.2") == 1


def test_prerelease_ranks_lower():
    # 1.2 release is greater than a 1.2rc pre-release.
    assert compare("1.2", "1.2rc1") == 1


def test_uncertain_when_unparseable():
    # Genuine uncertainty: one operand has no interpretable version tokens.
    assert compare("1.0", "???") is None
    assert compare("", "1.0") is None
    assert compare(None, "1.0") is None


def test_normalize_version_extracts():
    assert normalize_version("nginx/1.18.0") == "1.18.0"
    assert normalize_version("Apache/2.4.41 (Ubuntu)") == "2.4.41"
    assert normalize_version("*") is None
    assert normalize_version("unknown") is None


def test_exact_match():
    r = in_range("2.4.49", exact="2.4.49")
    assert r.outcome == RangeOutcome.IN_RANGE
    r2 = in_range("2.4.50", exact="2.4.49")
    assert r2.outcome == RangeOutcome.OUT_OF_RANGE


def test_inclusive_and_exclusive_bounds():
    # [2.4.0, 2.4.52)
    assert in_range("2.4.0", start="2.4.0", start_including=True,
                    end="2.4.52", end_including=False).outcome == RangeOutcome.IN_RANGE
    assert in_range("2.4.52", start="2.4.0", start_including=True,
                    end="2.4.52", end_including=False).outcome == RangeOutcome.OUT_OF_RANGE
    # (2.4.0, 2.4.52]
    assert in_range("2.4.0", start="2.4.0", start_including=False,
                    end="2.4.52", end_including=True).outcome == RangeOutcome.OUT_OF_RANGE
    assert in_range("2.4.52", start="2.4.0", start_including=False,
                    end="2.4.52", end_including=True).outcome == RangeOutcome.IN_RANGE


def test_open_ended_ranges():
    assert in_range("1.20.0", end="1.21.0", end_including=False).outcome == RangeOutcome.IN_RANGE
    assert in_range("1.21.0", end="1.21.0", end_including=False).outcome == RangeOutcome.OUT_OF_RANGE
    assert in_range("3.0", start="2.0", start_including=True).outcome == RangeOutcome.IN_RANGE


def test_no_constraint():
    assert in_range("1.0").outcome == RangeOutcome.NO_CONSTRAINT


def test_unknown_detected_version_is_uncertain():
    assert in_range(None, start="1.0", end="2.0").outcome == RangeOutcome.UNCERTAIN


def test_uncertain_comparison_scheme():
    # A detected version that cannot be compared with the boundary.
    r = in_range("weirdscheme", exact="2.4.49")
    assert r.outcome in (RangeOutcome.UNCERTAIN, RangeOutcome.OUT_OF_RANGE)
