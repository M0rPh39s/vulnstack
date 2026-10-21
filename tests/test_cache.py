import time

from vulnstack.cache import Cache


def test_roundtrip(tmp_path):
    c = Cache(tmp_path, ttl_seconds=60)
    assert c.get("k") is None
    c.set("k", {"a": [1, 2]})
    assert c.get("k") == {"a": [1, 2]}


def test_keys_are_hashed_not_used_as_paths(tmp_path):
    c = Cache(tmp_path)
    c.set("../../etc/passwd", {"x": 1})
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1 and len(files[0].stem) == 64
    assert not (tmp_path.parent / "etc").exists()


def test_expired_entries_ignored(tmp_path, monkeypatch):
    c = Cache(tmp_path, ttl_seconds=10)
    c.set("k", {"a": 1})
    real = time.time()
    monkeypatch.setattr(time, "time", lambda: real + 11)
    assert c.get("k") is None


def test_zero_ttl_disables_cache(tmp_path):
    c = Cache(tmp_path, ttl_seconds=0)
    c.set("k", {"a": 1})
    assert c.get("k") is None
    assert not list(tmp_path.glob("*.json"))


def test_corrupt_entry_is_a_miss(tmp_path):
    c = Cache(tmp_path)
    c.set("k", {"a": 1})
    next(tmp_path.glob("*.json")).write_text("{ broken")
    assert c.get("k") is None


def test_write_failure_is_non_fatal(tmp_path, monkeypatch):
    from pathlib import Path
    c = Cache(tmp_path)

    def deny(self, *a, **k):
        raise OSError("read-only")

    monkeypatch.setattr(Path, "write_text", deny)
    c.set("k", {"a": 1})  # must not raise


def test_clear_counts_and_handles_missing_dir(tmp_path):
    assert Cache(tmp_path / "missing").clear() == 0
    c = Cache(tmp_path)
    c.set("a", {})
    c.set("b", {})
    (tmp_path / "keep.txt").write_text("not a cache entry")
    assert c.clear() == 2
    assert (tmp_path / "keep.txt").exists()
