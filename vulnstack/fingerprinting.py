"""Deterministic technology fingerprinting engine.

Applies the data-driven rules in :mod:`vulnstack.fingerprints` to the evidence
collected from a single HTTP response. The engine:

* never invents version numbers — a version is reported only when a matcher's
  capture group extracts one from real response data;
* preserves conflicting version evidence instead of silently picking one;
* records, for every detection, the methods used, the confidence, and the
  concrete evidence strings so results are auditable;
* keeps client-side library detections (jQuery, React, …) clearly categorised
  so they are never mistaken for backend frameworks.

Header evidence is reported honestly: a ``Server`` header is treated as "the
response reported X", which may be produced by a reverse proxy, CDN or cache
rather than the origin software.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from vulnstack.fingerprints import (
    FINGERPRINTS,
    M_COOKIE,
    M_HEADER,
    M_HEADER_PRESENT,
    M_HTML,
    M_LINK,
    M_META_GENERATOR,
    M_SCRIPT,
    Fingerprint,
    Matcher,
)
from vulnstack.http_client import HttpResponse
from vulnstack.logging_config import get_logger

log = get_logger("fingerprinting")

_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class DetectedTechnology:
    name: str
    category: str
    vendor: str = ""
    version: str | None = None
    confidence: str = "low"
    detection_methods: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    version_evidence: list[str] = field(default_factory=list)
    conflicting_versions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "vendor": self.vendor,
            "version": self.version,
            "confidence": self.confidence,
            "detection_methods": sorted(set(self.detection_methods)),
            "evidence": self.evidence,
            "version_evidence": self.version_evidence,
            "conflicting_versions": self.conflicting_versions,
            "notes": self.notes,
        }


@dataclass
class PageEvidence:
    headers: dict[str, str]
    cookie_names: list[str]
    meta_generators: list[str]
    script_srcs: list[str]
    link_hrefs: list[str]
    html: str

    @classmethod
    def from_response(cls, resp: HttpResponse) -> "PageEvidence":
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookie_names: list[str] = []
        raw_cookie = resp.headers.get("Set-Cookie") or headers.get("set-cookie")
        if raw_cookie:
            cookie_names = re.findall(r"(?:^|,\s*)([A-Za-z0-9_.\-]+)=", raw_cookie)

        meta_generators: list[str] = []
        script_srcs: list[str] = []
        link_hrefs: list[str] = []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for meta in soup.find_all("meta"):
                if (meta.get("name") or "").lower() == "generator":
                    content = meta.get("content")
                    if content:
                        meta_generators.append(content.strip())
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    script_srcs.append(src.strip())
            for link in soup.find_all("link"):
                href = link.get("href")
                if href:
                    link_hrefs.append(href.strip())
        except Exception as exc:  # pragma: no cover - defensive against malformed HTML
            log.debug("HTML parse issue (non-fatal): %s", exc)
        return cls(
            headers=headers,
            cookie_names=cookie_names,
            meta_generators=meta_generators,
            script_srcs=script_srcs,
            link_hrefs=link_hrefs,
            html=resp.text,
        )


def _apply_matcher(matcher: Matcher, ev: PageEvidence) -> list[tuple[str, str | None]]:
    """Return a list of (evidence_text, version_or_None) for each hit."""
    hits: list[tuple[str, str | None]] = []
    flags = re.IGNORECASE

    if matcher.method == M_HEADER_PRESENT:
        value = ev.headers.get(matcher.target.lower())
        if value is not None:
            hits.append((f"header {matcher.target}: {value}", None))
        return hits

    if matcher.method == M_HEADER:
        value = ev.headers.get(matcher.target.lower())
        if value:
            m = re.search(matcher.pattern, value, flags)
            if m:
                version = m.group(matcher.version_group) if matcher.version_group else None
                hits.append((f"header {matcher.target}: {value}", version))
        return hits

    if matcher.method == M_COOKIE:
        for name in ev.cookie_names:
            if re.search(matcher.pattern, name, flags):
                hits.append((f"cookie {name}", None))
        return hits

    if matcher.method == M_META_GENERATOR:
        for content in ev.meta_generators:
            m = re.search(matcher.pattern, content, flags)
            if m:
                version = m.group(matcher.version_group) if matcher.version_group else None
                hits.append((f"meta generator: {content}", version))
        return hits

    if matcher.method == M_SCRIPT:
        for src in ev.script_srcs:
            m = re.search(matcher.pattern, src, flags)
            if m:
                version = (
                    m.group(matcher.version_group)
                    if matcher.version_group and m.group(matcher.version_group)
                    else None
                )
                hits.append((f"script src: {src}", version))
        return hits

    if matcher.method == M_LINK:
        for href in ev.link_hrefs:
            m = re.search(matcher.pattern, href, flags)
            if m:
                version = (
                    m.group(matcher.version_group)
                    if matcher.version_group and m.group(matcher.version_group)
                    else None
                )
                hits.append((f"link href: {href}", version))
        return hits

    if matcher.method == M_HTML:
        m = re.search(matcher.pattern, ev.html, flags)
        if m:
            version = (
                m.group(matcher.version_group)
                if matcher.version_group and m.lastindex and m.group(matcher.version_group)
                else None
            )
            snippet = m.group(0)[:80]
            hits.append((f"html match: {snippet}", version))
        return hits

    return hits


def _detect_one(fp: Fingerprint, ev: PageEvidence) -> DetectedTechnology | None:
    detection_methods: list[str] = []
    evidence: list[str] = []
    versions: list[str] = []
    best_conf = 0

    for matcher in fp.matchers:
        for evidence_text, version in _apply_matcher(matcher, ev):
            detection_methods.append(matcher.method)
            evidence.append(evidence_text)
            best_conf = max(best_conf, _CONFIDENCE_RANK[matcher.confidence])
            if version:
                versions.append(version)

    if not evidence:
        return None

    unique_versions = sorted(set(versions))
    version = unique_versions[0] if unique_versions else None
    conflicts = unique_versions[1:] if len(unique_versions) > 1 else []
    notes: list[str] = []
    if conflicts:
        notes.append(
            "Multiple distinct versions observed; reporting the lowest and "
            "preserving the conflict."
        )

    confidence = next(
        (name for name, rank in _CONFIDENCE_RANK.items() if rank == best_conf), "low"
    )

    return DetectedTechnology(
        name=fp.name,
        category=fp.category,
        vendor=fp.vendor,
        version=version,
        confidence=confidence,
        detection_methods=detection_methods,
        evidence=evidence,
        version_evidence=unique_versions,
        conflicting_versions=conflicts,
        notes=notes,
    )


def fingerprint(resp: HttpResponse) -> list[DetectedTechnology]:
    """Run all fingerprints against a response and return detections."""
    ev = PageEvidence.from_response(resp)
    results: list[DetectedTechnology] = []
    for fp in FINGERPRINTS:
        detected = _detect_one(fp, ev)
        if detected is not None:
            results.append(detected)
    # Stable, readable ordering: by confidence (desc) then name.
    results.sort(key=lambda d: (-_CONFIDENCE_RANK[d.confidence], d.name.lower()))
    return results
