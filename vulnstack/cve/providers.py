"""Provider abstraction for trusted vulnerability data sources.

A :class:`Provider` knows how to fetch normalized :class:`Vulnerability`
records from a trusted source. The updater drives providers; new sources can
be added by implementing this interface and registering them, without changing
the database or search layers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from datetime import datetime

from vulnstack.cve.models import Vulnerability

ProgressCallback = Callable[[int, int | None], None]


class ProviderError(Exception):
    """Recoverable provider/network error; the DB must be left intact."""


class Provider(ABC):
    name: str

    @abstractmethod
    def fetch(
        self,
        *,
        modified_since: datetime | None,
        full: bool,
        progress: ProgressCallback | None = None,
    ) -> Iterator[Vulnerability]:
        """Yield normalized vulnerability records.

        ``modified_since`` requests an incremental window; ``full`` requests a
        complete synchronization. Implementations must raise
        :class:`ProviderError` on failure rather than returning partial/false
        success.
        """
        raise NotImplementedError

    def latest_source_modified(self) -> str | None:
        """Return the newest source-modified timestamp seen in the last fetch."""
        return None


_REGISTRY: dict[str, Callable[..., Provider]] = {}


def register(name: str, factory: Callable[..., Provider]) -> None:
    _REGISTRY[name] = factory


def available() -> list[str]:
    return sorted(_REGISTRY)


def get_provider(name: str, **kwargs) -> Provider:
    try:
        factory = _REGISTRY[name]
    except KeyError:
        raise ProviderError(
            f"unknown data source {name!r}; available: {', '.join(available()) or 'none'}"
        ) from None
    return factory(**kwargs)
