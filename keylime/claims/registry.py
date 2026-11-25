"""Registries for the variation axes of the claims pipeline.

- translator_registry: per EVIDENCE TYPE (keylime/claims/translators/)
- renderer_registry:   per OUTPUT FORMAT  (keylime/claims/renderers/)

A new entry is one module with the matching decorator plus one registration
import in the package __init__ (a new output format also needs an
OutputFormat member). Registration is import-time only; duplicates raise
ValueError (programming error), unknown keys raise KeylimeClaimsError
(runtime error).
"""

from __future__ import annotations

from typing import Any, Dict, Generic, List, TypeVar

from keylime.claims.base import ClaimsTranslator, KeylimeClaimsError, OutputFormat, Renderer

K = TypeVar("K")
V = TypeVar("V")


class _Registry(Generic[K, V]):
    """Generic registry core (private): a map with loud failure modes."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._entries: Dict[K, V] = {}

    def register(self, key: K, value: V) -> None:
        if key in self._entries:
            raise ValueError(f"Duplicate registration for key {key!r} in the {self._name} registry")
        self._entries[key] = value

    def get(self, key: K) -> V:
        try:
            return self._entries[key]
        except KeyError:
            known = ", ".join(repr(k) for k in self._entries)
            suffix = f" (known: {known})" if known else ""
            raise KeylimeClaimsError(
                f"No registration for key {key!r} in the {self._name} registry{suffix}"
            ) from None

    def keys(self) -> List[K]:
        return list(self._entries)

    def __contains__(self, key: Any) -> bool:
        return key in self._entries


translator_registry: _Registry[str, type[ClaimsTranslator]] = _Registry(name="translator")
"""key: evidence_type str -> ClaimsTranslator subclass."""

renderer_registry: _Registry[OutputFormat, type[Renderer]] = _Registry(name="renderer")
"""key: OutputFormat member -> Renderer subclass."""


def register_evidence_type(cls: type[ClaimsTranslator]) -> type[ClaimsTranslator]:
    """Class decorator: register a ClaimsTranslator subclass."""
    evidence_type = getattr(cls, "evidence_type", None)
    if not isinstance(evidence_type, str) or not evidence_type:
        raise ValueError(f"{cls.__name__} must set a non-empty string evidence_type class attribute")
    translator_registry.register(evidence_type, cls)
    return cls


def register_output_format(cls: type[Renderer]) -> type[Renderer]:
    """Class decorator: register a Renderer subclass."""
    fmt = getattr(cls, "format", None)
    if not isinstance(fmt, OutputFormat):
        raise ValueError(f"{cls.__name__} must set its format class attribute to an OutputFormat member")
    renderer_registry.register(fmt, cls)
    return cls
