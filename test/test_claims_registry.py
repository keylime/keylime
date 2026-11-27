"""Unit tests for the claims pipeline registries (translator + renderer)."""

import unittest
from typing import Any, Dict, cast

from keylime.claims.base import (
    ClaimsTranslator,
    EvaluatedEvidence,
    KeylimeClaimsError,
    OutputFormat,
    Renderer,
    VerificationOutput,
)
from keylime.claims.registry import (
    register_evidence_type,
    register_output_format,
    renderer_registry,
    translator_registry,
)


class _DummyTranslator(ClaimsTranslator):
    evidence_type = "dummy-translator"

    def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
        return {}


class _DummyRenderer(Renderer):
    format = OutputFormat.JSONAPI

    def render(self, output: VerificationOutput, signer: Any) -> Any:
        return None


class _DummyTranslator2(ClaimsTranslator):
    evidence_type = "dummy-translator"

    def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
        return {}


class _DummyRenderer2(Renderer):
    format = OutputFormat.JSONAPI

    def render(self, output: VerificationOutput, signer: Any) -> Any:
        return None


class _RegistryTestBase(unittest.TestCase):
    """Isolates the registries so dummy registrations never collide with
    the real strategies imported alongside the claims package."""

    def setUp(self) -> None:
        self._saved_translators = dict(translator_registry._entries)  # pylint: disable=protected-access
        self._saved_renderers = dict(renderer_registry._entries)  # pylint: disable=protected-access
        translator_registry._entries.clear()  # pylint: disable=protected-access
        renderer_registry._entries.clear()  # pylint: disable=protected-access

    def tearDown(self) -> None:
        translator_registry._entries.clear()  # pylint: disable=protected-access
        translator_registry._entries.update(self._saved_translators)  # pylint: disable=protected-access
        renderer_registry._entries.clear()  # pylint: disable=protected-access
        renderer_registry._entries.update(self._saved_renderers)  # pylint: disable=protected-access


class TranslatorRegistryTest(_RegistryTestBase):
    def test_register_and_get_round_trip(self) -> None:
        register_evidence_type(_DummyTranslator)
        self.assertIs(translator_registry.get("dummy-translator"), _DummyTranslator)

    def test_duplicate_registration_raises(self) -> None:
        register_evidence_type(_DummyTranslator)
        with self.assertRaises(ValueError):
            register_evidence_type(_DummyTranslator2)

    def test_unknown_key_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            translator_registry.get("no-such-evidence-type")

    def test_unknown_key_error_names_the_axis_and_known_keys(self) -> None:
        register_evidence_type(_DummyTranslator)
        with self.assertRaises(KeylimeClaimsError) as ctx:
            translator_registry.get("no-such-evidence-type")
        message = str(ctx.exception)
        self.assertIn("translator", message)
        self.assertIn("dummy-translator", message)


class RendererRegistryTest(_RegistryTestBase):
    def test_register_and_get_round_trip(self) -> None:
        register_output_format(_DummyRenderer)
        self.assertIs(renderer_registry.get(OutputFormat.JSONAPI), _DummyRenderer)

    def test_duplicate_registration_raises(self) -> None:
        register_output_format(_DummyRenderer)
        with self.assertRaises(ValueError):
            register_output_format(_DummyRenderer2)

    def test_unknown_key_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            renderer_registry.get(cast(OutputFormat, "no-such-format"))

    def test_unknown_key_error_names_the_axis_and_known_keys(self) -> None:
        register_output_format(_DummyRenderer)
        with self.assertRaises(KeylimeClaimsError) as ctx:
            renderer_registry.get(cast(OutputFormat, "no-such-format"))
        message = str(ctx.exception)
        self.assertIn("renderer", message)
        self.assertIn(repr(OutputFormat.JSONAPI), message)


class DecoratorValidationTest(unittest.TestCase):
    """The decorators must fail loudly (naming the class) on a missing,
    empty, or wrong-typed registry key — not register under a key no
    lookup can ever find."""

    def test_missing_evidence_type_rejected(self) -> None:
        class _NoKeyTranslator(ClaimsTranslator):
            def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
                return {}

        with self.assertRaises(ValueError) as ctx:
            register_evidence_type(_NoKeyTranslator)
        self.assertIn("_NoKeyTranslator", str(ctx.exception))

    def test_empty_evidence_type_rejected(self) -> None:
        class _EmptyKeyTranslator(ClaimsTranslator):
            evidence_type = ""

            def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
                return {}

        with self.assertRaises(ValueError) as ctx:
            register_evidence_type(_EmptyKeyTranslator)
        self.assertIn("_EmptyKeyTranslator", str(ctx.exception))

    def test_non_enum_format_rejected(self) -> None:
        class _StrFormatRenderer(Renderer):
            format = "application/x-nope"  # type: ignore[assignment]  # deliberately wrong

            def render(self, output: VerificationOutput, signer: Any) -> Any:
                return None

        with self.assertRaises(ValueError) as ctx:
            register_output_format(_StrFormatRenderer)
        self.assertIn("_StrFormatRenderer", str(ctx.exception))
        self.assertIn("OutputFormat", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
