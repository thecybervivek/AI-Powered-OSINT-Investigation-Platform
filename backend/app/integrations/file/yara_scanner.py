import time
from pathlib import Path

from backend.app.core.config import settings
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus

SOURCE_NAME = "yara_scan"


class YaraScanner:
    """
    Compiles every .yar/.yara file under YARA_RULES_DIR once per process
    (class-level cache), then matches uploaded files against the combined
    rule set. Dropping additional rule files into that directory extends
    coverage without any code change - "custom rule support" per the
    Milestone 6 spec.

    Not modeled as a BaseIntegration/AsyncBaseIntegration subclass: this
    isn't a network source (is_configured() below covers "not installed
    / no rules" the same way the base class covers "no API key" for
    external sources), and matching is CPU-bound local work rather than
    an awaited HTTP call.
    """

    _compiled_rules = None
    _compile_error: str | None = None
    _compile_attempted = False

    @classmethod
    def _ensure_compiled(cls) -> None:

        if cls._compile_attempted:
            return

        cls._compile_attempted = True

        try:
            import yara
        except ImportError:
            cls._compile_error = (
                "yara-python is not installed; run "
                "'pip install yara-python' to enable YARA scanning."
            )
            return

        rules_dir = Path(settings.YARA_RULES_DIR)

        if not rules_dir.is_dir():
            cls._compile_error = f"YARA rules directory not found: {rules_dir}"
            return

        rule_filepaths: dict[str, str] = {}

        for pattern in ("*.yar", "*.yara"):
            for path in rules_dir.glob(pattern):
                rule_filepaths[path.stem] = str(path)

        if not rule_filepaths:
            cls._compile_error = f"No YARA rule files found in {rules_dir}."
            return

        try:
            cls._compiled_rules = yara.compile(filepaths=rule_filepaths)

        except yara.Error as error:
            cls._compile_error = f"Failed to compile YARA rules: {error}"

    def is_configured(self) -> bool:

        self._ensure_compiled()

        return self._compiled_rules is not None

    def scan(
        self,
        file_path: str,
    ) -> IntegrationResult:

        self._ensure_compiled()

        if self._compiled_rules is None:

            return IntegrationResult(
                source=SOURCE_NAME,
                status=ModuleResultStatus.SKIPPED,
                error_message=self._compile_error or "YARA scanning unavailable.",
            )

        start = time.perf_counter()

        try:
            matches = self._compiled_rules.match(
                file_path,
                timeout=int(settings.YARA_SCAN_TIMEOUT_SECONDS),
            )

        except Exception as error:

            return IntegrationResult(
                source=SOURCE_NAME,
                status=ModuleResultStatus.FAILED,
                error_message=f"YARA scan failed: {error}",
                latency_ms=round((time.perf_counter() - start) * 1000),
            )

        match_data = [
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "matched_strings": self._string_identifiers(match),
            }
            for match in matches
        ]

        return IntegrationResult(
            source=SOURCE_NAME,
            status=ModuleResultStatus.SUCCESS,
            data={
                "matched": bool(match_data),
                "match_count": len(match_data),
                "matches": match_data,
            },
            latency_ms=round((time.perf_counter() - start) * 1000),
        )

    @staticmethod
    def _string_identifiers(match) -> list[str]:
        """
        yara-python's match.strings shape changed across versions -
        4.3+ returns StringMatch objects with `.identifier`, older
        releases return raw (offset, identifier, data) tuples. Handles
        both so this doesn't silently break on a version bump.
        """

        identifiers: list[str] = []

        for item in match.strings:

            identifier = getattr(item, "identifier", None)

            if identifier is None and isinstance(item, tuple) and len(item) >= 2:
                identifier = item[1]

            if identifier and identifier not in identifiers:
                identifiers.append(identifier)

        return identifiers[:20]
