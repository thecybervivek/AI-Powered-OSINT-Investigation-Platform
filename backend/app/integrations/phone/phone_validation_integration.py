import phonenumbers
from phonenumbers import NumberParseException
from phonenumbers import PhoneNumberFormat
from phonenumbers import PhoneNumberType
from phonenumbers import carrier as pn_carrier
from phonenumbers import geocoder as pn_geocoder
from phonenumbers import timezone as pn_timezone

from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus

# phonenumbers.PhoneNumberType is an IntEnum with no built-in label -
# this is the only place that mapping lives, so both the service's risk
# scoring and the schema/tests read the same human-readable strings.
_NUMBER_TYPE_LABELS: dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


# Fallback default regions tried, in order, when the input has no
# leading "+" and therefore carries no explicit country context.
# libphonenumber CANNOT parse a bare national-format number (e.g.
# "9917891298") without being told which region's dialing plan to
# apply - passing region=None only works for numbers that are already
# in E.164 form. Previously this integration always passed None, so
# every valid Indian number typed without "+91" raised
# NumberParseException and was reported NOT_FOUND / is_valid=False -
# which the risk engine then read as a validation failure (see
# phone_service.py regression fix). India is tried first because it is
# this deployment's primary user base; additional regions can be
# appended here without touching any other part of this integration.
_DEFAULT_REGION_FALLBACKS: tuple[str, ...] = ("IN",)


class PhoneValidationIntegration(AsyncBaseIntegration):
    """
    Validates and enriches a phone number entirely from libphonenumber's
    bundled offline datasets: structural validity, E.164/international/
    national formatting, ISO region, coarse geographic description,
    carrier name (where the offline carrier database has one - many
    ported/VOIP numbers won't), number type (mobile/VOIP/premium-rate/
    etc.), and associated timezones.

    Always configured - no API key or network call is involved, so this
    source can never be SKIPPED and never times out.
    """

    source_name = "phone_validation"

    def is_configured(self) -> bool:
        return True

    def _parse(self, target: str) -> tuple["phonenumbers.PhoneNumber", str | None]:
        """
        Tries to parse `target` as a phone number, returning the parsed
        number together with the region context that was actually used
        to resolve it (None when the input already carried its own "+"
        country code and no fallback was needed).

        A leading "+" lets libphonenumber infer the region itself. An
        input without one is only parseable if a default region is
        supplied - so when the direct parse fails AND the input has no
        "+", this retries against each entry in
        _DEFAULT_REGION_FALLBACKS before giving up. This never changes
        behavior for numbers already in E.164 form, and never mutates
        the caller's original input - only the returned parsed object
        differs.
        """

        try:
            return phonenumbers.parse(target, None), None

        except NumberParseException:

            if target.strip().startswith("+"):
                raise

            for region in _DEFAULT_REGION_FALLBACKS:

                try:
                    return phonenumbers.parse(target, region), region

                except NumberParseException:
                    continue

            raise

    async def _query(self, target: str) -> IntegrationResult:

        try:
            parsed, assumed_region = self._parse(target)

        except NumberParseException as error:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "raw_input": target,
                    "is_valid": False,
                    "is_possible": False,
                    "parse_error": getattr(error.error_type, "name", None)
                    or str(error),
                },
                error_message=(
                    "Could not parse this as a phone number. Numbers "
                    "without a country must be given in international "
                    "format, e.g. +14155552671."
                ),
            )

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        region_code = phonenumbers.region_code_for_number(parsed)
        number_type = phonenumbers.number_type(parsed)

        region_description = pn_geocoder.description_for_number(parsed, "en") or None
        carrier_name = pn_carrier.name_for_number(parsed, "en") or None
        timezones = list(pn_timezone.time_zones_for_number(parsed))

        data = {
            "raw_input": target,
            "is_valid": is_valid,
            "is_possible": is_possible,
            "e164_format": phonenumbers.format_number(parsed, PhoneNumberFormat.E164),
            "international_format": phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
            "national_format": phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL),
            "country_calling_code": parsed.country_code,
            "country_code": region_code,
            "region_description": region_description,
            "number_type": _NUMBER_TYPE_LABELS.get(number_type, "unknown"),
            "carrier_name": carrier_name,
            "timezones": timezones,
            # Set only when the input had no "+" and a default region
            # (e.g. "IN") had to be assumed to parse it at all. Purely
            # informational - see phone_service.py: assuming a country
            # context is never itself a risk signal.
            "assumed_country": assumed_region,
        }

        status = (
            ModuleResultStatus.SUCCESS if is_valid else ModuleResultStatus.NOT_FOUND
        )

        return IntegrationResult(
            source=self.source_name,
            status=status,
            data=data,
        )
