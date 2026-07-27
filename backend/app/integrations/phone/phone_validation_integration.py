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

    async def _query(self, target: str) -> IntegrationResult:

        try:
            # A leading "+" lets libphonenumber infer the region itself;
            # without one, parsing without a default region raises for
            # any number that isn't already in E.164 form - that failure
            # is itself useful signal ("not a parseable phone number"),
            # not an integration error.
            parsed = phonenumbers.parse(target, None)

        except NumberParseException as error:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "raw_input": target,
                    "is_valid": False,
                    "is_possible": False,
                    "parse_error": error.error_type.name if error.error_type else str(error),
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
        }

        status = (
            ModuleResultStatus.SUCCESS if is_valid else ModuleResultStatus.NOT_FOUND
        )

        return IntegrationResult(
            source=self.source_name,
            status=status,
            data=data,
        )
