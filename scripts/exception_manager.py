
from datetime import date, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from packaging.utils import canonicalize_name


# 1. 문자열 유효성 검사
def is_nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


# 2. 예외 승인 정책 검증
def validate_exception_policy(policy):

    settings = policy.get("exception_policy")

    if not isinstance(settings, dict):
        raise ValueError("Invalid exception policy")

    if settings.get("require_approval") is not True:
        raise ValueError("Exception approval must be required")

    if settings.get("require_expiration") is not True:
        raise ValueError("Exception expiration must be required")

    max_days = settings.get("max_duration_days")

    if type(max_days) is not int or not 1 <= max_days <= 30:
        raise ValueError("Invalid maximum exception duration")

    timezone_name = settings.get("timezone")

    if not is_nonempty_string(timezone_name):
        raise ValueError("Missing policy timezone")

    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        raise ValueError("Invalid policy timezone")

    return max_days


# 3. 예외 승인 목록 검증
def validate_exception_records(exception_data):

    records = exception_data.get("exceptions")

    if not isinstance(records, list):
        raise ValueError("Invalid exception list")

    seen_ids = set()

    required_fields = (
        "exception_id",
        "vulnerability_id",
        "package",
        "version",
        "status"
    )

    for record in records:

        if not isinstance(record, dict):
            raise ValueError("Invalid exception record")

        for field in required_fields:

            if not is_nonempty_string(record.get(field)):
                raise ValueError(
                    f"Missing exception field: {field}"
                )

        exception_id = record["exception_id"]

        if exception_id in seen_ids:
            raise ValueError(
                f"Duplicate exception ID: {exception_id}"
            )

        seen_ids.add(exception_id)

        if record["status"] not in {
            "APPROVED",
            "PENDING",
            "REJECTED",
            "REVOKED"
        }:
            raise ValueError(
                f"Invalid exception status: {exception_id}"
            )

    return records


# 4. 개별 승인 정보 검증
def validate_approval(record, max_days, today):

    if record["status"] != "APPROVED":
        return False, "NOT_APPROVED"

    required_fields = (
        "reason",
        "owner",
        "approved_by",
        "approved_date",
        "expires_at"
    )

    for field in required_fields:

        if not is_nonempty_string(record.get(field)):
            return False, f"MISSING_FIELD: {field}"

    if record["owner"].strip() == record["approved_by"].strip():
        return False, "SELF_APPROVAL"

    controls = record.get("compensating_controls")

    if not isinstance(controls, list) or not controls:
        return False, "MISSING_COMPENSATING_CONTROLS"

    if not all(is_nonempty_string(item) for item in controls):
        return False, "INVALID_COMPENSATING_CONTROLS"

    try:
        approved_date = date.fromisoformat(
            record["approved_date"]
        )

        expires_at = date.fromisoformat(
            record["expires_at"]
        )

    except ValueError:
        return False, "INVALID_DATE_FORMAT"

    if approved_date > today:
        return False, "FUTURE_APPROVAL"

    if expires_at <= approved_date:
        return False, "INVALID_DATE_RANGE"

    duration = (expires_at - approved_date).days

    if duration > max_days:
        return False, "DURATION_EXCEEDED"

    if today >= expires_at:
        return False, "EXPIRED"

    return True, "VALID_APPROVAL"


# 5. 취약점별 예외 승인 판단
def evaluate_exception(
    finding,
    severity,
    rules,
    exception_data,
    policy,
    today=None
):

    max_days = validate_exception_policy(policy)

    if today is None:
        timezone_name = policy["exception_policy"]["timezone"]
        today = datetime.now(ZoneInfo(timezone_name)).date()

    records = validate_exception_records(
        exception_data
    )

    # Critical과 Unknown은 예외 승인 금지
    if severity in {"CRITICAL", "UNKNOWN"}:
        return False, "SEVERITY_NOT_ELIGIBLE"

    if not rules[severity]["exception_allowed"]:
        return False, "EXCEPTION_NOT_ALLOWED"

    identifiers = finding["aliases"] | {
        finding["id"]
    }

    matched = []

    for record in records:

        if canonicalize_name(record["package"]) != finding["package"]:
            continue

        if record["version"] != finding["version"]:
            continue

        if record["vulnerability_id"] not in identifiers:
            continue

        matched.append(record)

    if not matched:
        return False, "NO_MATCHING_EXCEPTION"

    if len(matched) > 1:
        return False, "AMBIGUOUS_EXCEPTION"

    record = matched[0]

    valid, reason = validate_approval(
        record,
        max_days,
        today
    )

    if valid:
        return True, record["exception_id"]

    return False, reason
