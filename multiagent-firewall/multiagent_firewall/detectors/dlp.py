from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from ..config.detection import REGEX_PATTERNS, KEYWORDS

try:
    import phonenumbers

    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False


def detect_keywords(
    text: str,
    keywords: Mapping[str, Sequence[str]] | None = None,
) -> List[Dict[str, Any]]:
    kw = keywords if keywords is not None else KEYWORDS

    findings: List[Dict[str, Any]] = []
    text_lower = text.lower()

    for field_name, keyword_list in kw.items():
        for keyword in keyword_list:
            if keyword.lower() in text_lower:
                findings.append(
                    {
                        "field": field_name,
                        "value": keyword,
                        "sources": ["dlp_keyword"],
                    }
                )

    return findings


def luhn_checksum(card_number: str) -> bool:
    """Validate credit card numbers using the Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False

    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def validate_ssn(ssn: str) -> bool:
    """Basic validation for US Social Security Numbers."""
    ssn_clean = ssn.replace("-", "").replace(" ", "")

    if not ssn_clean.isdigit():
        return False
    if len(ssn_clean) != 9:
        return False

    area = ssn_clean[:3]
    group = ssn_clean[3:5]
    serial = ssn_clean[5:]

    if area == "000" or area == "666" or int(area) >= 900:
        return False

    if group == "00":
        return False

    if serial == "0000":
        return False

    return True


def validate_vin(vin: str) -> bool:
    """Validate Vehicle Identification Number using check digit."""
    vin = vin.upper().replace(" ", "")

    if len(vin) != 17:
        return False

    if any(char in vin for char in "IOQ"):
        return False

    transliteration = {
        "A": 1,
        "B": 2,
        "C": 3,
        "D": 4,
        "E": 5,
        "F": 6,
        "G": 7,
        "H": 8,
        "J": 1,
        "K": 2,
        "L": 3,
        "M": 4,
        "N": 5,
        "P": 7,
        "R": 9,
        "S": 2,
        "T": 3,
        "U": 4,
        "V": 5,
        "W": 6,
        "X": 7,
        "Y": 8,
        "Z": 9,
    }

    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    total = 0
    for i, char in enumerate(vin):
        if char.isdigit():
            value = int(char)
        else:
            value = transliteration.get(char, 0)
        total += value * weights[i]

    check_digit = total % 11
    check_char = "X" if check_digit == 10 else str(check_digit)

    return vin[8] == check_char


_CHECKSUM_VALIDATORS = {
    "CREDIT_DEBIT_CARD": luhn_checksum,
    "SSN": validate_ssn,
    "VEHICLE_IDENTIFIER": validate_vin,
}


def apply_checksum_validation(
    findings: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Validate checksum-capable regex findings and enrich accepted matches.

    Findings for checksum-backed fields are kept only when they pass validation.
    Accepted findings receive the `dlp_checksum` source in addition to
    existing detector sources.
    """
    validated: List[Dict[str, Any]] = []

    for raw_item in findings:
        if not isinstance(raw_item, Mapping):
            continue

        item = dict(raw_item)
        field = str(item.get("field") or "").strip().upper()
        value = str(item.get("value") or "")

        validator = _CHECKSUM_VALIDATORS.get(field)
        if validator is not None and not validator(value):
            continue

        sources = _collect_sources(item)
        if validator is not None and "dlp_checksum" not in sources:
            sources.append("dlp_checksum")
        item["sources"] = sources
        validated.append(item)

    return validated


def detect_regex_patterns(
    text: str,
    regex_patterns: Mapping[str, object] | None = None,
) -> List[Dict[str, Any]]:
    patterns = regex_patterns if regex_patterns is not None else REGEX_PATTERNS

    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    text_lower = text.lower()
    word_spans: List[Tuple[int, int]] | None = None

    for field_name, entry in patterns.items():
        rule = _normalize_regex_rule(field_name, entry)
        pattern = rule["regex"]

        if pattern == "__library:phonenumbers__":
            if PHONENUMBERS_AVAILABLE:
                region = rule.get("region", "US")
                findings.extend(_detect_with_phonenumbers(text, region, rule["field"]))
            else:
                print("PHONENUMBERS NOT AVAILABLE")
            continue

        keywords = rule["keywords"]
        window = rule["window"]
        min_digits = rule.get("min_digits")
        max_digits = rule.get("max_digits")
        keyword_matchers = _build_keyword_matchers(keywords) if keywords else []

        for match in re.finditer(pattern, text):
            value = _extract_match_value(match)
            cleaned = value.strip()
            if not cleaned:
                continue
            if min_digits is not None or max_digits is not None:
                digits = sum(1 for ch in cleaned if ch.isdigit())
                if min_digits is not None and digits < min_digits:
                    continue
                if max_digits is not None and digits > max_digits:
                    continue
            if keyword_matchers:
                if window <= 0:
                    continue
                if word_spans is None:
                    word_spans = _word_spans(text_lower)
                window_text = _extract_window_text(
                    text_lower, word_spans, match.span(), window
                )
                if not window_text or not _window_has_keyword(
                    window_text, keyword_matchers
                ):
                    continue
            findings.append(
                {
                    "field": rule["field"],
                    "value": cleaned,
                    "sources": ["dlp_regex"],
                }
            )

    return findings


def _normalize_regex_rule(field_name: str, entry: object) -> Dict[str, Any]:
    if isinstance(entry, str):
        return {
            "field": field_name,
            "regex": entry,
            "window": 0,
            "keywords": [],
            "min_digits": None,
            "max_digits": None,
            "region": None,
        }
    if isinstance(entry, Mapping):
        regex = entry.get("regex") or entry.get("pattern")
        if not isinstance(regex, str):
            raise ValueError(f"Regex pattern missing for field {field_name}")
        return {
            "field": entry.get("field", field_name),
            "regex": regex,
            "window": int(entry.get("window") or 0),
            "keywords": list(entry.get("keywords") or []),
            "min_digits": entry.get("min_digits"),
            "max_digits": entry.get("max_digits"),
            "region": entry.get("region"),
        }
    raise ValueError(f"Invalid regex entry for field {field_name}")


def _detect_with_phonenumbers(
    text: str, region: str = "US", field_name: str = "PHONE_NUMBER"
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    try:
        for match in phonenumbers.PhoneNumberMatcher(text, region):
            findings.append(
                {
                    "field": field_name,
                    "value": match.raw_string,
                    "sources": ["dlp_phonenumbers"],
                }
            )
    except Exception:
        pass

    return findings


def _collect_sources(item: Mapping[str, Any]) -> List[str]:
    raw_sources = item.get("sources")
    if raw_sources is None:
        raw_sources = item.get("source")
    if isinstance(raw_sources, list):
        source_items = raw_sources
    elif raw_sources is None:
        source_items = []
    else:
        source_items = [raw_sources]

    normalized: List[str] = []
    for source in source_items:
        if not isinstance(source, str):
            continue
        cleaned = source.strip()
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def _extract_match_value(match: re.Match[str]) -> str:
    groups = match.groups()
    if groups:
        parts = [part if part is not None else "" for part in groups]
        return " ".join(parts)
    return match.group(0)


def _word_spans(text_lower: str) -> List[Tuple[int, int]]:
    return [m.span() for m in re.finditer(r"\b\w+\b", text_lower)]


def _extract_window_text(
    text_lower: str,
    word_spans: List[Tuple[int, int]],
    match_span: Tuple[int, int],
    window: int,
) -> str:
    if not word_spans:
        return ""
    match_start, match_end = match_span
    start_index = None
    end_index = None
    for i, (start, end) in enumerate(word_spans):
        if start_index is None and end >= match_start:
            start_index = i
        if start <= match_end:
            end_index = i
    if start_index is None:
        start_index = 0
    if end_index is None:
        end_index = start_index
    if end_index < start_index:
        end_index = start_index
    window_start = max(0, start_index - window)
    window_end = min(len(word_spans) - 1, end_index + window)
    char_start = word_spans[window_start][0]
    char_end = word_spans[window_end][1]
    return text_lower[char_start:char_end]


def _build_keyword_matchers(
    keywords: Iterable[str],
) -> List[Tuple[str, object]]:
    matchers: List[Tuple[str, object]] = []
    for keyword in keywords:
        kw = keyword.strip().lower()
        if not kw:
            continue
        if re.search(r"\W", kw):
            matchers.append(("substr", kw))
        else:
            matchers.append(("regex", re.compile(rf"\b{re.escape(kw)}\b")))
    return matchers


def _window_has_keyword(window_text: str, matchers: List[Tuple[str, object]]) -> bool:
    for kind, matcher in matchers:
        if kind == "substr":
            if matcher in window_text:
                return True
        elif matcher.search(window_text):
            return True
    return False


__all__ = [
    "detect_keywords",
    "detect_regex_patterns",
    "apply_checksum_validation",
]
