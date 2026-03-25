from __future__ import annotations

import pytest
from multiagent_firewall.detectors.dlp import (
    apply_checksum_validation,
    detect_keywords,
    detect_regex_patterns,
)
from multiagent_firewall.detectors.checksum_validators import validate_ssn


def test_detect_keywords_default():
    text = """
    Here is my key:
    -----BEGIN PRIVATE KEY-----
    super-secret-material
    -----END PRIVATE KEY-----
    """
    findings = detect_keywords(text)

    assert len(findings) >= 1
    field_names = [f["field"] for f in findings]
    assert "PASSWORD" in field_names


def test_detect_keywords_custom():
    text = "This contains foo and bar"
    custom_keywords = {
        "CUSTOM_FIELD": ["foo", "bar"],
    }
    findings = detect_keywords(text, custom_keywords)

    assert len(findings) == 2
    assert all(f["field"] == "CUSTOM_FIELD" for f in findings)
    assert all(f["sources"] == ["dlp_keyword"] for f in findings)


def test_detect_keywords_case_insensitive():
    text = "ssh key header -----begin private key----- content"
    findings = detect_keywords(text)

    field_names = [f["field"] for f in findings]
    assert "PASSWORD" in field_names


def test_detect_keywords_empty_text():
    findings = detect_keywords("")
    assert findings == []


def test_apply_checksum_validation_keeps_valid_checksum_fields():
    findings = [
        {
            "field": "SSN",
            "value": "123-45-6789",
            "sources": ["dlp_regex"],
        },
        {
            "field": "EMAIL",
            "value": "a@example.com",
            "sources": ["dlp_regex"],
        },
    ]

    validated = apply_checksum_validation(findings)

    assert len(validated) == 2
    ssn = next(item for item in validated if item["field"] == "SSN")
    assert ssn["sources"] == ["dlp_regex", "dlp_checksum"]


def test_apply_checksum_validation_removes_invalid_checksum_fields():
    findings = [
        {
            "field": "SSN",
            "value": "000-45-6789",
            "sources": ["dlp_regex"],
        },
        {
            "field": "EMAIL",
            "value": "a@example.com",
            "sources": ["dlp_regex"],
        },
    ]

    validated = apply_checksum_validation(findings)

    assert len(validated) == 1
    fields = {item["field"] for item in validated}
    assert fields == {"EMAIL"}


def test_detect_regex_patterns_default():
    text = "Contact me at test@example.com or +1-650-253-0000"
    findings = detect_regex_patterns(text)

    assert len(findings) >= 2
    field_names = [f["field"] for f in findings]
    assert "EMAIL" in field_names
    assert "PHONE_NUMBER" in field_names


def test_detect_regex_patterns_custom():
    text = "Order ID: ABC123"
    custom_patterns = {
        "ORDER_ID": {
            "field": "ORDER_ID",
            "regex": r"\b[A-Z]{3}\d{3}\b",
            "window": 0,
            "keywords": [],
        },
    }
    findings = detect_regex_patterns(text, custom_patterns)

    assert len(findings) == 1
    assert findings[0]["field"] == "ORDER_ID"
    assert findings[0]["value"] == "ABC123"
    assert findings[0]["sources"] == ["dlp_regex"]


def test_detect_regex_patterns_empty_text():
    findings = detect_regex_patterns("")
    assert findings == []


def test_detect_regex_patterns_no_match():
    text = "No sensitive data here"
    findings = detect_regex_patterns(text)
    assert findings == []


def test_detect_regex_patterns_tuple_match():
    text = "test@example.com"
    custom_patterns = {
        "EMAIL_PARTS": {
            "field": "EMAIL_PARTS",
            "regex": r"(\w+)@(\w+\.\w+)",
            "window": 0,
            "keywords": [],
        },
    }
    findings = detect_regex_patterns(text, custom_patterns)

    assert len(findings) == 1
    assert "test example.com" in findings[0]["value"]


def test_detect_regex_patterns_keyword_window_allows_match():
    text = "SSN: 123-45-6789"
    custom_patterns = {
        "SSN": {
            "field": "SSN",
            "regex": r"\b\d{3}-\d{2}-\d{4}\b",
            "window": 1,
            "keywords": ["ssn"],
        },
    }
    findings = detect_regex_patterns(text, custom_patterns)

    assert len(findings) == 1
    assert findings[0]["field"] == "SSN"


def test_detect_regex_patterns_keyword_window_blocks_match():
    text = "SSN data for records 123-45-6789"
    custom_patterns = {
        "SSN": {
            "field": "SSN",
            "regex": r"\b\d{3}-\d{2}-\d{4}\b",
            "window": 2,
            "keywords": ["ssn"],
        },
    }
    findings = detect_regex_patterns(text, custom_patterns)

    assert findings == []


# ============================================================================
# Extended Regex Pattern Tests
# ============================================================================


def test_detect_regex_ipv4():
    text = "Server IP is 192.168.1.1 and gateway is 10.0.0.1"
    findings = detect_regex_patterns(text)

    field_names = [f["field"] for f in findings]
    assert "IPV4" in field_names
    values = [f["value"] for f in findings if f["field"] == "IPV4"]
    assert "192.168.1.1" in values
    assert "10.0.0.1" in values


def test_detect_regex_mac_address():
    text = "MAC: 00:1A:2B:3C:4D:5E and 00-1A-2B-3C-4D-5F"
    findings = detect_regex_patterns(text)

    mac_findings = [f for f in findings if f["field"] == "MAC_ADDRESS"]
    assert len(mac_findings) >= 1


def test_detect_regex_url():
    text = "Visit https://example.com or http://test.org"
    findings = detect_regex_patterns(text)

    field_names = [f["field"] for f in findings]
    assert "URL" in field_names


def test_detect_regex_credit_card():
    text = "Card: 4532-0151-1283-0366"
    findings = detect_regex_patterns(text)

    field_names = [f["field"] for f in findings]
    assert "CREDIT_DEBIT_CARD" in field_names


def test_detect_regex_date():
    text = "Date: 2024-05-12"
    findings = detect_regex_patterns(text)

    field_names = [f["field"] for f in findings]
    assert "DATE" in field_names


# ============================================================================
# Extended Keyword Tests
# ============================================================================


def test_detect_keywords_ignores_generic_terms():
    text = "Enter your credentials to sign in with fingerprint and medical info"
    findings = detect_keywords(text)

    assert findings == []


# ============================================================================
# Checksum Validator Tests
# ============================================================================


def test_validate_ssn_valid():
    assert validate_ssn("123-45-6789") is True
    assert validate_ssn("123 45 6789") is True
    assert validate_ssn("123456789") is True


def test_validate_ssn_invalid():
    assert validate_ssn("000-45-6789") is False  # Area 000
    assert validate_ssn("666-45-6789") is False  # Area 666
    assert validate_ssn("900-45-6789") is False  # Area 900+
    assert validate_ssn("123-00-6789") is False  # Group 00
    assert validate_ssn("123-45-0000") is False  # Serial 0000
    assert validate_ssn("1234567890") is False  # Invalid length
    assert validate_ssn("12345678901") is False  # Invalid length


# ============================================================================
# Integration Tests
# ============================================================================


def test_integration_high_risk_data():
    text = """
    -----BEGIN PRIVATE KEY-----
    mySecret123
    -----END PRIVATE KEY-----
    Credit Card: 4532-0151-1283-0366
    SSN: 123-45-6789
    """

    keyword_findings = detect_keywords(text)
    regex_findings = detect_regex_patterns(text)
    validated_regex_findings = apply_checksum_validation(regex_findings)

    # Should detect multiple high-risk fields
    all_findings = keyword_findings + validated_regex_findings
    field_names = [f["field"] for f in all_findings]

    assert "PASSWORD" in field_names
    # Credit card and SSN should remain detectable after checksum validation
    assert "CREDIT_DEBIT_CARD" in field_names
    assert "SSN" in field_names


def test_integration_medium_risk_data():
    text = """
    Contact information:
    Email: user@example.com
    Phone: +1-650-253-0000
    Company: Acme Corp
    """

    keyword_findings = detect_keywords(text)
    regex_findings = detect_regex_patterns(text)

    all_findings = keyword_findings + regex_findings
    field_names = [f["field"] for f in all_findings]

    assert "EMAIL" in field_names
    assert "PHONE_NUMBER" in field_names
    assert "PASSWORD" not in field_names
