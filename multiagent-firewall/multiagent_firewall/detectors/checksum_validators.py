from __future__ import annotations


def validate_ssn(ssn: str) -> bool:
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


__all__ = ["validate_ssn"]
