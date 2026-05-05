"""
============================================
BLACK WALL — Attack Type Classifiers
============================================
Heuristic functions that classify Wazuh rule groups
and descriptions into known attack categories.
"""


def classify_attack_type(groups: list[str], description: str) -> str:
    """
    Classify an alert into a known attack category based on
    Wazuh rule groups and description text.

    Returns one of: brute_force, sql_injection, web_scan, dos_ddos,
    port_scan, or unknown.
    """
    desc_lower = description.lower()
    groups_lower = [g.lower() for g in groups]

    if any("brute force" in g for g in groups_lower) or \
       "brute force" in desc_lower or "failed" in desc_lower:
        return "brute_force"

    if any("sql" in g for g in groups_lower) or "sql injection" in desc_lower:
        return "sql_injection"

    if "404" in desc_lower or "web_scan" in groups_lower:
        return "web_scan"

    if "flood" in desc_lower or "dos" in desc_lower:
        return "dos_ddos"

    return "unknown"
