"""Load a strict, user-editable JSON ruleset (no arbitrary code execution)."""
import json
from pathlib import Path

from .rules import ALL_RULES, DEFAULT_THRESHOLDS
ALLOWED = set(ALL_RULES)
NUMBERS = {"scan_ports": (1, 65535), "scan_window": (1, 3600),
           "rate_packets": (1, 1000000), "rate_window": (1, 3600),
           "syn_packets": (1, 1000000), "syn_window": (1, 3600),
           "icmp_packets": (1, 1000000), "icmp_window": (1, 3600),
           "cooldown": (0, 3600)}


def load_ruleset(path):
    data = json.loads(Path(path).read_text(encoding="utf8"))
    if not isinstance(data, dict) or set(data) != {"enabled", "settings", "prohibited_ports", "thresholds"}:
        raise ValueError("Ruleset must have exactly: enabled, settings, prohibited_ports, thresholds")
    enabled, settings, ports = data["enabled"], data["settings"], data["prohibited_ports"]
    if not isinstance(enabled, list) or any(not isinstance(x, str) or x not in ALLOWED for x in enabled) or len(set(enabled)) != len(enabled):
        raise ValueError("Invalid or duplicate enabled rule ID")
    if not isinstance(settings, dict) or set(settings) != set(NUMBERS):
        raise ValueError("Settings must contain exactly the documented numeric keys")
    for k, (low, high) in NUMBERS.items():
        val = settings[k]
        if type(val) is not int or not low <= val <= high:
            raise ValueError(f"{k} must be an integer between {low} and {high}")
    if not isinstance(ports, list) or any(type(x) is not int or not 1 <= x <= 65535 for x in ports) or len(set(ports)) != len(ports):
        raise ValueError("prohibited_ports must be unique TCP ports 1..65535")
    limits = data.get("thresholds")
    if not isinstance(limits, dict) or set(limits) != set(DEFAULT_THRESHOLDS):
        raise ValueError("thresholds must contain exactly the configurable extended rule IDs")
    validated = {}
    for rule, default in DEFAULT_THRESHOLDS.items():
        pair = limits[rule]
        if not isinstance(pair, list) or len(pair) != 2 or any(type(x) is not int for x in pair):
            raise ValueError(f"{rule} must be a list of two integers")
        # Entropy is expressed in centibits; zero indicates an unused window for single-packet rules.
        if not (1 <= pair[0] <= 1000000 and 0 <= pair[1] <= 3600):
            raise ValueError(f"{rule} threshold values outside permitted range")
        validated[rule] = tuple(pair)
    return {**settings, "enabled": enabled, "prohibited_ports": ports, "thresholds": validated}


if __name__ == "__main__":
    import os
    path = os.environ.get("NETSENTRY_RULESET") or ("/app/config/rules.json" if Path("/app/config/rules.json").exists() else "config/rules.json")
    print("Valid ruleset:", path, load_ruleset(path))
