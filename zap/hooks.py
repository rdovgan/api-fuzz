"""Custom zap-api-scan.py hooks: tune down active-scan aggressiveness.

Loaded via `--hook /zap/hooks/hooks.py`. `zap_active_scan` runs right before
the active scan starts, with the actual scan policy object the scan will use
— so changes here are guaranteed to apply (unlike the `-config scanner.*`
global defaults, which per zaproxy/zaproxy#1530 don't reliably override an
already-defined named policy).

Applies Attack Strength=LOW / Alert Threshold=HIGH to every scan rule in the
policy: fewer payloads per parameter, and only reports higher-confidence
findings. Reduces request volume and skips the most aggressive payload
variants (still includes SQLi/XSS/command-injection/etc., just fewer/gentler
attempts per rule).
"""

ATTACK_STRENGTH = "LOW"
ALERT_THRESHOLD = "HIGH"


def zap_active_scan(zap, target, policy):
    rules = zap.ascan.scanners(policy)
    for rule in rules:
        rule_id = rule["id"]
        zap.ascan.set_scanner_attack_strength(rule_id, ATTACK_STRENGTH, policy)
        zap.ascan.set_scanner_alert_threshold(rule_id, ALERT_THRESHOLD, policy)
    print(f"[hooks.py] Set {len(rules)} scan rules in policy '{policy}' to "
          f"strength={ATTACK_STRENGTH}, threshold={ALERT_THRESHOLD}")
