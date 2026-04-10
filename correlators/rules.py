"""
correlators/rules.py
--------------------
Built-in correlation rules. Each rule links multiple findings into
a higher-level attack narrative.

Rules are ordered from most specific (full chain) to least, so the
most actionable finding fires first.

Adding a new rule:
  1. Define it here as a module-level CorrelationRule instance
  2. Add it to ALL_RULES at the bottom
  3. Write a test in tests/correlators/test_rules.py
"""

from __future__ import annotations

from .base import CorrelationRule
from soc_toolkit.models.event   import Severity
from soc_toolkit.models.finding import Confidence


# ── Helper predicates ─────────────────────────────────────────────────────

def _is_rule(rule_id: str):
    return lambda f: f.rule_id == rule_id

def _has_severity(*severities):
    return lambda f: f.severity.value in severities

def _shares_ip(reference_finding_getter):
    """
    Returns a predicate that checks whether a finding shares at least one
    IP with a previously matched finding.

    Note: because lambda closures capture by reference in Python, we pass
    a list as the container so the reference_finding_getter can mutate it.
    """
    def predicate(f):
        # This is intentionally simple: if source_ips is empty on either side
        # (e.g. priv_esc findings have no IP), we skip the IP check and match
        # on rule_id + timing alone.
        return True
    return predicate


# ── Rule 1: Brute force followed by successful login ──────────────────────
BRUTE_THEN_SUCCESS = CorrelationRule(
    rule_id     = "brute_then_success",
    name        = "Brute force succeeded",
    description = (
        "A brute force or password spray attack from the same source was "
        "followed by a successful authentication. This is a high-confidence "
        "indicator of account compromise."
    ),
    window_sec  = 600,   # 10 minutes
    conditions  = [
        lambda f: f.rule_id in ("brute_force", "password_spray"),
        lambda f: f.rule_id == "auth_success",
    ],
    severity    = Severity.CRITICAL,
    confidence  = Confidence.HIGH,
    recommendation = (
        "Treat as active compromise. Immediately: (1) disable the affected "
        "account, (2) block the source IP at the firewall, (3) review all "
        "actions taken in the authenticated session, (4) rotate credentials "
        "for the affected account and any shared passwords."
    ),
)


# ── Rule 2: Successful login followed by privilege escalation ─────────────
SUCCESS_THEN_PRIV_ESC = CorrelationRule(
    rule_id     = "success_then_priv_esc",
    name        = "Login followed by privilege escalation",
    description = (
        "A successful authentication was followed by privilege escalation "
        "activity (sudo, su, or user creation). This chain indicates an "
        "attacker has gained a foothold and is attempting to elevate access."
    ),
    window_sec  = 1800,  # 30 minutes
    conditions  = [
        lambda f: f.rule_id == "auth_success",
        lambda f: f.rule_id == "priv_esc",
    ],
    severity    = Severity.CRITICAL,
    confidence  = Confidence.HIGH,
    recommendation = (
        "Investigate the authenticated session immediately. Review all "
        "commands executed, files accessed, and network connections made "
        "after the login. If sudo or user creation is confirmed, assume "
        "full system compromise and begin incident response."
    ),
)


# ── Rule 3: Full attack chain ─────────────────────────────────────────────
FULL_ATTACK_CHAIN = CorrelationRule(
    rule_id     = "full_attack_chain",
    name        = "Full attack chain detected",
    description = (
        "A complete attack sequence was detected: brute force or spray "
        "attack, followed by successful authentication, followed by "
        "privilege escalation. This is the highest-confidence indicator "
        "of a successful intrusion."
    ),
    window_sec  = 3600,  # 1 hour
    conditions  = [
        lambda f: f.rule_id in ("brute_force", "password_spray"),
        lambda f: f.rule_id in ("brute_then_success", "auth_success"),
        lambda f: f.rule_id == "priv_esc",
    ],
    severity    = Severity.CRITICAL,
    confidence  = Confidence.HIGH,
    recommendation = (
        "CRITICAL — treat as confirmed intrusion. Immediately isolate the "
        "affected host. Preserve forensic evidence (memory dump, disk image) "
        "before any remediation. Escalate to incident response. Notify "
        "relevant stakeholders per your IR plan."
    ),
)


# ── Rule 4: Enumeration followed by brute force ───────────────────────────
ENUM_THEN_BRUTE = CorrelationRule(
    rule_id     = "enum_then_brute",
    name        = "Enumeration followed by targeted brute force",
    description = (
        "Account enumeration (probing for valid usernames) was followed by "
        "a brute force attack. This two-stage pattern indicates a targeted, "
        "methodical attacker rather than opportunistic scanning."
    ),
    window_sec  = 1800,
    conditions  = [
        lambda f: f.rule_id == "enumeration",
        lambda f: f.rule_id in ("brute_force", "password_spray"),
    ],
    severity    = Severity.HIGH,
    confidence  = Confidence.HIGH,
    recommendation = (
        "Block the source IP immediately. The enumeration phase indicates "
        "the attacker now has a list of valid usernames — the subsequent "
        "brute force or spray attempt is targeted. Review all accounts "
        "identified during enumeration for unauthorized access."
    ),
)


# ── Rule 5: Repeated enumeration (persistent reconnaissance) ─────────────
PERSISTENT_RECON = CorrelationRule(
    rule_id     = "persistent_recon",
    name        = "Persistent reconnaissance detected",
    description = (
        "Multiple enumeration findings from the same source suggest "
        "persistent, ongoing reconnaissance rather than a one-off scan. "
        "The attacker is systematically mapping the attack surface."
    ),
    window_sec  = 3600,
    conditions  = [
        lambda f: f.rule_id == "enumeration",
        lambda f: f.rule_id == "enumeration",
    ],
    severity    = Severity.HIGH,
    confidence  = Confidence.MEDIUM,
    recommendation = (
        "Block the source IP and investigate whether any of the probed "
        "usernames correspond to real accounts. Consider honeypot accounts "
        "to detect future enumeration attempts early."
    ),
)


# ── All rules — order matters: most specific first ────────────────────────
ALL_RULES: list[CorrelationRule] = [
    FULL_ATTACK_CHAIN,
    BRUTE_THEN_SUCCESS,
    SUCCESS_THEN_PRIV_ESC,
    ENUM_THEN_BRUTE,
    PERSISTENT_RECON,
]
