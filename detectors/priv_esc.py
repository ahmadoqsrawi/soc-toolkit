"""
detectors/priv_esc.py
---------------------
Detects privilege escalation patterns:
  1. Sudo abuse      — user runs sudo commands after authenticating
  2. Failed sudo     — repeated failed sudo attempts (password guessing)
  3. Su switching    — switching to another user via su
  4. User creation   — new accounts added (post-compromise persistence)
  5. Group changes   — user added to privileged group (wheel, sudo, admin)

Each pattern is a separate Finding so analysts can triage independently.
All findings from the same user in a session are linked via metadata.
"""

from __future__ import annotations

from collections import defaultdict
from typing      import Iterator

from .base import BaseDetector
from soc_toolkit.models.event   import Event, EventType, Severity
from soc_toolkit.models.finding import Finding, Confidence
from soc_toolkit.config.loader  import Config

# Commands that indicate high-risk sudo usage
_HIGH_RISK_COMMANDS = (
    '/bin/bash', '/bin/sh', '/bin/zsh',
    '/usr/bin/passwd', '/usr/bin/chsh',
    '/usr/sbin/useradd', '/usr/sbin/usermod', '/usr/sbin/userdel',
    '/usr/sbin/visudo', '/etc/sudoers',
    'chmod', 'chown', '/etc/shadow', '/etc/passwd',
    'nc ', 'netcat', 'ncat', 'curl', 'wget',
    'python', 'perl', 'ruby', 'php',
)

_FAILED_SUDO_THRESHOLD = 3


def _extract_command(message: str) -> str:
    """Extract the COMMAND= value from a sudo log message."""
    if 'COMMAND=' in message:
        return message.split('COMMAND=', 1)[-1].strip()
    return ''


def _is_high_risk(command: str) -> bool:
    cmd_lower = command.lower()
    return any(risk in cmd_lower for risk in _HIGH_RISK_COMMANDS)


class PrivEscDetector(BaseDetector):

    def __init__(self, config: Config = None):
        self.cfg = config or Config()

    @property
    def rule_id(self) -> str:
        return "priv_esc"

    def analyze(self, events: Iterator[Event]) -> Iterator[Finding]:
        # Collect all priv-esc related events by type
        sudo_events:         list[Event] = []
        failed_sudo_by_user: dict[str, list[Event]] = defaultdict(list)
        su_events:           list[Event] = []
        user_created_events: list[Event] = []
        group_change_events: list[Event] = []

        for event in events:
            if event.user and event.user in self.cfg.allowed_users:
                continue

            if event.event_type == EventType.SUDO:
                if 'authentication failure' in event.message.lower() or \
                   'incorrect password' in event.message.lower():
                    if event.user:
                        failed_sudo_by_user[event.user].append(event)
                else:
                    sudo_events.append(event)

            elif event.event_type == EventType.SU:
                su_events.append(event)

            elif event.event_type == EventType.USER_CREATED:
                user_created_events.append(event)

            elif event.event_type == EventType.GROUP_CHANGE:
                group_change_events.append(event)

        # ── 1. Sudo command execution ──────────────────────────────────────
        if sudo_events:
            high_risk = [e for e in sudo_events if _is_high_risk(_extract_command(e.message))]
            normal    = [e for e in sudo_events if e not in high_risk]

            if high_risk:
                commands  = [_extract_command(e.message) for e in high_risk]
                users     = list({e.user for e in high_risk if e.user})
                cmd_str   = "; ".join(commands[:5])
                if len(commands) > 5:
                    cmd_str += f" (+{len(commands)-5} more)"

                yield Finding(
                    rule_id     = self.rule_id,
                    title       = "High-risk sudo command executed",
                    severity    = Severity.CRITICAL,
                    confidence  = Confidence.HIGH,
                    description = (
                        f"User(s) {', '.join(users)} executed high-risk sudo "
                        f"command(s) that indicate privilege abuse or "
                        f"potential post-compromise activity: {cmd_str}."
                    ),
                    recommendation = (
                        "Review these commands immediately. Shell spawns "
                        "(bash/sh) via sudo are a strong indicator of "
                        "privilege escalation. Correlate with preceding "
                        "authentication events from the same user."
                    ),
                    events   = high_risk,
                    metadata = {
                        "users":    users,
                        "commands": commands,
                        "risk":     "high",
                    },
                )

            if normal:
                users   = list({e.user for e in normal if e.user})
                yield Finding(
                    rule_id     = self.rule_id,
                    title       = f"Sudo activity — {len(normal)} command(s)",
                    severity    = Severity.MEDIUM,
                    confidence  = Confidence.MEDIUM,
                    description = (
                        f"User(s) {', '.join(users)} ran {len(normal)} sudo "
                        f"command(s). Review if this is expected for these accounts."
                    ),
                    recommendation = (
                        "Verify sudo usage is authorized. If preceded by "
                        "a brute force or spray finding, treat as HIGH."
                    ),
                    events   = normal,
                    metadata = {"users": users, "risk": "normal"},
                )

        # ── 2. Failed sudo attempts ────────────────────────────────────────
        for user, evs in failed_sudo_by_user.items():
            if len(evs) < _FAILED_SUDO_THRESHOLD:
                continue
            yield Finding(
                rule_id     = self.rule_id,
                title       = f"Repeated failed sudo attempts by {user}",
                severity    = Severity.HIGH,
                confidence  = Confidence.HIGH,
                description = (
                    f"{user} failed sudo authentication {len(evs)} time(s). "
                    f"This may indicate password guessing on a compromised "
                    f"low-privilege account attempting to escalate."
                ),
                recommendation = (
                    f"Investigate {user}'s recent login history. If the "
                    f"account was recently authenticated from an unusual IP, "
                    f"treat as active compromise."
                ),
                events   = evs,
                metadata = {"user": user, "failed_count": len(evs)},
            )

        # ── 3. Su switching ───────────────────────────────────────────────
        if su_events:
            targets = list({e.user for e in su_events if e.user})
            root_su = [e for e in su_events if e.user == 'root']

            severity = Severity.HIGH if root_su else Severity.MEDIUM
            desc_target = "root" if root_su else ", ".join(targets)

            yield Finding(
                rule_id     = self.rule_id,
                title       = f"User switching via su to {desc_target}",
                severity    = severity,
                confidence  = Confidence.MEDIUM,
                description = (
                    f"su was used to switch to account(s): "
                    f"{', '.join(targets)}. "
                    f"{'Switching to root is high-risk and warrants immediate review.' if root_su else ''}"
                ),
                recommendation = (
                    "Verify su usage is authorized. If the originating "
                    "session followed unusual authentication, treat as "
                    "lateral movement or privilege escalation."
                ),
                events   = su_events,
                metadata = {"target_users": targets, "root_switch": bool(root_su)},
            )

        # ── 4. New user creation ───────────────────────────────────────────
        if user_created_events:
            created_users = [e.user for e in user_created_events if e.user]
            yield Finding(
                rule_id     = self.rule_id,
                title       = f"New user account created: {', '.join(created_users)}",
                severity    = Severity.HIGH,
                confidence  = Confidence.HIGH,
                description = (
                    f"{len(user_created_events)} new user account(s) created: "
                    f"{', '.join(created_users)}. "
                    f"Attacker-created accounts are a common persistence mechanism."
                ),
                recommendation = (
                    "Verify each new account is authorized. If unexpected, "
                    "disable immediately, audit sudo/group membership, and "
                    "check for SSH authorized_keys changes."
                ),
                events   = user_created_events,
                metadata = {"created_users": created_users},
            )

        # ── 5. Group changes ───────────────────────────────────────────────
        if group_change_events:
            yield Finding(
                rule_id     = self.rule_id,
                title       = f"Group membership changed ({len(group_change_events)} event(s))",
                severity    = Severity.HIGH,
                confidence  = Confidence.MEDIUM,
                description = (
                    f"{len(group_change_events)} group membership change(s) "
                    f"detected. Adding users to wheel, sudo, or admin groups "
                    f"grants elevated privileges."
                ),
                recommendation = (
                    "Verify all group changes are authorized. Pay particular "
                    "attention to wheel, sudo, and admin group modifications."
                ),
                events   = group_change_events,
                metadata = {},
            )
