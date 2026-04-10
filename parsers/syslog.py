"""
parsers/syslog.py
-----------------
Parses Linux syslog / auth.log format.
Detects auth failures, sudo, su, session events, and user management.
Yields one Event per matched line, skips lines that don't match any rule.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib  import Path
from typing   import Iterator, Optional

from .base import BaseParser
from soc_toolkit.models.event import Event, EventType, Severity


# ── Timestamp ──────────────────────────────────────────────────────────────
_TS_PATTERN  = re.compile(r'^(\w{3}\s+\d+\s+[\d:]+)')
_CURRENT_YEAR = datetime.now().year

# ── Header (host + process) ────────────────────────────────────────────────
_HEADER = re.compile(
    r'^\w{3}\s+\d+\s+[\d:]+\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)$'
)

# ── Event classification rules ─────────────────────────────────────────────
# Each rule: (process_hint | None, message_pattern, EventType, Severity)
# process_hint: if set, only try this pattern when process matches the hint.
# This avoids false-positive matches across process types.
_RULES: list[tuple[Optional[str], re.Pattern, EventType, Severity]] = [

    # ── Auth failures ──────────────────────────────────────────────────────
    (None,
     re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)', re.I),
     EventType.AUTH_FAILURE, Severity.ERROR),

    (None,
     re.compile(r'authentication failure.*user=(\S+).*rhost=([\d.]+)', re.I),
     EventType.AUTH_FAILURE, Severity.ERROR),

    (None,
     re.compile(r'Invalid user (\S+) from ([\d.]+)', re.I),
     EventType.AUTH_FAILURE, Severity.WARNING),

    (None,
     re.compile(r'pam_unix.*authentication failure.*user=(\S+)', re.I),
     EventType.AUTH_FAILURE, Severity.ERROR),

    # ── Auth success ───────────────────────────────────────────────────────
    (None,
     re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)', re.I),
     EventType.AUTH_SUCCESS, Severity.INFO),

    # ── Privilege escalation — sudo ────────────────────────────────────────
    # Message format when process="sudo": "user : TTY=... ; COMMAND=..."
    ('sudo',
     re.compile(r'^(\S+)\s+:.*COMMAND=(.+)', re.I),
     EventType.SUDO, Severity.INFO),

    # Sudo auth failure: "sudo: pam_unix ... authentication failure; ... user=X"
    ('sudo',
     re.compile(r'authentication failure.*user=(\S+)', re.I),
     EventType.SUDO, Severity.WARNING),

    # ── Privilege escalation — su ──────────────────────────────────────────
    (None,
     re.compile(r'pam_unix.*su.*session opened for user (\S+)', re.I),
     EventType.SU, Severity.INFO),

    (None,
     re.compile(r'Successful su for (\S+)', re.I),
     EventType.SU, Severity.WARNING),

    # ── Session ───────────────────────────────────────────────────────────
    (None,
     re.compile(r'session opened for user (\S+)', re.I),
     EventType.SESSION_OPEN, Severity.INFO),

    (None,
     re.compile(r'session closed for user (\S+)', re.I),
     EventType.SESSION_CLOSE, Severity.INFO),

    # ── User / group management ────────────────────────────────────────────
    # "new user: name=backdoor, UID=..." — stop capture at comma or whitespace
    (None,
     re.compile(r'new user: name=([^,\s]+)', re.I),
     EventType.USER_CREATED, Severity.WARNING),

    (None,
     re.compile(r'delete user (\S+)', re.I),
     EventType.USER_DELETED, Severity.WARNING),

    (None,
     re.compile(r'(?:groupadd|usermod).*(?:group|user) ([^,\s]+)', re.I),
     EventType.GROUP_CHANGE, Severity.WARNING),
]


def _parse_timestamp(line: str) -> Optional[datetime]:
    m = _TS_PATTERN.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(f"{_CURRENT_YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _looks_like_ip(s: Optional[str]) -> bool:
    if not s:
        return False
    return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s))


def _classify(
    process: str, message: str
) -> tuple[EventType, Severity, Optional[str], Optional[str]]:
    """
    Return (event_type, severity, user, ip).
    Tries process-specific rules first, then general rules.
    """
    proc_lower = process.lower()

    for proc_hint, pattern, etype, esev in _RULES:
        # Skip rules that only apply to a specific process
        if proc_hint and proc_lower != proc_hint:
            continue

        m = pattern.search(message)
        if not m:
            continue

        groups = m.groups()
        user = groups[0] if len(groups) >= 1 else None
        ip   = groups[1] if len(groups) >= 2 and _looks_like_ip(groups[1]) else None

        # For sudo commands, first group is user, second is command (not IP)
        if etype == EventType.SUDO and user and not ip:
            pass  # user extracted correctly, no IP expected

        return etype, esev, user, ip

    return EventType.GENERIC, Severity.UNKNOWN, None, None


class SyslogParser(BaseParser):

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return (
            'auth'   in name or
            'syslog' in name or
            name.endswith('.log')    or
            name.endswith('.log.gz') or
            name.endswith('.sample')
        )

    def parse(self, path: Path) -> Iterator[Event]:
        with self.open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                ts  = _parse_timestamp(line)
                hm  = _HEADER.match(line)

                host    = hm.group('host')    if hm else ''
                process = hm.group('process') if hm else ''
                pid     = hm.group('pid')     if hm else None
                message = hm.group('message') if hm else line

                etype, esev, user, ip = _classify(process, message)

                yield Event(
                    event_type = etype,
                    severity   = esev,
                    timestamp  = ts,
                    source     = str(path),
                    host       = host,
                    process    = process,
                    pid        = pid,
                    user       = user,
                    ip         = ip,
                    message    = message,
                    raw        = line,
                )
