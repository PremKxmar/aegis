"""MCP security gateway: fingerprint tools, detect poisoning and rug pulls.

Two different defences live here and they catch different things:

  static scan   reads a tool description on arrival and looks for hidden
                instructions, HTML-comment payloads, system tags, base64
                blobs and zero-width unicode. Pattern-based, so evadable.

  rug pull      hashes every tool definition at registration and compares on
                every later sighting. Content-independent: it does not care
                what the new description *says*, only that it changed. A
                server that ships clean, earns trust, then mutates is caught
                regardless of how innocuous the new text looks.

Measured behaviour of the underlying scanner (see tests/test_mcp_gateway.py):
a description containing a bare `~/.ssh/id_rsa` read request scores ZERO on
the static scan -- no keyword matches. The rug-pull check flags it as
CRITICAL. That gap is the argument for fingerprinting over filtering.
"""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)

from agent_os import MCPSecurityScanner  # noqa: E402

# The scanner logs every finding at INFO to stdout, which drowns the demo.
logging.getLogger("agent_os.mcp_security").setLevel(logging.WARNING)
logging.getLogger("agent_os.prompt_injection").setLevel(logging.WARNING)


@dataclass
class ToolRecord:
    server: str
    name: str
    description: str
    version: int = 1
    threats: list[str] = field(default_factory=list)
    quarantined: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"server": self.server, "name": self.name,
                "description": self.description[:120],
                "version": self.version, "threats": self.threats,
                "quarantined": self.quarantined}


class MCPGateway:
    """Front door for every MCP tool definition entering the system."""

    def __init__(self) -> None:
        self.scanner = MCPSecurityScanner()
        self.tools: dict[str, ToolRecord] = {}
        self.events: list[dict[str, Any]] = []

    @staticmethod
    def _key(server: str, name: str) -> str:
        return f"{server}::{name}"

    def register(self, server: str, name: str, description: str,
                 schema: dict[str, Any] | None = None) -> list[str]:
        """Admit or quarantine a tool definition. Returns threat messages.

        First sighting runs the static scan and fingerprints the tool. Later
        sightings additionally run the rug-pull comparison.
        """
        key = self._key(server, name)
        messages: list[str] = []

        # scan_tool already performs the rug-pull comparison internally
        # (agent_os/mcp_security.py:462) when a fingerprint exists, so calling
        # check_rug_pull() as well double-reports every finding.
        for threat in self.scanner.scan_tool(name, description, schema,
                                             server_name=server):
            msg = (f"{str(threat.threat_type).split('.')[-1]}/"
                   f"{str(threat.severity).split('.')[-1]}: {threat.message}")
            if msg not in messages:
                messages.append(msg)

        # Re-register so the fingerprint tracks the newest definition; the
        # comparison above already happened against the previous one.
        fp = self.scanner.register_tool(name, description, schema, server)

        rec = self.tools.get(key) or ToolRecord(server, name, description)
        rec.description = description
        rec.version = getattr(fp, "version", rec.version)
        rec.threats = messages
        rec.quarantined = bool(messages)
        self.tools[key] = rec

        self.events.append({"tool": key, "version": rec.version,
                            "threats": messages, "quarantined": rec.quarantined})
        return messages

    def is_allowed(self, server: str, name: str) -> tuple[bool, str]:
        rec = self.tools.get(self._key(server, name))
        if rec is None:
            return False, "tool not registered with the gateway"
        if rec.quarantined:
            return False, f"tool quarantined: {'; '.join(rec.threats[:2])}"
        return True, ""

    def snapshot(self) -> dict[str, Any]:
        return {"tools": [t.to_dict() for t in self.tools.values()],
                "events": self.events[-20:],
                "quarantined": sum(1 for t in self.tools.values() if t.quarantined)}

    def reset(self) -> None:
        self.scanner = MCPSecurityScanner()
        self.tools.clear()
        self.events.clear()
