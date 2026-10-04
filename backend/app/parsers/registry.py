"""Bootstraps the ParserRegistry with all deterministic (known-format) parsers.

Adding a sixth known source later means writing one new BaseLogParser
subclass and adding one line here — nothing else in the pipeline changes.
"""
from app.parsers.apache import ApacheAccessParser
from app.parsers.base import ParserRegistry
from app.parsers.cisco import CiscoSyslogParser
from app.parsers.fortigate import FortigateParser
from app.parsers.linux import LinuxSyslogParser
from app.parsers.windows import WindowsJsonParser


def build_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register_parser(CiscoSyslogParser())
    registry.register_parser(FortigateParser())
    registry.register_parser(LinuxSyslogParser())
    registry.register_parser(WindowsJsonParser())
    registry.register_parser(ApacheAccessParser())
    return registry


# Process-wide singleton used by the API layer.
parser_registry = build_registry()
