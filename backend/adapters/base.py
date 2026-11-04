"""
backend/adapters/base.py
Abstract base class and registry for all security tool integrations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from backend.models import Finding, ToolRun, ToolStatus


class BaseAdapter(ABC):
    def __init__(self, tool_name: str, mode: str = "live"):
        self.tool_name = tool_name
        self.mode = mode

    @abstractmethod
    def parse(self, raw_output: str, target: str) -> List[Finding]:
        """Maps raw CLI/API/file output into unified Finding objects."""
        pass

    @abstractmethod
    def execute(self, target: str, options: Dict[str, Any]) -> ToolRun:
        """Executes live assessment or imports mock samples."""
        pass