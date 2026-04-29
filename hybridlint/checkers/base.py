"""Abstract base class for all SP checkers."""
from abc import ABC, abstractmethod

from hybridlint.cpg.models import FunctionCPG, Finding


class BaseChecker(ABC):
    """Base class that every security-property checker must subclass."""

    @abstractmethod
    def check(self, cpg: FunctionCPG) -> list[Finding]:
        """Analyse *cpg* and return zero or more findings."""
        ...
