from abc import ABC, abstractmethod

from hkemlint.cpg.models import FunctionCPG, Finding


class BaseChecker(ABC):

    @abstractmethod
    def check(self, cpg: FunctionCPG) -> list[Finding]:
        ...
