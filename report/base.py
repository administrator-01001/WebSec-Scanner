from abc import ABC, abstractmethod
from webscanner.models.result import ScanResult


class ReportGenerator(ABC):
    @abstractmethod
    def generate(self, result: ScanResult, output_path: str = ""):
        pass
