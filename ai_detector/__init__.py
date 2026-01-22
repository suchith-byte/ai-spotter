"""AI Service Detection CLI Tool.

Detects external AI/LLM service usage in repositories by analyzing
code, dependencies, configuration files, and API keys.

Example usage:
    >>> from ai_detector import scan_repository
    >>> results = scan_repository(repo_path="/path/to/repo")
    >>> for result in results:
    ...     print(f"{result.service_name}: {result.detection_type}")
"""

__version__ = "0.1.0"
__author__ = "Suchith"

from .config import AppConfig, get_config, set_config
from .detectors import DetectionResult, DetectorManager
from .reporters import ReporterManager
from .scanner import RepositoryScanner, scan_repository
from .services import AIService, AIServiceRegistry

__all__ = [
    # Version
    "__version__",
    # Core classes
    "AIService",
    "AIServiceRegistry",
    "DetectionResult",
    "DetectorManager",
    "ReporterManager",
    "RepositoryScanner",
    # Configuration
    "AppConfig",
    "get_config",
    "set_config",
    # Convenience functions
    "scan_repository",
]
