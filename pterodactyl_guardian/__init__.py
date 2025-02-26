"""
Pterodactyl Guardian SDK - Intelligent security monitoring for Pterodactyl Panel.

This package provides a comprehensive security and abuse detection system
for Pterodactyl Panel installations, leveraging advanced analysis techniques,
adaptive learning, and behavioral prediction to identify and mitigate threats.
"""

from .client import PterodactylGuardian
from .detect.engine import DetectionModules
from .analysis.static import AnalysisLevel
from .intelligence.learning import LearningMode
from .monitoring.scheduler import ScheduleFrequency

__version__ = "0.1.0"
__author__ = "info@zenturocloud.com"
__license__ = "MIT"

__all__ = [
    "PterodactylGuardian",
    "DetectionModules",
    "AnalysisLevel",
    "LearningMode",
    "ScheduleFrequency",
    "__version__",
]
