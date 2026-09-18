"""
PhishGuard Detection Engine
Modular, explainable detection system for email security analysis.
"""

from .engine import DetectionEngine
from .scoring import RiskScorer
from .rules import Finding
from .sender import SenderAnalyzer
from .url_analyzer import URLAnalyzer
from .content_analyzer import ContentAnalyzer
from .header_analyzer import HeaderAnalyzer
from .attachment_analyzer import AttachmentAnalyzer

__all__ = [
    "DetectionEngine",
    "RiskScorer",
    "SenderAnalyzer",
    "URLAnalyzer",
    "ContentAnalyzer",
    "HeaderAnalyzer",
    "AttachmentAnalyzer",
]
