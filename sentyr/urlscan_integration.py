"""
URLScan.io Integration - Stub Implementation

This is a minimal stub to maintain compatibility with the security analyst agent.
For full URLScan.io functionality, implement the actual integration.
"""

from typing import Optional, List
from dataclasses import dataclass
from datetime import datetime
from sentyr.logger import get_logger

logger = get_logger(__name__)


@dataclass
class URLScanResult:
    """URLScan.io scan result"""
    url: str
    verdict: str = "unknown"
    is_phishing: bool = False
    screenshot_url: Optional[str] = None
    brands_detected: List[str] = None
    technologies: List[str] = None
    redirects: List[str] = None
    http_transactions: int = 0
    resources_loaded: int = 0
    malicious_indicators: List[str] = None
    scan_id: Optional[str] = None
    scan_time: Optional[datetime] = None

    def __post_init__(self):
        if self.brands_detected is None:
            self.brands_detected = []
        if self.technologies is None:
            self.technologies = []
        if self.redirects is None:
            self.redirects = []
        if self.malicious_indicators is None:
            self.malicious_indicators = []


class URLScanIntegration:
    """
    URLScan.io integration stub.
    
    This is a minimal implementation that returns empty results.
    To enable full functionality, implement actual URLScan.io API calls.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 30,
        max_wait_seconds: int = 60
    ):
        self.api_key = api_key
        self.timeout = timeout
        self.max_wait_seconds = max_wait_seconds
        
        if not api_key:
            logger.warning("URLScan.io API key not provided - integration disabled")
        else:
            logger.info("URLScan.io integration initialized (stub)")

    async def scan_url(self, url: str) -> Optional[URLScanResult]:
        """
        Scan a URL with URLScan.io (stub implementation).
        
        Args:
            url: URL to scan
            
        Returns:
            URLScanResult or None if API key not configured
        """
        if not self.api_key:
            logger.debug(f"URLScan.io scan skipped for {url} - no API key")
            return None
        
        # Stub: Return empty result
        logger.debug(f"URLScan.io stub: would scan {url}")
        return URLScanResult(
            url=url,
            verdict="unknown",
            scan_time=datetime.utcnow()
        )

    async def get_result(self, scan_id: str) -> Optional[URLScanResult]:
        """Get scan result by ID (stub)"""
        if not self.api_key:
            return None
        
        logger.debug(f"URLScan.io stub: would get result for {scan_id}")
        return None

