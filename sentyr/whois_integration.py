"""
WHOIS Integration - Stub Implementation

This is a minimal stub to maintain compatibility with the security analyst agent.
For full WHOIS functionality, implement the actual integration.
"""

from typing import Optional, List
from dataclasses import dataclass
from datetime import datetime
from sentyr.logger import get_logger

logger = get_logger(__name__)


@dataclass
class WHOISResult:
    """WHOIS lookup result"""
    domain: str
    age_days: Optional[int] = None
    is_recently_registered: bool = False
    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = None
    risk_indicators: List[str] = None
    raw_whois: Optional[str] = None

    def __post_init__(self):
        if self.name_servers is None:
            self.name_servers = []
        if self.risk_indicators is None:
            self.risk_indicators = []


class WHOISIntegration:
    """
    WHOIS integration stub.
    
    This is a minimal implementation that returns empty results.
    To enable full functionality, implement actual WHOIS lookups.
    """

    def __init__(
        self,
        timeout: int = 10,
        recently_registered_threshold_days: int = 30
    ):
        self.timeout = timeout
        self.recently_registered_threshold_days = recently_registered_threshold_days
        logger.info("WHOIS integration initialized (stub)")

    async def lookup(self, domain: str) -> Optional[WHOISResult]:
        """
        Perform WHOIS lookup for a domain (stub implementation).
        
        Args:
            domain: Domain to lookup
            
        Returns:
            WHOISResult or None
        """
        logger.debug(f"WHOIS stub: would lookup {domain}")
        
        # Stub: Return empty result
        return WHOISResult(
            domain=domain,
            age_days=None,
            is_recently_registered=False
        )

    def is_recently_registered(self, registration_date: datetime) -> bool:
        """Check if domain was recently registered"""
        if not registration_date:
            return False
        
        age_days = (datetime.utcnow() - registration_date).days
        return age_days <= self.recently_registered_threshold_days

