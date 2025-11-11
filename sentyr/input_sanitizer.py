"""Input sanitization utilities for preventing injection attacks.

Provides comprehensive input sanitization for:
- SQL injection prevention
- NoSQL injection prevention
- Command injection prevention
- XSS prevention
- Path traversal prevention
- Query language injection prevention (Splunk, Datadog, etc.)
"""

import re
from typing import Optional, List, Set
from urllib.parse import urlparse, quote
from sentyr.logger import get_logger

logger = get_logger(__name__)


class InputSanitizer:
    """Comprehensive input sanitization for security."""

    # Dangerous characters for various injection types
    SQL_DANGEROUS_CHARS = r"[';\"\\--/*]"
    NOSQL_DANGEROUS_CHARS = r"[${}]"
    COMMAND_DANGEROUS_CHARS = r"[;&|`$(){}[\]<>\\]"
    PATH_TRAVERSAL_PATTERN = r"\.\./|\.\.\\|\.\."
    XSS_DANGEROUS_CHARS = r"[<>\"'&]"

    # Allowed character sets for different types
    ALPHANUMERIC = re.compile(r'^[a-zA-Z0-9_\-]+$')
    IP_ADDRESS = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    DOMAIN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    EMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    HASH_MD5 = re.compile(r'^[a-fA-F0-9]{32}$')
    HASH_SHA256 = re.compile(r'^[a-fA-F0-9]{64}$')

    # Query language reserved words to escape
    SPLUNK_RESERVED = {'OR', 'AND', 'NOT', 'IN', 'AS', 'BY', 'WHERE', 'EVAL', 'SEARCH'}
    DATADOG_RESERVED = {'AND', 'OR', 'NOT', 'IN', 'EXISTS'}

    def __init__(self):
        """Initialize input sanitizer."""
        logger.info("Input sanitizer initialized")

    def sanitize_for_sql(self, value: str, max_length: int = 255) -> str:
        """
        Sanitize input for SQL queries.

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string safe for SQL

        Raises:
            ValueError: If input contains dangerous characters
        """
        if not value:
            return ""

        # Truncate to max length
        value = value[:max_length]

        # Check for dangerous characters
        if re.search(self.SQL_DANGEROUS_CHARS, value):
            logger.warning(f"SQL injection attempt detected in: {value[:50]}")
            # Remove dangerous characters
            value = re.sub(self.SQL_DANGEROUS_CHARS, '', value)

        # Escape single quotes (most common SQL escape)
        value = value.replace("'", "''")

        return value

    def sanitize_for_nosql(self, value: str, max_length: int = 255) -> str:
        """
        Sanitize input for NoSQL queries (MongoDB, etc.).

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string safe for NoSQL
        """
        if not value:
            return ""

        value = value[:max_length]

        # Check for NoSQL injection patterns
        if re.search(self.NOSQL_DANGEROUS_CHARS, value):
            logger.warning(f"NoSQL injection attempt detected in: {value[:50]}")
            value = re.sub(self.NOSQL_DANGEROUS_CHARS, '', value)

        return value

    def sanitize_for_command(self, value: str, max_length: int = 255) -> str:
        """
        Sanitize input for shell commands.

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string safe for commands

        Raises:
            ValueError: If input contains dangerous characters
        """
        if not value:
            return ""

        value = value[:max_length]

        # Check for command injection
        if re.search(self.COMMAND_DANGEROUS_CHARS, value):
            logger.warning(f"Command injection attempt detected in: {value[:50]}")
            # For commands, we're very strict - only allow alphanumeric and safe chars
            value = re.sub(r'[^a-zA-Z0-9_\-\.]', '', value)

        return value

    def sanitize_path(self, path: str, max_length: int = 255) -> str:
        """
        Sanitize file paths to prevent path traversal attacks.

        Args:
            path: File path to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized path

        Raises:
            ValueError: If path contains traversal attempts
        """
        if not path:
            return ""

        path = path[:max_length]

        # Detect path traversal
        if re.search(self.PATH_TRAVERSAL_PATTERN, path):
            logger.warning(f"Path traversal attempt detected in: {path}")
            raise ValueError("Path traversal detected")

        # Remove any null bytes
        path = path.replace('\0', '')

        # Normalize path separators
        path = path.replace('\\', '/')

        # Remove leading/trailing whitespace
        path = path.strip()

        return path

    def sanitize_for_xss(self, value: str, max_length: int = 1000) -> str:
        """
        Sanitize input to prevent XSS attacks.

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            HTML-safe string
        """
        if not value:
            return ""

        value = value[:max_length]

        # HTML entity encoding
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#x27;')

        return value

    def sanitize_for_splunk(self, value: str, max_length: int = 500) -> str:
        """
        Sanitize input for Splunk queries.

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string safe for Splunk queries
        """
        if not value:
            return ""

        value = value[:max_length]

        # Escape special characters
        value = value.replace('\\', '\\\\')
        value = value.replace('"', '\\"')
        value = value.replace('*', '\\*')
        value = value.replace('?', '\\?')

        # Wrap in quotes to prevent injection
        return f'"{value}"'

    def sanitize_for_datadog(self, value: str, max_length: int = 500) -> str:
        """
        Sanitize input for Datadog queries.

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string safe for Datadog queries
        """
        if not value:
            return ""

        value = value[:max_length]

        # Escape special characters in Datadog query syntax
        value = value.replace('\\', '\\\\')
        value = value.replace('"', '\\"')
        value = value.replace('*', '\\*')
        value = value.replace(':', '\\:')

        # Wrap in quotes
        return f'"{value}"'

    def sanitize_ip_address(self, ip: str) -> Optional[str]:
        """
        Validate and sanitize IP address.

        Args:
            ip: IP address string

        Returns:
            Sanitized IP or None if invalid
        """
        if not ip:
            return None

        # Remove whitespace
        ip = ip.strip()

        # Validate IPv4 format
        if self.IP_ADDRESS.match(ip):
            # Validate octets are 0-255
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return ip

        logger.warning(f"Invalid IP address: {ip}")
        return None

    def sanitize_domain(self, domain: str) -> Optional[str]:
        """
        Validate and sanitize domain name.

        Args:
            domain: Domain name string

        Returns:
            Sanitized domain or None if invalid
        """
        if not domain:
            return None

        # Remove whitespace and convert to lowercase
        domain = domain.strip().lower()

        # Validate domain format
        if self.DOMAIN.match(domain) and len(domain) <= 253:
            return domain

        logger.warning(f"Invalid domain: {domain}")
        return None

    def sanitize_email(self, email: str) -> Optional[str]:
        """
        Validate and sanitize email address.

        Args:
            email: Email address string

        Returns:
            Sanitized email or None if invalid
        """
        if not email:
            return None

        # Remove whitespace and convert to lowercase
        email = email.strip().lower()

        # Validate email format
        if self.EMAIL.match(email) and len(email) <= 254:
            return email

        logger.warning(f"Invalid email: {email}")
        return None

    def sanitize_hash(self, hash_value: str) -> Optional[str]:
        """
        Validate and sanitize hash value (MD5 or SHA256).

        Args:
            hash_value: Hash string

        Returns:
            Sanitized hash or None if invalid
        """
        if not hash_value:
            return None

        # Remove whitespace and convert to lowercase
        hash_value = hash_value.strip().lower()

        # Validate hash format
        if self.HASH_MD5.match(hash_value) or self.HASH_SHA256.match(hash_value):
            return hash_value

        logger.warning(f"Invalid hash format: {hash_value[:20]}")
        return None

    def sanitize_url(self, url: str, max_length: int = 2048) -> Optional[str]:
        """
        Validate and sanitize URL.

        Args:
            url: URL string
            max_length: Maximum allowed length

        Returns:
            Sanitized URL or None if invalid
        """
        if not url:
            return None

        # Truncate to max length
        url = url.strip()[:max_length]

        try:
            # Parse URL to validate structure
            parsed = urlparse(url)

            # Require scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                logger.warning(f"Invalid URL structure: {url[:50]}")
                return None

            # Only allow http/https schemes
            if parsed.scheme not in ['http', 'https']:
                logger.warning(f"Invalid URL scheme: {parsed.scheme}")
                return None

            # Validate domain part
            domain = parsed.netloc.split(':')[0]  # Remove port if present
            if not self.sanitize_domain(domain):
                return None

            return url

        except Exception as e:
            logger.warning(f"URL validation error: {e}")
            return None

    def sanitize_alphanumeric(self, value: str, max_length: int = 255, allow_dash: bool = True, allow_underscore: bool = True) -> str:
        """
        Sanitize to only alphanumeric characters (and optionally dash/underscore).

        Args:
            value: Input string
            max_length: Maximum allowed length
            allow_dash: Allow dash character
            allow_underscore: Allow underscore character

        Returns:
            Sanitized alphanumeric string
        """
        if not value:
            return ""

        value = value[:max_length]

        # Build allowed pattern
        pattern = r'[^a-zA-Z0-9'
        if allow_dash:
            pattern += r'\-'
        if allow_underscore:
            pattern += r'_'
        pattern += r']'

        # Remove disallowed characters
        sanitized = re.sub(pattern, '', value)

        return sanitized

    def validate_and_sanitize_ioc(self, value: str, ioc_type: str) -> Optional[str]:
        """
        Validate and sanitize IOC based on type.

        Args:
            value: IOC value
            ioc_type: Type of IOC (ip, domain, url, email, hash)

        Returns:
            Sanitized IOC or None if invalid
        """
        ioc_type = ioc_type.lower()

        if ioc_type == "ip":
            return self.sanitize_ip_address(value)
        elif ioc_type == "domain":
            return self.sanitize_domain(value)
        elif ioc_type == "url":
            return self.sanitize_url(value)
        elif ioc_type == "email":
            return self.sanitize_email(value)
        elif ioc_type == "hash":
            return self.sanitize_hash(value)
        elif ioc_type in ["user", "username"]:
            return self.sanitize_alphanumeric(value, allow_dash=True, allow_underscore=True)
        else:
            # Default: conservative sanitization
            return self.sanitize_alphanumeric(value)


# Global sanitizer instance
_sanitizer = None


def get_sanitizer() -> InputSanitizer:
    """Get global sanitizer instance."""
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = InputSanitizer()
    return _sanitizer
