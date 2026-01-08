"""
Utility functions for SQL injection scanning.
"""
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Tuple


class URLBuilder:
    """Build and manage URLs for injection."""
    
    @staticmethod
    def inject_parameter(url: str, param: str, payload: str, method: str = 'GET') -> Tuple[str, Dict]:
        """
        Inject payload into URL parameter.
        
        Returns:
            Tuple of (url, data_dict) for GET and POST requests
        """
        parsed = urlparse(url)
        
        if method.upper() == 'GET':
            # Parse query string
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Flatten single-value lists
            params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
            
            # Inject payload
            params[param] = payload
            
            # Rebuild URL
            new_query = urlencode(params, doseq=True)
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            return new_url, {}
        else:
            return url, {param: payload}


class ResponseAnalyzer:
    """Analyze HTTP responses for SQL injection indicators."""
    
    @staticmethod
    def extract_data(response_text: str, delimiter: str = ':') -> List[str]:
        """Extract data from response using delimiter."""
        # Simple extraction - look for delimiter-separated values
        lines = response_text.split('\n')
        data = []
        
        for line in lines:
            if delimiter in line:
                parts = line.split(delimiter)
                data.extend(parts)
        
        return [d.strip() for d in data if d.strip()]
    
    @staticmethod
    def detect_error(response_text: str) -> Optional[str]:
        """Detect SQL error in response."""
        error_patterns = [
            r"SQL syntax",
            r"mysql_fetch",
            r"Warning.*mysql",
            r"Unclosed quotation",
            r"quoted string",
            r"syntax error",
            r"database error",
            r"ODBC",
            r"OLE DB",
            r"Oracle error",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        
        return None
    
    @staticmethod
    def is_vulnerable(response_text: str, test_string: str) -> bool:
        """Check if response contains test string (indicating vulnerability)."""
        return test_string in response_text


class PayloadTester:
    """Test payloads and detect vulnerability."""
    
    @staticmethod
    def test_time_based(response_time: float, threshold: float = 5.0) -> bool:
        """Test if response time indicates time-based SQLi."""
        return response_time > threshold
    
    @staticmethod
    def detect_dbms(response_text: str, version_string: str) -> Optional[str]:
        """Detect DBMS type from version string."""
        if 'mysql' in version_string.lower():
            return 'MySQL'
        elif 'mariadb' in version_string.lower():
            return 'MariaDB'
        elif 'postgresql' in version_string.lower():
            return 'PostgreSQL'
        elif 'microsoft' in version_string.lower() or 'mssql' in version_string.lower():
            return 'MSSQL'
        else:
            return 'Unknown'


class RateLimiter:
    """Rate limiting for requests."""
    
    def __init__(self, requests_per_second: float = 1.0):
        """Initialize rate limiter."""
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
    
    def wait(self):
        """Wait if necessary to maintain rate limit."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()


class WAFDetector:
    """Detect WAF/IPS responses."""
    
    WAF_SIGNATURES = {
        'ModSecurity': [r'403 Forbidden', r'mod_security'],
        'Cloudflare': [r'1020', r'Ray ID'],
        'AWS WAF': [r'400 Bad Request', r'AWS WAF'],
        'Imperva': [r'403 Forbidden', r'Imperva'],
    }
    
    @staticmethod
    def detect(response_text: str, status_code: int) -> Optional[str]:
        """Detect WAF from response."""
        for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
            for sig in signatures:
                if re.search(sig, response_text, re.IGNORECASE):
                    return waf_name
        
        # Check status codes
        if status_code == 403:
            return 'Unknown WAF (403 Forbidden)'
        elif status_code == 406:
            return 'Unknown WAF (406 Not Acceptable)'
        
        return None
