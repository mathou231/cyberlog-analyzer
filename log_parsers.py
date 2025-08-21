"""
Log Parsers pour différents formats de logs de sécurité
"""
import pandas as pd
import re
from datetime import datetime
from typing import Dict, List, Optional
import ipaddress

class LogParser:
    """Classe de base pour tous les parseurs de logs"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'sql_injection': [
                r'(union.*select)', r'(select.*from)', r'(\bor\b.*=.*)',
                r'(drop.*table)', r'(insert.*into)', r'(update.*set)'
            ],
            'xss': [
                r'(<script)', r'(javascript:)', r'(onerror=)', r'(onload=)'
            ],
            'brute_force': [
                r'(admin)', r'(administrator)', r'(root)', r'(test)'
            ],
            'directory_traversal': [
                r'(\.\./)', r'(\.\.\\)', r'(/etc/passwd)', r'(/windows/system32)'
            ]
        }
    
    def parse(self, log_content: str) -> pd.DataFrame:
        """Méthode abstraite à implémenter par chaque parseur"""
        raise NotImplementedError
    
    def detect_threats(self, df: pd.DataFrame) -> pd.DataFrame:
        """Détecte les menaces dans les logs parsés"""
        df['threat_type'] = 'normal'
        df['threat_score'] = 0
        
        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                mask = df['raw_log'].str.contains(pattern, case=False, na=False, regex=True)
                df.loc[mask, 'threat_type'] = threat_type
                df.loc[mask, 'threat_score'] += 1
        
        return df

class ApacheLogParser(LogParser):
    """Parseur pour logs Apache/Nginx"""
    
    def __init__(self):
        super().__init__()
        # Format Apache Common Log
        self.apache_pattern = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
    
    def parse(self, log_content: str) -> pd.DataFrame:
        """Parse les logs Apache/Nginx"""
        lines = log_content.strip().split('\n')
        parsed_logs = []
        
        for line in lines:
            if not line.strip():
                continue
                
            match = re.match(self.apache_pattern, line)
            if match:
                ip, timestamp_str, method, url, protocol, status, size, referer, user_agent = match.groups()
                
                try:
                    timestamp = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                except:
                    timestamp = datetime.now()
                
                parsed_logs.append({
                    'timestamp': timestamp,
                    'ip_address': ip,
                    'method': method,
                    'url': url,
                    'status_code': int(status),
                    'response_size': int(size) if size != '-' else 0,
                    'user_agent': user_agent,
                    'referer': referer,
                    'raw_log': line
                })
        
        df = pd.DataFrame(parsed_logs)
        if not df.empty:
            df = self.detect_threats(df)
            df = self.add_geo_info(df)
        
        return df
    
    def add_geo_info(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ajoute des informations géographiques basiques"""
        # Simulation géographique simple pour la démo
        geo_mapping = {
            '192.168.': 'Internal',
            '10.': 'Internal', 
            '172.16.': 'Internal',
            '127.': 'Localhost'
        }
        
        df['geo_location'] = 'Unknown'
        df['is_internal'] = False
        
        for ip_prefix, location in geo_mapping.items():
            mask = df['ip_address'].str.startswith(ip_prefix)
            df.loc[mask, 'geo_location'] = location
            df.loc[mask, 'is_internal'] = True
        
        # IPs externes = potentiellement suspectes
        external_mask = ~df['is_internal']
        df.loc[external_mask, 'geo_location'] = 'External'
        
        return df

class WindowsEventLogParser(LogParser):
    """Parseur pour Windows Event Logs"""
    
    def parse(self, log_content: str) -> pd.DataFrame:
        """Parse les logs Windows Event (format simplifié)"""
        lines = log_content.strip().split('\n')
        parsed_logs = []
        
        for line in lines:
            if not line.strip():
                continue
            
            # Pattern simplifié pour Event Log Windows
            parts = line.split('\t') if '\t' in line else line.split(',')
            
            if len(parts) >= 4:
                try:
                    timestamp = datetime.strptime(parts[0].strip(), '%Y-%m-%d %H:%M:%S')
                    event_id = parts[1].strip()
                    level = parts[2].strip()
                    description = ' '.join(parts[3:])
                    
                    parsed_logs.append({
                        'timestamp': timestamp,
                        'event_id': event_id,
                        'level': level,
                        'description': description,
                        'raw_log': line
                    })
                except:
                    # Si parsing échoue, garde quand même la ligne
                    parsed_logs.append({
                        'timestamp': datetime.now(),
                        'event_id': 'Unknown',
                        'level': 'Unknown',
                        'description': line,
                        'raw_log': line
                    })
        
        df = pd.DataFrame(parsed_logs)
        if not df.empty:
            df = self.detect_threats(df)
        
        return df

class GenericLogParser(LogParser):
    """Parseur générique pour logs non structurés"""
    
    def parse(self, log_content: str) -> pd.DataFrame:
        """Parse générique basé sur les patterns de menaces"""
        lines = log_content.strip().split('\n')
        parsed_logs = []
        
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            
            # Extraction basique timestamp si présent
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if timestamp_match:
                try:
                    timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S')
                except:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            # Extraction IP si présente
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            ip_address = ip_match.group(1) if ip_match else 'Unknown'
            
            parsed_logs.append({
                'timestamp': timestamp,
                'line_number': i + 1,
                'ip_address': ip_address,
                'content': line,
                'raw_log': line
            })
        
        df = pd.DataFrame(parsed_logs)
        if not df.empty:
            df = self.detect_threats(df)
        
        return df

def get_parser(log_type: str) -> LogParser:
    """Factory pour obtenir le bon parseur selon le type de log"""
    parsers = {
        'apache': ApacheLogParser(),
        'nginx': ApacheLogParser(),  # Même format qu'Apache
        'windows': WindowsEventLogParser(),
        'generic': GenericLogParser()
    }
    
    return parsers.get(log_type, GenericLogParser())

def parse_logs(log_content: str, log_type: str = 'generic') -> pd.DataFrame:
    """Fonction principale pour parser les logs"""
    parser = get_parser(log_type)
    return parser.parse(log_content)