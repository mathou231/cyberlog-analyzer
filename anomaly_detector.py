"""
Détecteur d'anomalies ML pour l'analyse de logs de sécurité
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import Dict, List, Tuple
from datetime import datetime, timedelta
import re

class AnomalyDetector:
    """Détecteur d'anomalies utilisant Machine Learning"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        self.is_fitted = False
    
    def extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extrait les features numériques pour le ML"""
        features = []
        
        # Features temporelles
        if 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
            features.extend(['hour', 'day_of_week'])
        
        # Features spécifiques aux logs web
        if 'status_code' in df.columns:
            features.append('status_code')
        
        if 'response_size' in df.columns:
            # Log du size pour normaliser
            df['log_response_size'] = np.log1p(df['response_size'])
            features.append('log_response_size')
        
        # Features de threat scoring
        if 'threat_score' in df.columns:
            features.append('threat_score')
        
        # Frequency features par IP
        if 'ip_address' in df.columns:
            ip_counts = df['ip_address'].value_counts()
            df['ip_frequency'] = df['ip_address'].map(ip_counts)
            df['log_ip_frequency'] = np.log1p(df['ip_frequency'])
            features.append('log_ip_frequency')
        
        # Features URL/path length (pour logs web)
        if 'url' in df.columns:
            df['url_length'] = df['url'].str.len()
            df['url_param_count'] = df['url'].str.count('&')
            features.extend(['url_length', 'url_param_count'])
        
        # Assure que toutes les features existent
        for feature in features:
            if feature not in df.columns:
                df[feature] = 0
        
        return df[features].fillna(0).values
    
    def detect_time_anomalies(self, df: pd.DataFrame) -> List[Dict]:
        """Détecte les anomalies temporelles"""
        if 'timestamp' not in df.columns:
            return []
        
        anomalies = []
        df_time = df.copy()
        df_time['timestamp'] = pd.to_datetime(df_time['timestamp'])
        df_time['hour'] = df_time['timestamp'].dt.hour
        
        # Activité en heures inhabituelles (2h-6h du matin)
        night_activity = df_time[(df_time['hour'] >= 2) & (df_time['hour'] <= 6)]
        if len(night_activity) > 0:
            anomalies.append({
                'type': 'Unusual Night Activity',
                'count': len(night_activity),
                'severity': 'Medium',
                'description': f'{len(night_activity)} events detected during night hours (2-6 AM)',
                'ips': night_activity['ip_address'].unique().tolist() if 'ip_address' in night_activity else []
            })
        
        # Burst d'activité (beaucoup d'events en peu de temps)
        df_time['minute'] = df_time['timestamp'].dt.floor('min')
        minute_counts = df_time.groupby('minute').size()
        high_activity = minute_counts[minute_counts > minute_counts.quantile(0.95)]
        
        if len(high_activity) > 0:
            anomalies.append({
                'type': 'Activity Burst',
                'count': len(high_activity),
                'severity': 'High',
                'description': f'High activity detected: {high_activity.max()} events in single minute',
                'timestamps': high_activity.index.tolist()
            })
        
        return anomalies
    
    def detect_ip_anomalies(self, df: pd.DataFrame) -> List[Dict]:
        """Détecte les anomalies liées aux adresses IP"""
        if 'ip_address' not in df.columns:
            return []
        
        anomalies = []
        
        # IPs avec beaucoup de requêtes (potential DDoS/brute force)
        ip_counts = df['ip_address'].value_counts()
        threshold = ip_counts.quantile(0.95)
        suspicious_ips = ip_counts[ip_counts > threshold]
        
        if len(suspicious_ips) > 0:
            for ip, count in suspicious_ips.items():
                # Analyse du comportement de cette IP
                ip_data = df[df['ip_address'] == ip]
                
                # Check for different threat indicators
                severity = 'Low'
                if count > ip_counts.quantile(0.99):
                    severity = 'Critical'
                elif count > ip_counts.quantile(0.97):
                    severity = 'High'
                elif count > ip_counts.quantile(0.95):
                    severity = 'Medium'
                
                threat_types = []
                if 'threat_type' in ip_data.columns:
                    threats = ip_data[ip_data['threat_type'] != 'normal']['threat_type'].unique()
                    threat_types = threats.tolist()
                
                anomalies.append({
                    'type': 'Suspicious IP Activity',
                    'ip': ip,
                    'count': int(count),
                    'severity': severity,
                    'description': f'IP {ip} generated {count} events',
                    'threat_types': threat_types,
                    'time_span': f"{ip_data['timestamp'].min()} to {ip_data['timestamp'].max()}" if 'timestamp' in ip_data else 'Unknown'
                })
        
        return anomalies
    
    def detect_pattern_anomalies(self, df: pd.DataFrame) -> List[Dict]:
        """Détecte les anomalies basées sur les patterns de contenu"""
        anomalies = []
        
        # Requêtes avec des patterns suspects
        if 'threat_score' in df.columns:
            high_threat = df[df['threat_score'] > 0]
            
            if len(high_threat) > 0:
                threat_summary = high_threat['threat_type'].value_counts()
                
                for threat_type, count in threat_summary.items():
                    if threat_type == 'normal':
                        continue
                    
                    severity = 'Medium'
                    if count > 10:
                        severity = 'High'
                    elif count > 50:
                        severity = 'Critical'
                    
                    affected_ips = high_threat[high_threat['threat_type'] == threat_type]['ip_address'].unique()
                    
                    anomalies.append({
                        'type': f'{threat_type.title()} Attack Pattern',
                        'count': int(count),
                        'severity': severity,
                        'description': f'{count} {threat_type} attempts detected',
                        'affected_ips': affected_ips.tolist() if 'ip_address' in high_threat else [],
                        'pattern': threat_type
                    })
        
        return anomalies
    
    def fit_and_predict(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict]]:
        """Effectue la détection d'anomalies complète"""
        if df.empty:
            return df, []
        
        # Extraction des features
        try:
            features = self.extract_features(df.copy())
            
            if features.shape[1] > 0:
                # Normalisation et détection
                features_scaled = self.scaler.fit_transform(features)
                anomaly_scores = self.isolation_forest.fit_predict(features_scaled)
                
                # Ajoute les scores au DataFrame
                df = df.copy()
                df['anomaly_score'] = anomaly_scores
                df['is_anomaly'] = anomaly_scores == -1
            else:
                df['anomaly_score'] = 1
                df['is_anomaly'] = False
                
        except Exception as e:
            print(f"Erreur dans la détection ML: {e}")
            df['anomaly_score'] = 1
            df['is_anomaly'] = False
        
        # Détections spécialisées
        anomalies = []
        anomalies.extend(self.detect_time_anomalies(df))
        anomalies.extend(self.detect_ip_anomalies(df))
        anomalies.extend(self.detect_pattern_anomalies(df))
        
        return df, anomalies
    
    def get_summary_stats(self, df: pd.DataFrame, anomalies: List[Dict]) -> Dict:
        """Génère des statistiques résumées"""
        stats = {
            'total_events': len(df),
            'anomalous_events': len(df[df.get('is_anomaly', False) == True]) if 'is_anomaly' in df.columns else 0,
            'unique_ips': len(df['ip_address'].unique()) if 'ip_address' in df.columns else 0,
            'threat_events': len(df[df.get('threat_score', 0) > 0]) if 'threat_score' in df.columns else 0,
            'time_span': None,
            'top_threats': [],
            'critical_anomalies': len([a for a in anomalies if a.get('severity') == 'Critical']),
            'high_anomalies': len([a for a in anomalies if a.get('severity') == 'High']),
            'medium_anomalies': len([a for a in anomalies if a.get('severity') == 'Medium'])
        }
        
        if 'timestamp' in df.columns and not df.empty:
            stats['time_span'] = {
                'start': df['timestamp'].min(),
                'end': df['timestamp'].max(),
                'duration': str(pd.to_datetime(df['timestamp'].max()) - pd.to_datetime(df['timestamp'].min()))
            }
        
        if 'threat_type' in df.columns:
            threat_counts = df[df['threat_type'] != 'normal']['threat_type'].value_counts()
            stats['top_threats'] = [{'type': t, 'count': int(c)} for t, c in threat_counts.head().items()]
        
        return stats

def analyze_logs(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict], Dict]:
    """Fonction principale d'analyse des logs"""
    detector = AnomalyDetector()
    analyzed_df, anomalies = detector.fit_and_predict(df)
    stats = detector.get_summary_stats(analyzed_df, anomalies)
    
    return analyzed_df, anomalies, stats