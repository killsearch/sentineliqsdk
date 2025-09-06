# Monitoramento de Rede

Este exemplo demonstra como criar analisadores para monitoramento de rede usando o SentinelIQ SDK, incluindo detecção de tráfego suspeito, análise de logs de firewall e correlação de eventos.

## Analisador de Tráfego de Rede

### Detecção de Anomalias de Tráfego

```python
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sentineliqsdk import Analyzer, WorkerInput

class NetworkTrafficAnalyzer(Analyzer):
    """Analisador de tráfego de rede para detecção de anomalias."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.thresholds = {
            "high_bandwidth": self.get_param("high_bandwidth_threshold", 1000),  # MB/s
            "unusual_ports": self.get_param("unusual_ports_threshold", 5),
            "geo_anomaly": self.get_param("geo_anomaly_threshold", 0.8)
        }
    
    def run(self) -> None:
        traffic_data = self.get_data()
        
        # Validar formato dos dados
        if not self._validate_traffic_data(traffic_data):
            self.error("Dados de tráfego inválidos")
        
        # Analisar tráfego
        analysis_result = self._analyze_traffic(traffic_data)
        
        # Gerar relatório
        self.report({
            "timestamp": datetime.now().isoformat(),
            "source_ip": traffic_data.get("source_ip"),
            "destination_ip": traffic_data.get("destination_ip"),
            "analysis": analysis_result,
            "recommendations": self._generate_recommendations(analysis_result)
        })
    
    def _validate_traffic_data(self, data: Dict[str, Any]) -> bool:
        """Valida se os dados de tráfego estão no formato correto."""
        required_fields = ["source_ip", "destination_ip", "bytes_transferred", "timestamp"]
        return all(field in data for field in required_fields)
    
    def _analyze_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa o tráfego de rede em busca de anomalias."""
        anomalies = []
        risk_score = 0
        
        # Análise de largura de banda
        bandwidth_anomaly = self._check_bandwidth_anomaly(traffic_data)
        if bandwidth_anomaly:
            anomalies.append(bandwidth_anomaly)
            risk_score += 30
        
        # Análise de portas
        port_anomaly = self._check_port_anomaly(traffic_data)
        if port_anomaly:
            anomalies.append(port_anomaly)
            risk_score += 25
        
        # Análise geográfica
        geo_anomaly = self._check_geo_anomaly(traffic_data)
        if geo_anomaly:
            anomalies.append(geo_anomaly)
            risk_score += 35
        
        # Análise de protocolo
        protocol_anomaly = self._check_protocol_anomaly(traffic_data)
        if protocol_anomaly:
            anomalies.append(protocol_anomaly)
            risk_score += 20
        
        # Análise de timing
        timing_anomaly = self._check_timing_anomaly(traffic_data)
        if timing_anomaly:
            anomalies.append(timing_anomaly)
            risk_score += 15
        
        return {
            "anomalies": anomalies,
            "risk_score": min(risk_score, 100),
            "verdict": self._determine_verdict(risk_score),
            "confidence": self._calculate_confidence(anomalies)
        }
    
    def _check_bandwidth_anomaly(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verifica anomalias de largura de banda."""
        bytes_transferred = traffic_data.get("bytes_transferred", 0)
        duration = traffic_data.get("duration_seconds", 1)
        
        if duration > 0:
            bandwidth_mbps = (bytes_transferred * 8) / (duration * 1024 * 1024)
            
            if bandwidth_mbps > self.thresholds["high_bandwidth"]:
                return {
                    "type": "high_bandwidth",
                    "severity": "high",
                    "description": f"Largura de banda anormalmente alta: {bandwidth_mbps:.2f} Mbps",
                    "value": bandwidth_mbps,
                    "threshold": self.thresholds["high_bandwidth"]
                }
        
        return None
    
    def _check_port_anomaly(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verifica anomalias de portas."""
        destination_port = traffic_data.get("destination_port")
        
        # Lista de portas suspeitas
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 5900]
        
        if destination_port in suspicious_ports:
            return {
                "type": "suspicious_port",
                "severity": "medium",
                "description": f"Porta suspeita detectada: {destination_port}",
                "port": destination_port,
                "reason": "Porta comumente usada para ataques"
            }
        
        # Verificar portas não padrão
        if destination_port and (destination_port < 1024 or destination_port > 65535):
            return {
                "type": "unusual_port",
                "severity": "low",
                "description": f"Porta não padrão: {destination_port}",
                "port": destination_port
            }
        
        return None
    
    def _check_geo_anomaly(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verifica anomalias geográficas."""
        source_country = traffic_data.get("source_country")
        destination_country = traffic_data.get("destination_country")
        
        # Lista de países de alto risco
        high_risk_countries = ["CN", "RU", "KP", "IR", "SY"]
        
        if source_country in high_risk_countries:
            return {
                "type": "geo_anomaly",
                "severity": "high",
                "description": f"Tráfego originado de país de alto risco: {source_country}",
                "country": source_country,
                "risk_level": "high"
            }
        
        # Verificar tráfego internacional suspeito
        if source_country != destination_country:
            return {
                "type": "international_traffic",
                "severity": "medium",
                "description": f"Tráfego internacional: {source_country} -> {destination_country}",
                "source_country": source_country,
                "destination_country": destination_country
            }
        
        return None
    
    def _check_protocol_anomaly(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verifica anomalias de protocolo."""
        protocol = traffic_data.get("protocol", "").upper()
        
        # Protocolos suspeitos
        suspicious_protocols = ["ICMP", "UDP"]
        
        if protocol in suspicious_protocols:
            return {
                "type": "suspicious_protocol",
                "severity": "medium",
                "description": f"Protocolo suspeito detectado: {protocol}",
                "protocol": protocol,
                "reason": "Protocolo comumente usado para ataques"
            }
        
        return None
    
    def _check_timing_anomaly(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verifica anomalias de timing."""
        timestamp = traffic_data.get("timestamp")
        
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.hour
                
                # Tráfego suspeito fora do horário comercial
                if hour < 6 or hour > 22:
                    return {
                        "type": "timing_anomaly",
                        "severity": "medium",
                        "description": f"Tráfego fora do horário comercial: {hour:02d}:00",
                        "hour": hour,
                        "reason": "Atividade suspeita em horário não comercial"
                    }
            except ValueError:
                pass
        
        return None
    
    def _determine_verdict(self, risk_score: int) -> str:
        """Determina o veredito baseado no score de risco."""
        if risk_score >= 70:
            return "malicious"
        elif risk_score >= 40:
            return "suspicious"
        else:
            return "safe"
    
    def _calculate_confidence(self, anomalies: List[Dict[str, Any]]) -> float:
        """Calcula a confiança baseada no número e severidade das anomalias."""
        if not anomalies:
            return 0.9  # Alta confiança para tráfego normal
        
        high_severity = sum(1 for a in anomalies if a.get("severity") == "high")
        medium_severity = sum(1 for a in anomalies if a.get("severity") == "medium")
        
        confidence = 0.5 + (high_severity * 0.2) + (medium_severity * 0.1)
        return min(confidence, 0.95)
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas na análise."""
        recommendations = []
        anomalies = analysis.get("anomalies", [])
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get("type")
            
            if anomaly_type == "high_bandwidth":
                recommendations.append("Investigar possível DDoS ou exfiltração de dados")
            elif anomaly_type == "suspicious_port":
                recommendations.append("Verificar se o serviço na porta é legítimo")
            elif anomaly_type == "geo_anomaly":
                recommendations.append("Considerar bloqueio geográfico se apropriado")
            elif anomaly_type == "suspicious_protocol":
                recommendations.append("Analisar tráfego do protocolo suspeito")
            elif anomaly_type == "timing_anomaly":
                recommendations.append("Verificar se a atividade é autorizada")
        
        if not recommendations:
            recommendations.append("Tráfego normal, nenhuma ação necessária")
        
        return recommendations

# Exemplo de uso
if __name__ == "__main__":
    traffic_data = {
        "source_ip": "192.168.1.100",
        "destination_ip": "8.8.8.8",
        "source_port": 12345,
        "destination_port": 53,
        "protocol": "UDP",
        "bytes_transferred": 1500000,
        "duration_seconds": 2,
        "timestamp": "2024-01-15T14:30:00Z",
        "source_country": "BR",
        "destination_country": "US"
    }
    
    input_data = {
        "dataType": "network_traffic",
        "data": traffic_data,
        "config": {"auto_extract": True}
    }
    
    analyzer = NetworkTrafficAnalyzer(input_data)
    analyzer.run()
```

## Analisador de Logs de Firewall

### Análise de Regras de Firewall

```python
from __future__ import annotations
import re
from typing import Dict, Any, List, Set
from sentineliqsdk import Analyzer, WorkerInput

class FirewallLogAnalyzer(Analyzer):
    """Analisador de logs de firewall para detecção de ataques."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.attack_patterns = {
            "port_scan": r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+).*?(\d+).*?DENY",
            "brute_force": r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+).*?22.*?DENY",
            "ddos": r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+).*?(\d+).*?DENY.*?(\d+)",
            "malicious_ip": r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+).*?DENY"
        }
        
        self.known_malicious_ips = {
            "1.2.3.4", "5.6.7.8", "9.10.11.12"
        }
    
    def run(self) -> None:
        log_data = self.get_data()
        
        # Analisar logs
        analysis_result = self._analyze_firewall_logs(log_data)
        
        # Gerar relatório
        self.report({
            "log_analysis": analysis_result,
            "threats_detected": len(analysis_result.get("threats", [])),
            "recommendations": self._generate_security_recommendations(analysis_result)
        })
    
    def _analyze_firewall_logs(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa logs de firewall em busca de ameaças."""
        logs = log_data.get("logs", [])
        
        if not logs:
            return {"error": "Nenhum log fornecido"}
        
        threats = []
        statistics = {
            "total_logs": len(logs),
            "blocked_connections": 0,
            "allowed_connections": 0,
            "unique_ips": set(),
            "port_scan_attempts": 0,
            "brute_force_attempts": 0
        }
        
        for log_entry in logs:
            # Atualizar estatísticas
            self._update_statistics(log_entry, statistics)
            
            # Detectar ameaças
            detected_threats = self._detect_threats(log_entry)
            threats.extend(detected_threats)
        
        # Converter set para lista para serialização JSON
        statistics["unique_ips"] = list(statistics["unique_ips"])
        
        return {
            "threats": threats,
            "statistics": statistics,
            "risk_level": self._calculate_risk_level(threats, statistics)
        }
    
    def _update_statistics(self, log_entry: str, stats: Dict[str, Any]) -> None:
        """Atualiza estatísticas dos logs."""
        if "DENY" in log_entry:
            stats["blocked_connections"] += 1
        elif "ALLOW" in log_entry:
            stats["allowed_connections"] += 1
        
        # Extrair IPs
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        ips = re.findall(ip_pattern, log_entry)
        stats["unique_ips"].update(ips)
    
    def _detect_threats(self, log_entry: str) -> List[Dict[str, Any]]:
        """Detecta ameaças em uma entrada de log."""
        threats = []
        
        # Detectar port scan
        port_scan_match = re.search(self.attack_patterns["port_scan"], log_entry)
        if port_scan_match:
            threats.append({
                "type": "port_scan",
                "severity": "high",
                "source_ip": port_scan_match.group(1),
                "target_ip": port_scan_match.group(2),
                "port": port_scan_match.group(3),
                "description": "Tentativa de port scan detectada"
            })
        
        # Detectar brute force SSH
        brute_force_match = re.search(self.attack_patterns["brute_force"], log_entry)
        if brute_force_match:
            threats.append({
                "type": "brute_force_ssh",
                "severity": "high",
                "source_ip": brute_force_match.group(1),
                "target_ip": brute_force_match.group(2),
                "description": "Tentativa de brute force SSH detectada"
            })
        
        # Detectar IPs maliciosos conhecidos
        for malicious_ip in self.known_malicious_ips:
            if malicious_ip in log_entry:
                threats.append({
                    "type": "known_malicious_ip",
                    "severity": "critical",
                    "malicious_ip": malicious_ip,
                    "description": f"IP malicioso conhecido detectado: {malicious_ip}"
                })
        
        # Detectar possível DDoS
        ddos_match = re.search(self.attack_patterns["ddos"], log_entry)
        if ddos_match:
            packet_count = int(ddos_match.group(4)) if ddos_match.group(4) else 0
            if packet_count > 100:  # Threshold para DDoS
                threats.append({
                    "type": "ddos_attempt",
                    "severity": "critical",
                    "source_ip": ddos_match.group(1),
                    "target_ip": ddos_match.group(2),
                    "packet_count": packet_count,
                    "description": "Possível tentativa de DDoS detectada"
                })
        
        return threats
    
    def _calculate_risk_level(self, threats: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
        """Calcula o nível de risco baseado nas ameaças detectadas."""
        if not threats:
            return "low"
        
        critical_threats = sum(1 for t in threats if t.get("severity") == "critical")
        high_threats = sum(1 for t in threats if t.get("severity") == "high")
        
        if critical_threats > 0:
            return "critical"
        elif high_threats > 2:
            return "high"
        elif high_threats > 0 or len(threats) > 5:
            return "medium"
        else:
            return "low"
    
    def _generate_security_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Gera recomendações de segurança baseadas na análise."""
        recommendations = []
        threats = analysis.get("threats", [])
        risk_level = analysis.get("risk_level", "low")
        
        if risk_level == "critical":
            recommendations.append("AÇÃO IMEDIATA: Bloquear IPs maliciosos e investigar incidente")
        
        threat_types = {t.get("type") for t in threats}
        
        if "port_scan" in threat_types:
            recommendations.append("Implementar detecção de port scan em tempo real")
        
        if "brute_force_ssh" in threat_types:
            recommendations.append("Configurar fail2ban ou similar para SSH")
        
        if "ddos_attempt" in threat_types:
            recommendations.append("Ativar proteção DDoS e monitorar largura de banda")
        
        if "known_malicious_ip" in threat_types:
            recommendations.append("Atualizar blacklist de IPs maliciosos")
        
        if not recommendations:
            recommendations.append("Nenhuma ameaça crítica detectada, continuar monitoramento")
        
        return recommendations

# Exemplo de uso
if __name__ == "__main__":
    firewall_logs = {
        "logs": [
            "2024-01-15 14:30:00 192.168.1.100 -> 10.0.0.1:22 DENY",
            "2024-01-15 14:30:01 192.168.1.100 -> 10.0.0.1:23 DENY",
            "2024-01-15 14:30:02 192.168.1.100 -> 10.0.0.1:80 DENY",
            "2024-01-15 14:30:03 1.2.3.4 -> 10.0.0.1:443 DENY",
            "2024-01-15 14:30:04 192.168.1.100 -> 10.0.0.1:22 DENY"
        ]
    }
    
    input_data = {
        "dataType": "firewall_logs",
        "data": firewall_logs,
        "config": {"auto_extract": True}
    }
    
    analyzer = FirewallLogAnalyzer(input_data)
    analyzer.run()
```

## Correlação de Eventos de Rede

### Sistema de Correlação Avançado

```python
from __future__ import annotations
from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from sentineliqsdk import Analyzer, WorkerInput

class NetworkEventCorrelator(Analyzer):
    """Correlaciona eventos de rede para detectar padrões de ataque."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.correlation_window = self.get_param("correlation_window_minutes", 30)
        self.thresholds = {
            "port_scan_threshold": self.get_param("port_scan_threshold", 5),
            "brute_force_threshold": self.get_param("brute_force_threshold", 3),
            "geo_anomaly_threshold": self.get_param("geo_anomaly_threshold", 0.7)
        }
    
    def run(self) -> None:
        events = self.get_data()
        
        # Validar eventos
        if not self._validate_events(events):
            self.error("Formato de eventos inválido")
        
        # Correlacionar eventos
        correlation_result = self._correlate_events(events)
        
        # Gerar relatório
        self.report({
            "correlation_analysis": correlation_result,
            "attack_campaigns": self._identify_attack_campaigns(correlation_result),
            "recommendations": self._generate_correlation_recommendations(correlation_result)
        })
    
    def _validate_events(self, events: Dict[str, Any]) -> bool:
        """Valida se os eventos estão no formato correto."""
        if "events" not in events:
            return False
        
        required_fields = ["timestamp", "source_ip", "event_type"]
        for event in events["events"]:
            if not all(field in event for field in required_fields):
                return False
        
        return True
    
    def _correlate_events(self, events_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlaciona eventos de rede."""
        events = events_data["events"]
        
        # Agrupar eventos por IP de origem
        events_by_ip = defaultdict(list)
        for event in events:
            events_by_ip[event["source_ip"]].append(event)
        
        correlations = []
        
        for source_ip, ip_events in events_by_ip.items():
            # Correlacionar eventos do mesmo IP
            ip_correlations = self._correlate_ip_events(source_ip, ip_events)
            correlations.extend(ip_correlations)
        
        # Correlacionar eventos entre IPs diferentes
        cross_ip_correlations = self._correlate_cross_ip_events(events)
        correlations.extend(cross_ip_correlations)
        
        return {
            "correlations": correlations,
            "total_events": len(events),
            "unique_ips": len(events_by_ip),
            "correlation_score": self._calculate_correlation_score(correlations)
        }
    
    def _correlate_ip_events(self, source_ip: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlaciona eventos do mesmo IP de origem."""
        correlations = []
        
        # Ordenar eventos por timestamp
        sorted_events = sorted(events, key=lambda x: x["timestamp"])
        
        # Detectar port scan
        port_scan = self._detect_port_scan_pattern(sorted_events)
        if port_scan:
            correlations.append(port_scan)
        
        # Detectar brute force
        brute_force = self._detect_brute_force_pattern(sorted_events)
        if brute_force:
            correlations.append(brute_force)
        
        # Detectar lateral movement
        lateral_movement = self._detect_lateral_movement_pattern(sorted_events)
        if lateral_movement:
            correlations.append(lateral_movement)
        
        return correlations
    
    def _detect_port_scan_pattern(self, events: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        """Detecta padrão de port scan."""
        port_events = [e for e in events if e.get("event_type") == "connection_denied"]
        
        if len(port_events) < self.thresholds["port_scan_threshold"]:
            return None
        
        # Agrupar por destino
        target_ips = Counter(e.get("destination_ip") for e in port_events)
        
        # Verificar se há múltiplos destinos
        if len(target_ips) > 1:
            return {
                "type": "port_scan",
                "severity": "high",
                "source_ip": events[0]["source_ip"],
                "target_ips": list(target_ips.keys()),
                "scan_count": len(port_events),
                "timeframe": self._calculate_timeframe(port_events),
                "description": f"Port scan detectado: {len(port_events)} tentativas em {len(target_ips)} alvos"
            }
        
        return None
    
    def _detect_brute_force_pattern(self, events: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        """Detecta padrão de brute force."""
        auth_events = [e for e in events if e.get("event_type") == "authentication_failed"]
        
        if len(auth_events) < self.thresholds["brute_force_threshold"]:
            return None
        
        # Verificar se são para o mesmo serviço
        services = Counter(e.get("service") for e in auth_events)
        most_common_service = services.most_common(1)[0][0] if services else None
        
        return {
            "type": "brute_force",
            "severity": "high",
            "source_ip": events[0]["source_ip"],
            "target_service": most_common_service,
            "attempt_count": len(auth_events),
            "timeframe": self._calculate_timeframe(auth_events),
            "description": f"Brute force detectado: {len(auth_events)} tentativas no serviço {most_common_service}"
        }
    
    def _detect_lateral_movement_pattern(self, events: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        """Detecta padrão de lateral movement."""
        # Procurar por conexões sucessivas entre diferentes segmentos de rede
        internal_ips = [e for e in events if self._is_internal_ip(e.get("source_ip", ""))]
        external_ips = [e for e in events if not self._is_internal_ip(e.get("source_ip", ""))]
        
        if len(internal_ips) > 2 and len(external_ips) > 0:
            return {
                "type": "lateral_movement",
                "severity": "critical",
                "source_ip": events[0]["source_ip"],
                "internal_connections": len(internal_ips),
                "external_connections": len(external_ips),
                "timeframe": self._calculate_timeframe(events),
                "description": "Possível lateral movement detectado: conexões internas e externas"
            }
        
        return None
    
    def _correlate_cross_ip_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlaciona eventos entre IPs diferentes."""
        correlations = []
        
        # Detectar ataques coordenados
        coordinated_attack = self._detect_coordinated_attack(events)
        if coordinated_attack:
            correlations.append(coordinated_attack)
        
        # Detectar botnet activity
        botnet_activity = self._detect_botnet_activity(events)
        if botnet_activity:
            correlations.append(botnet_activity)
        
        return correlations
    
    def _detect_coordinated_attack(self, events: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        """Detecta ataques coordenados de múltiplos IPs."""
        # Agrupar por timestamp (janela de tempo)
        time_windows = defaultdict(list)
        
        for event in events:
            timestamp = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
            window_key = timestamp.replace(minute=0, second=0, microsecond=0)
            time_windows[window_key].append(event)
        
        # Verificar janelas com alta atividade
        for window, window_events in time_windows.items():
            if len(window_events) > 10:  # Threshold para atividade coordenada
                source_ips = set(e["source_ip"] for e in window_events)
                if len(source_ips) > 3:  # Múltiplos IPs
                    return {
                        "type": "coordinated_attack",
                        "severity": "critical",
                        "source_ips": list(source_ips),
                        "event_count": len(window_events),
                        "time_window": window.isoformat(),
                        "description": f"Ataque coordenado detectado: {len(source_ips)} IPs, {len(window_events)} eventos"
                    }
        
        return None
    
    def _detect_botnet_activity(self, events: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        """Detecta atividade de botnet."""
        # Procurar por padrões de comportamento similar entre IPs
        ip_behaviors = defaultdict(list)
        
        for event in events:
            source_ip = event["source_ip"]
            behavior = {
                "event_type": event.get("event_type"),
                "destination_port": event.get("destination_port"),
                "protocol": event.get("protocol")
            }
            ip_behaviors[source_ip].append(behavior)
        
        # Encontrar IPs com comportamento similar
        similar_ips = []
        behavior_patterns = defaultdict(list)
        
        for ip, behaviors in ip_behaviors.items():
            pattern = tuple(sorted(behaviors, key=str))
            behavior_patterns[pattern].append(ip)
        
        for pattern, ips in behavior_patterns.items():
            if len(ips) > 2:  # Threshold para botnet
                similar_ips.extend(ips)
        
        if similar_ips:
            return {
                "type": "botnet_activity",
                "severity": "high",
                "suspected_botnet_ips": similar_ips,
                "behavior_patterns": len(behavior_patterns),
                "description": f"Atividade de botnet detectada: {len(similar_ips)} IPs com comportamento similar"
            }
        
        return None
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Verifica se um IP é interno."""
        internal_ranges = [
            "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
        ]
        return any(ip.startswith(range_prefix) for range_prefix in internal_ranges)
    
    def _calculate_timeframe(self, events: List[Dict[str, Any]]) -> str:
        """Calcula o timeframe dos eventos."""
        if not events:
            return "0 minutes"
        
        timestamps = [datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) for e in events]
        min_time = min(timestamps)
        max_time = max(timestamps)
        duration = max_time - min_time
        
        return f"{duration.total_seconds() / 60:.1f} minutes"
    
    def _calculate_correlation_score(self, correlations: List[Dict[str, Any]]) -> float:
        """Calcula score de correlação."""
        if not correlations:
            return 0.0
        
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        total_score = sum(severity_scores.get(c.get("severity", "low"), 1) for c in correlations)
        
        return min(total_score / len(correlations), 4.0)
    
    def _identify_attack_campaigns(self, correlation_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identifica campanhas de ataque."""
        campaigns = []
        correlations = correlation_result.get("correlations", [])
        
        # Agrupar correlações por tipo
        by_type = defaultdict(list)
        for corr in correlations:
            by_type[corr["type"]].append(corr)
        
        # Identificar campanhas
        for corr_type, corr_list in by_type.items():
            if len(corr_list) > 1:
                campaigns.append({
                    "campaign_type": corr_type,
                    "correlation_count": len(corr_list),
                    "severity": max(c.get("severity", "low") for c in corr_list),
                    "description": f"Campanha de {corr_type} com {len(corr_list)} correlações"
                })
        
        return campaigns
    
    def _generate_correlation_recommendations(self, correlation_result: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas na correlação."""
        recommendations = []
        correlations = correlation_result.get("correlations", [])
        score = correlation_result.get("correlation_score", 0)
        
        if score >= 3.0:
            recommendations.append("ALERTA CRÍTICO: Múltiplas ameaças correlacionadas detectadas")
        
        correlation_types = {c["type"] for c in correlations}
        
        if "port_scan" in correlation_types:
            recommendations.append("Implementar detecção de port scan em tempo real")
        
        if "brute_force" in correlation_types:
            recommendations.append("Configurar proteção contra brute force")
        
        if "lateral_movement" in correlation_types:
            recommendations.append("Investigar possível comprometimento interno")
        
        if "coordinated_attack" in correlation_types:
            recommendations.append("Ativar modo de proteção contra ataques coordenados")
        
        if "botnet_activity" in correlation_types:
            recommendations.append("Bloquear IPs suspeitos de botnet")
        
        return recommendations

# Exemplo de uso
if __name__ == "__main__":
    network_events = {
        "events": [
            {
                "timestamp": "2024-01-15T14:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "event_type": "connection_denied",
                "destination_port": 22,
                "protocol": "TCP"
            },
            {
                "timestamp": "2024-01-15T14:30:01Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "event_type": "connection_denied",
                "destination_port": 23,
                "protocol": "TCP"
            },
            {
                "timestamp": "2024-01-15T14:30:02Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "event_type": "authentication_failed",
                "service": "ssh"
            }
        ]
    }
    
    input_data = {
        "dataType": "network_events",
        "data": network_events,
        "config": {"auto_extract": True}
    }
    
    correlator = NetworkEventCorrelator(input_data)
    correlator.run()
```

## Conclusão

Estes exemplos demonstram como usar o SentinelIQ SDK para criar analisadores robustos de monitoramento de rede, capazes de detectar anomalias, analisar logs de firewall e correlacionar eventos para identificar padrões de ataque complexos.
