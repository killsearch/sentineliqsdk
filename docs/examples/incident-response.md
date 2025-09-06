# Resposta a Incidentes

Este exemplo demonstra como criar analisadores e respondedores para resposta a incidentes de segurança usando o SentinelIQ SDK, incluindo triagem automática, análise forense e automação de resposta.

## Analisador de Triagem de Incidentes

### Classificação Automática de Incidentes

```python
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sentineliqsdk import Analyzer, WorkerInput

class IncidentTriageAnalyzer(Analyzer):
    """Analisador para triagem automática de incidentes de segurança."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        
        self.incident_types = {
            "malware": ["virus", "trojan", "ransomware", "backdoor"],
            "phishing": ["phishing", "spear_phishing", "credential_theft"],
            "ddos": ["ddos", "dos", "flood_attack"],
            "intrusion": ["intrusion", "unauthorized_access", "privilege_escalation"],
            "data_breach": ["data_breach", "data_exfiltration", "data_leak"]
        }
    
    def run(self) -> None:
        incident_data = self.get_data()
        
        # Validar dados do incidente
        if not self._validate_incident_data(incident_data):
            self.error("Dados do incidente inválidos")
        
        # Realizar triagem
        triage_result = self._perform_triage(incident_data)
        
        # Gerar relatório
        self.report({
            "incident_id": incident_data.get("incident_id"),
            "triage_result": triage_result,
            "recommended_actions": self._generate_recommendations(triage_result),
            "escalation_required": triage_result["severity"] in ["critical", "high"]
        })
    
    def _validate_incident_data(self, data: Dict[str, Any]) -> bool:
        """Valida se os dados do incidente estão completos."""
        required_fields = ["incident_id", "description", "timestamp", "source"]
        return all(field in data for field in required_fields)
    
    def _perform_triage(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Realiza triagem do incidente."""
        description = incident_data.get("description", "").lower()
        source = incident_data.get("source", "").lower()
        
        # Classificar tipo de incidente
        incident_type = self._classify_incident_type(description)
        
        # Determinar severidade
        severity = self._determine_severity(incident_data, incident_type)
        
        # Calcular prioridade
        priority = self._calculate_priority(incident_data, severity)
        
        # Identificar indicadores de comprometimento
        iocs = self._extract_iocs(incident_data)
        
        # Determinar categoria de impacto
        impact_category = self._assess_impact(incident_data, incident_type)
        
        return {
            "incident_type": incident_type,
            "severity": severity,
            "priority": priority,
            "impact_category": impact_category,
            "iocs": iocs,
            "confidence": self._calculate_confidence(incident_data, incident_type),
            "estimated_resolution_time": self._estimate_resolution_time(severity, incident_type)
        }
    
    def _classify_incident_type(self, description: str) -> str:
        """Classifica o tipo de incidente baseado na descrição."""
        for incident_type, keywords in self.incident_types.items():
            if any(keyword in description for keyword in keywords):
                return incident_type
        
        # Análise de palavras-chave adicionais
        if any(word in description for word in ["attack", "exploit", "vulnerability"]):
            return "intrusion"
        elif any(word in description for word in ["email", "suspicious", "suspicious_email"]):
            return "phishing"
        else:
            return "unknown"
    
    def _determine_severity(self, incident_data: Dict[str, Any], incident_type: str) -> str:
        """Determina a severidade do incidente."""
        severity_indicators = {
            "critical": [
                "ransomware", "data_breach", "privilege_escalation", "root_compromise",
                "production_down", "customer_data", "financial_loss"
            ],
            "high": [
                "malware", "intrusion", "unauthorized_access", "system_compromise",
                "network_intrusion", "suspicious_activity"
            ],
            "medium": [
                "phishing", "suspicious_email", "policy_violation", "anomaly"
            ],
            "low": [
                "false_positive", "informational", "routine_check"
            ]
        }
        
        description = incident_data.get("description", "").lower()
        source = incident_data.get("source", "").lower()
        
        # Verificar indicadores de severidade
        for severity, indicators in severity_indicators.items():
            if any(indicator in description or indicator in source for indicator in indicators):
                return severity
        
        # Severidade baseada no tipo de incidente
        type_severity_map = {
            "malware": "high",
            "phishing": "medium",
            "ddos": "high",
            "intrusion": "high",
            "data_breach": "critical"
        }
        
        return type_severity_map.get(incident_type, "medium")
    
    def _calculate_priority(self, incident_data: Dict[str, Any], severity: str) -> int:
        """Calcula a prioridade numérica do incidente."""
        base_priority = self.severity_weights.get(severity, 1)
        
        # Ajustar prioridade baseado em fatores adicionais
        priority_modifiers = 0
        
        # Impacto no negócio
        if incident_data.get("business_impact", "low") == "high":
            priority_modifiers += 2
        elif incident_data.get("business_impact", "low") == "medium":
            priority_modifiers += 1
        
        # Urgência temporal
        if incident_data.get("urgency", "low") == "high":
            priority_modifiers += 2
        elif incident_data.get("urgency", "low") == "medium":
            priority_modifiers += 1
        
        # Múltiplos sistemas afetados
        affected_systems = incident_data.get("affected_systems", [])
        if len(affected_systems) > 3:
            priority_modifiers += 1
        
        return min(base_priority + priority_modifiers, 10)
    
    def _extract_iocs(self, incident_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai indicadores de comprometimento do incidente."""
        iocs = []
        
        # IPs mencionados
        if "source_ip" in incident_data:
            iocs.append({
                "type": "ip",
                "value": incident_data["source_ip"],
                "context": "source"
            })
        
        # URLs mencionadas
        if "url" in incident_data:
            iocs.append({
                "type": "url",
                "value": incident_data["url"],
                "context": "suspicious_url"
            })
        
        # Domínios mencionados
        if "domain" in incident_data:
            iocs.append({
                "type": "domain",
                "value": incident_data["domain"],
                "context": "suspicious_domain"
            })
        
        # Hashes de arquivos
        if "file_hash" in incident_data:
            iocs.append({
                "type": "hash",
                "value": incident_data["file_hash"],
                "context": "malicious_file"
            })
        
        # Emails suspeitos
        if "email" in incident_data:
            iocs.append({
                "type": "email",
                "value": incident_data["email"],
                "context": "phishing_email"
            })
        
        return iocs
    
    def _assess_impact(self, incident_data: Dict[str, Any], incident_type: str) -> str:
        """Avalia a categoria de impacto do incidente."""
        affected_systems = incident_data.get("affected_systems", [])
        business_impact = incident_data.get("business_impact", "low")
        
        # Impacto baseado no número de sistemas afetados
        if len(affected_systems) > 5:
            return "high"
        elif len(affected_systems) > 2:
            return "medium"
        
        # Impacto baseado no tipo de incidente
        high_impact_types = ["data_breach", "ransomware", "ddos"]
        if incident_type in high_impact_types:
            return "high"
        
        # Impacto baseado no impacto no negócio
        if business_impact == "high":
            return "high"
        elif business_impact == "medium":
            return "medium"
        
        return "low"
    
    def _calculate_confidence(self, incident_data: Dict[str, Any], incident_type: str) -> float:
        """Calcula a confiança na classificação do incidente."""
        confidence = 0.5  # Base
        
        # Aumentar confiança se há IOCs específicos
        ioc_count = len(self._extract_iocs(incident_data))
        confidence += min(ioc_count * 0.1, 0.3)
        
        # Aumentar confiança se há evidências específicas
        if incident_data.get("evidence"):
            confidence += 0.2
        
        # Aumentar confiança se há logs de sistema
        if incident_data.get("system_logs"):
            confidence += 0.1
        
        return min(confidence, 0.95)
    
    def _estimate_resolution_time(self, severity: str, incident_type: str) -> str:
        """Estima o tempo de resolução do incidente."""
        base_times = {
            "critical": "4-8 hours",
            "high": "1-2 days",
            "medium": "3-5 days",
            "low": "1-2 weeks"
        }
        
        base_time = base_times.get(severity, "3-5 days")
        
        # Ajustar baseado no tipo de incidente
        if incident_type == "data_breach":
            return "1-2 weeks"
        elif incident_type == "malware":
            return "2-4 days"
        elif incident_type == "phishing":
            return "1-3 days"
        
        return base_time
    
    def _generate_recommendations(self, triage_result: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas na triagem."""
        recommendations = []
        severity = triage_result["severity"]
        incident_type = triage_result["incident_type"]
        
        # Recomendações baseadas na severidade
        if severity == "critical":
            recommendations.extend([
                "AÇÃO IMEDIATA: Ativar equipe de resposta a incidentes",
                "Notificar stakeholders e executivos",
                "Implementar medidas de contenção imediatas"
            ])
        elif severity == "high":
            recommendations.extend([
                "Priorizar investigação e resposta",
                "Notificar equipe de segurança",
                "Documentar evidências"
            ])
        
        # Recomendações baseadas no tipo de incidente
        if incident_type == "malware":
            recommendations.extend([
                "Isolar sistemas infectados",
                "Executar varredura antivírus completa",
                "Verificar backups e integridade dos dados"
            ])
        elif incident_type == "phishing":
            recommendations.extend([
                "Bloquear URLs e domínios maliciosos",
                "Notificar usuários afetados",
                "Implementar treinamento adicional de conscientização"
            ])
        elif incident_type == "data_breach":
            recommendations.extend([
                "Avaliar escopo da violação",
                "Notificar autoridades competentes se necessário",
                "Implementar medidas de mitigação"
            ])
        
        return recommendations

# Exemplo de uso
if __name__ == "__main__":
    incident_data = {
        "incident_id": "INC-2024-001",
        "description": "Ransomware detected on multiple workstations in finance department",
        "timestamp": "2024-01-15T14:30:00Z",
        "source": "EDR_system",
        "source_ip": "192.168.1.100",
        "affected_systems": ["WS-FIN-001", "WS-FIN-002", "WS-FIN-003"],
        "business_impact": "high",
        "urgency": "high",
        "evidence": ["encrypted_files", "ransom_note.txt"],
        "system_logs": ["windows_event_logs", "edr_logs"]
    }
    
    input_data = {
        "dataType": "incident",
        "data": incident_data,
        "config": {"auto_extract": True}
    }
    
    analyzer = IncidentTriageAnalyzer(input_data)
    analyzer.run()
```

## Respondedor de Contenção Automática

### Automação de Resposta a Incidentes

```python
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional
from sentineliqsdk import Responder, WorkerInput

class IncidentResponseResponder(Responder):
    """Respondedor para automação de resposta a incidentes."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.response_actions = {
            "malware": ["isolate_host", "quarantine_file", "block_hash"],
            "phishing": ["block_domain", "block_url", "disable_user"],
            "ddos": ["enable_ddos_protection", "rate_limit", "block_source_ips"],
            "intrusion": ["block_ip", "disable_account", "revoke_access"],
            "data_breach": ["disable_accounts", "revoke_access", "enable_monitoring"]
        }
    
    def run(self) -> None:
        incident_data = self.get_data()
        
        # Validar dados do incidente
        if not self._validate_incident_data(incident_data):
            self.error("Dados do incidente inválidos para resposta")
        
        # Determinar ações de resposta
        response_plan = self._create_response_plan(incident_data)
        
        # Executar ações de resposta
        execution_result = self._execute_response_actions(response_plan)
        
        # Gerar relatório
        self.report({
            "incident_id": incident_data.get("incident_id"),
            "response_plan": response_plan,
            "execution_result": execution_result,
            "next_steps": self._generate_next_steps(execution_result)
        })
    
    def _validate_incident_data(self, data: Dict[str, Any]) -> bool:
        """Valida se os dados do incidente são adequados para resposta."""
        required_fields = ["incident_id", "incident_type", "severity", "iocs"]
        return all(field in data for field in required_fields)
    
    def _create_response_plan(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cria plano de resposta baseado no incidente."""
        incident_type = incident_data.get("incident_type")
        severity = incident_data.get("severity")
        iocs = incident_data.get("iocs", [])
        
        # Determinar ações baseadas no tipo de incidente
        base_actions = self.response_actions.get(incident_type, [])
        
        # Ajustar ações baseado na severidade
        if severity == "critical":
            base_actions.extend(["escalate", "notify_executives", "activate_incident_team"])
        elif severity == "high":
            base_actions.extend(["notify_security_team", "increase_monitoring"])
        
        # Adicionar ações específicas baseadas nos IOCs
        ioc_actions = self._generate_ioc_actions(iocs)
        base_actions.extend(ioc_actions)
        
        return {
            "incident_type": incident_type,
            "severity": severity,
            "planned_actions": base_actions,
            "priority": self._calculate_response_priority(severity, incident_type),
            "estimated_duration": self._estimate_response_duration(base_actions)
        }
    
    def _generate_ioc_actions(self, iocs: List[Dict[str, Any]]) -> List[str]:
        """Gera ações específicas baseadas nos IOCs."""
        actions = []
        
        for ioc in iocs:
            ioc_type = ioc.get("type")
            ioc_value = ioc.get("value")
            context = ioc.get("context", "")
            
            if ioc_type == "ip":
                if "source" in context:
                    actions.append(f"block_ip:{ioc_value}")
                else:
                    actions.append(f"monitor_ip:{ioc_value}")
            
            elif ioc_type == "domain":
                actions.append(f"block_domain:{ioc_value}")
            
            elif ioc_type == "url":
                actions.append(f"block_url:{ioc_value}")
            
            elif ioc_type == "hash":
                actions.append(f"quarantine_hash:{ioc_value}")
            
            elif ioc_type == "email":
                actions.append(f"investigate_email:{ioc_value}")
        
        return actions
    
    def _calculate_response_priority(self, severity: str, incident_type: str) -> int:
        """Calcula a prioridade da resposta."""
        priority_map = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        
        base_priority = priority_map.get(severity, 1)
        
        # Ajustar prioridade baseado no tipo de incidente
        if incident_type in ["data_breach", "ransomware"]:
            base_priority += 2
        elif incident_type in ["malware", "intrusion"]:
            base_priority += 1
        
        return min(base_priority, 10)
    
    def _estimate_response_duration(self, actions: List[str]) -> str:
        """Estima a duração da resposta."""
        if not actions:
            return "Unknown"
        
        # Estimativas baseadas no número e tipo de ações
        base_time = 30  # minutos base
        
        # Ajustar baseado no número de ações
        base_time += len(actions) * 5
        
        # Ajustar baseado em ações complexas
        complex_actions = ["escalate", "activate_incident_team", "notify_executives"]
        complex_count = sum(1 for action in actions if any(ca in action for ca in complex_actions))
        base_time += complex_count * 15
        
        if base_time < 60:
            return f"{base_time} minutes"
        else:
            hours = base_time // 60
            minutes = base_time % 60
            return f"{hours}h {minutes}m"
    
    def _execute_response_actions(self, response_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Executa as ações de resposta (simulado)."""
        actions = response_plan.get("planned_actions", [])
        execution_results = []
        
        for action in actions:
            result = self._execute_single_action(action)
            execution_results.append(result)
        
        # Calcular estatísticas de execução
        successful = sum(1 for r in execution_results if r.get("success", False))
        failed = len(execution_results) - successful
        
        return {
            "total_actions": len(actions),
            "successful_actions": successful,
            "failed_actions": failed,
            "success_rate": successful / len(actions) if actions else 0,
            "execution_details": execution_results,
            "overall_status": "success" if failed == 0 else "partial_success" if successful > 0 else "failed"
        }
    
    def _execute_single_action(self, action: str) -> Dict[str, Any]:
        """Executa uma única ação de resposta (simulado)."""
        # Simular execução de ação
        import random
        success = random.random() > 0.1  # 90% de sucesso
        
        if ":" in action:
            action_type, target = action.split(":", 1)
        else:
            action_type = action
            target = None
        
        return {
            "action": action,
            "action_type": action_type,
            "target": target,
            "success": success,
            "timestamp": "2024-01-15T14:35:00Z",
            "message": f"Action {action_type} {'completed successfully' if success else 'failed'}"
        }
    
    def _generate_next_steps(self, execution_result: Dict[str, Any]) -> List[str]:
        """Gera próximos passos baseados no resultado da execução."""
        next_steps = []
        overall_status = execution_result.get("overall_status")
        
        if overall_status == "success":
            next_steps.extend([
                "Monitorar sistemas afetados",
                "Documentar ações tomadas",
                "Aguardar confirmação de resolução"
            ])
        elif overall_status == "partial_success":
            next_steps.extend([
                "Investigar ações que falharam",
                "Implementar ações alternativas",
                "Escalar para equipe técnica se necessário"
            ])
        else:
            next_steps.extend([
                "Escalar imediatamente para equipe de resposta a incidentes",
                "Implementar ações manuais de contenção",
                "Notificar stakeholders sobre falhas na automação"
            ])
        
        # Adicionar próximos passos baseados no tipo de incidente
        failed_actions = [r for r in execution_result.get("execution_details", []) if not r.get("success", False)]
        if failed_actions:
            next_steps.append(f"Investigar {len(failed_actions)} ações que falharam")
        
        return next_steps

# Exemplo de uso
if __name__ == "__main__":
    incident_data = {
        "incident_id": "INC-2024-001",
        "incident_type": "malware",
        "severity": "high",
        "iocs": [
            {"type": "ip", "value": "192.168.1.100", "context": "source"},
            {"type": "hash", "value": "abc123def456", "context": "malicious_file"},
            {"type": "domain", "value": "malicious.example.com", "context": "suspicious_domain"}
        ]
    }
    
    input_data = {
        "dataType": "incident_response",
        "data": incident_data,
        "config": {"auto_extract": True}
    }
    
    responder = IncidentResponseResponder(input_data)
    responder.run()
```

## Analisador Forense Digital

### Análise de Evidências Digitais

```python
from __future__ import annotations
import hashlib
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from sentineliqsdk import Analyzer, WorkerInput

class DigitalForensicsAnalyzer(Analyzer):
    """Analisador para análise forense digital de evidências."""
    
    def __init__(self, input_data: WorkerInput | Dict[str, Any]):
        super().__init__(input_data)
        self.known_malicious_hashes = {
            "abc123def456": "Trojan.Generic",
            "def456ghi789": "Ransomware.WannaCry",
            "ghi789jkl012": "Backdoor.RemoteAccess"
        }
        
        self.suspicious_patterns = [
            r"cmd\.exe.*\/c",
            r"powershell.*-enc",
            r"rundll32.*\.dll",
            r"regsvr32.*\.sct"
        ]
    
    def run(self) -> None:
        evidence_data = self.get_data()
        
        # Validar evidências
        if not self._validate_evidence_data(evidence_data):
            self.error("Dados de evidência inválidos")
        
        # Analisar evidências
        analysis_result = self._analyze_evidence(evidence_data)
        
        # Gerar relatório forense
        self.report({
            "evidence_id": evidence_data.get("evidence_id"),
            "forensic_analysis": analysis_result,
            "chain_of_custody": self._generate_chain_of_custody(evidence_data),
            "legal_considerations": self._generate_legal_considerations(analysis_result)
        })
    
    def _validate_evidence_data(self, data: Dict[str, Any]) -> bool:
        """Valida se os dados de evidência estão completos."""
        required_fields = ["evidence_id", "evidence_type", "timestamp"]
        return all(field in data for field in required_fields)
    
    def _analyze_evidence(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa evidências digitais."""
        evidence_type = evidence_data.get("evidence_type")
        
        if evidence_type == "file":
            return self._analyze_file_evidence(evidence_data)
        elif evidence_type == "memory":
            return self._analyze_memory_evidence(evidence_data)
        elif evidence_type == "network":
            return self._analyze_network_evidence(evidence_data)
        elif evidence_type == "log":
            return self._analyze_log_evidence(evidence_data)
        else:
            return {"error": f"Tipo de evidência não suportado: {evidence_type}"}
    
    def _analyze_file_evidence(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa evidências de arquivo."""
        file_path = evidence_data.get("file_path")
        file_hash = evidence_data.get("file_hash")
        file_size = evidence_data.get("file_size")
        
        analysis = {
            "file_analysis": {
                "path": file_path,
                "hash": file_hash,
                "size": file_size,
                "malware_detection": self._detect_malware(file_hash),
                "file_type": self._determine_file_type(file_path),
                "entropy": self._calculate_entropy(evidence_data)
            },
            "timeline": self._extract_file_timeline(evidence_data),
            "artifacts": self._extract_file_artifacts(evidence_data)
        }
        
        return analysis
    
    def _analyze_memory_evidence(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa evidências de memória."""
        memory_dump = evidence_data.get("memory_dump")
        process_list = evidence_data.get("process_list", [])
        
        analysis = {
            "memory_analysis": {
                "dump_size": len(memory_dump) if memory_dump else 0,
                "process_count": len(process_list),
                "suspicious_processes": self._identify_suspicious_processes(process_list),
                "injected_code": self._detect_code_injection(memory_dump),
                "network_connections": self._extract_network_connections(evidence_data)
            },
            "volatility_analysis": self._run_volatility_analysis(evidence_data)
        }
        
        return analysis
    
    def _analyze_network_evidence(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa evidências de rede."""
        network_capture = evidence_data.get("network_capture")
        connections = evidence_data.get("connections", [])
        
        analysis = {
            "network_analysis": {
                "capture_size": len(network_capture) if network_capture else 0,
                "connection_count": len(connections),
                "suspicious_connections": self._identify_suspicious_connections(connections),
                "data_exfiltration": self._detect_data_exfiltration(connections),
                "command_control": self._detect_c2_communication(connections)
            },
            "protocol_analysis": self._analyze_network_protocols(connections)
        }
        
        return analysis
    
    def _analyze_log_evidence(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa evidências de log."""
        log_entries = evidence_data.get("log_entries", [])
        log_source = evidence_data.get("log_source")
        
        analysis = {
            "log_analysis": {
                "entry_count": len(log_entries),
                "log_source": log_source,
                "suspicious_entries": self._identify_suspicious_log_entries(log_entries),
                "attack_patterns": self._detect_attack_patterns(log_entries),
                "timeline": self._extract_log_timeline(log_entries)
            },
            "correlation": self._correlate_log_events(log_entries)
        }
        
        return analysis
    
    def _detect_malware(self, file_hash: str) -> Dict[str, Any]:
        """Detecta malware baseado no hash do arquivo."""
        if file_hash in self.known_malicious_hashes:
            return {
                "detected": True,
                "malware_family": self.known_malicious_hashes[file_hash],
                "confidence": 0.95
            }
        else:
            return {
                "detected": False,
                "malware_family": None,
                "confidence": 0.0
            }
    
    def _determine_file_type(self, file_path: str) -> str:
        """Determina o tipo de arquivo baseado na extensão."""
        if not file_path:
            return "unknown"
        
        extension = file_path.split('.')[-1].lower()
        
        type_map = {
            'exe': 'executable',
            'dll': 'library',
            'bat': 'batch',
            'ps1': 'powershell',
            'vbs': 'vbscript',
            'js': 'javascript',
            'pdf': 'document',
            'doc': 'document',
            'docx': 'document'
        }
        
        return type_map.get(extension, 'unknown')
    
    def _calculate_entropy(self, evidence_data: Dict[str, Any]) -> float:
        """Calcula a entropia do arquivo (simulado)."""
        # Simulação de cálculo de entropia
        import random
        return round(random.uniform(0.0, 8.0), 2)
    
    def _extract_file_timeline(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai timeline de eventos do arquivo."""
        timeline = []
        
        # Adicionar eventos de timeline se disponíveis
        if "creation_time" in evidence_data:
            timeline.append({
                "event": "file_created",
                "timestamp": evidence_data["creation_time"],
                "description": "Arquivo criado"
            })
        
        if "modification_time" in evidence_data:
            timeline.append({
                "event": "file_modified",
                "timestamp": evidence_data["modification_time"],
                "description": "Arquivo modificado"
            })
        
        if "access_time" in evidence_data:
            timeline.append({
                "event": "file_accessed",
                "timestamp": evidence_data["access_time"],
                "description": "Arquivo acessado"
            })
        
        return sorted(timeline, key=lambda x: x["timestamp"])
    
    def _extract_file_artifacts(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai artefatos do arquivo."""
        artifacts = []
        
        # Simular extração de artefatos
        if evidence_data.get("file_type") == "executable":
            artifacts.extend([
                {
                    "type": "imports",
                    "value": ["kernel32.dll", "user32.dll", "advapi32.dll"],
                    "description": "Imports de bibliotecas do sistema"
                },
                {
                    "type": "strings",
                    "value": ["cmd.exe", "powershell", "regsvr32"],
                    "description": "Strings suspeitas encontradas"
                }
            ])
        
        return artifacts
    
    def _identify_suspicious_processes(self, process_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifica processos suspeitos."""
        suspicious = []
        
        for process in process_list:
            process_name = process.get("name", "").lower()
            
            # Verificar padrões suspeitos
            if any(pattern in process_name for pattern in ["cmd", "powershell", "rundll32"]):
                suspicious.append({
                    "pid": process.get("pid"),
                    "name": process.get("name"),
                    "reason": "Processo suspeito detectado",
                    "severity": "medium"
                })
        
        return suspicious
    
    def _detect_code_injection(self, memory_dump: str) -> Dict[str, Any]:
        """Detecta injeção de código na memória (simulado)."""
        # Simulação de detecção de injeção de código
        return {
            "detected": False,
            "injection_type": None,
            "confidence": 0.0
        }
    
    def _extract_network_connections(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai conexões de rede da memória."""
        connections = evidence_data.get("network_connections", [])
        
        suspicious_connections = []
        for conn in connections:
            if conn.get("remote_port") in [4444, 6666, 8080]:  # Portas suspeitas
                suspicious_connections.append(conn)
        
        return suspicious_connections
    
    def _identify_suspicious_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifica conexões suspeitas."""
        suspicious = []
        
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_port = conn.get("remote_port", 0)
            
            # Verificar IPs suspeitos
            if remote_ip.startswith("192.168.") or remote_ip.startswith("10."):
                continue  # IPs internos são menos suspeitos
            
            # Verificar portas suspeitas
            if remote_port in [4444, 6666, 8080, 9999]:
                suspicious.append({
                    "connection": conn,
                    "reason": f"Porta suspeita: {remote_port}",
                    "severity": "high"
                })
        
        return suspicious
    
    def _detect_data_exfiltration(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detecta possível exfiltração de dados."""
        total_bytes = sum(conn.get("bytes_sent", 0) for conn in connections)
        
        if total_bytes > 1000000:  # 1MB threshold
            return {
                "detected": True,
                "total_bytes": total_bytes,
                "confidence": 0.7,
                "description": "Grande volume de dados enviados"
            }
        
        return {
            "detected": False,
            "total_bytes": total_bytes,
            "confidence": 0.0
        }
    
    def _detect_c2_communication(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detecta comunicação de comando e controle."""
        # Simulação de detecção de C2
        return {
            "detected": False,
            "c2_indicators": [],
            "confidence": 0.0
        }
    
    def _analyze_network_protocols(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisa protocolos de rede."""
        protocols = {}
        
        for conn in connections:
            protocol = conn.get("protocol", "unknown")
            protocols[protocol] = protocols.get(protocol, 0) + 1
        
        return {
            "protocol_distribution": protocols,
            "most_common": max(protocols.items(), key=lambda x: x[1])[0] if protocols else None
        }
    
    def _identify_suspicious_log_entries(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifica entradas de log suspeitas."""
        suspicious = []
        
        for entry in log_entries:
            message = entry.get("message", "").lower()
            
            # Verificar padrões suspeitos
            for pattern in self.suspicious_patterns:
                if pattern in message:
                    suspicious.append({
                        "entry": entry,
                        "pattern": pattern,
                        "severity": "high"
                    })
        
        return suspicious
    
    def _detect_attack_patterns(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detecta padrões de ataque nos logs."""
        patterns = []
        
        # Simulação de detecção de padrões
        failed_logins = sum(1 for entry in log_entries if "failed login" in entry.get("message", "").lower())
        
        if failed_logins > 5:
            patterns.append({
                "pattern": "brute_force",
                "count": failed_logins,
                "severity": "high"
            })
        
        return patterns
    
    def _extract_log_timeline(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extrai timeline dos logs."""
        timeline = []
        
        for entry in log_entries:
            timeline.append({
                "timestamp": entry.get("timestamp"),
                "event": entry.get("event_type", "unknown"),
                "message": entry.get("message", "")
            })
        
        return sorted(timeline, key=lambda x: x["timestamp"])
    
    def _correlate_log_events(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlaciona eventos de log."""
        # Simulação de correlação
        return {
            "correlated_events": 0,
            "attack_sequences": [],
            "confidence": 0.0
        }
    
    def _generate_chain_of_custody(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Gera cadeia de custódia da evidência."""
        return [
            {
                "timestamp": evidence_data.get("timestamp"),
                "action": "evidence_collected",
                "handler": "automated_system",
                "location": "digital_forensics_lab",
                "description": "Evidência coletada automaticamente"
            }
        ]
    
    def _generate_legal_considerations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Gera considerações legais baseadas na análise."""
        considerations = []
        
        # Verificar se há evidências de atividade maliciosa
        if analysis_result.get("file_analysis", {}).get("malware_detection", {}).get("detected"):
            considerations.append("Evidência de malware detectada - considerar notificação legal")
        
        if analysis_result.get("memory_analysis", {}).get("suspicious_processes"):
            considerations.append("Processos suspeitos detectados - documentar para processo legal")
        
        if analysis_result.get("network_analysis", {}).get("data_exfiltration", {}).get("detected"):
            considerations.append("Possível exfiltração de dados - notificar autoridades competentes")
        
        if not considerations:
            considerations.append("Nenhuma consideração legal específica identificada")
        
        return considerations

# Exemplo de uso
if __name__ == "__main__":
    evidence_data = {
        "evidence_id": "EVD-2024-001",
        "evidence_type": "file",
        "timestamp": "2024-01-15T14:30:00Z",
        "file_path": "/suspicious/malware.exe",
        "file_hash": "abc123def456",
        "file_size": 1024000,
        "creation_time": "2024-01-15T14:25:00Z",
        "modification_time": "2024-01-15T14:28:00Z",
        "access_time": "2024-01-15T14:30:00Z"
    }
    
    input_data = {
        "dataType": "digital_evidence",
        "data": evidence_data,
        "config": {"auto_extract": True}
    }
    
    analyzer = DigitalForensicsAnalyzer(input_data)
    analyzer.run()
```

## Conclusão

Estes exemplos demonstram como usar o SentinelIQ SDK para criar sistemas robustos de resposta a incidentes, incluindo triagem automática, contenção automatizada e análise forense digital. Essas ferramentas podem ser integradas em workflows de SOC para melhorar a eficiência e eficácia da resposta a incidentes de segurança.
