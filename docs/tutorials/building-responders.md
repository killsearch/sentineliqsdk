---
title: Building Responders
---

# Building Responders

Responders are specialized workers that take automated actions based on analysis results. This guide covers everything you need to know about building effective responders with the SentinelIQ SDK.

## Table of Contents

- [Responder Fundamentals](#responder-fundamentals)
- [Common Response Patterns](#common-response-patterns)
- [Error Handling and Recovery](#error-handling-and-recovery)
- [State Management](#state-management)
- [Testing Responders](#testing-responders)
- [Advanced Patterns](#advanced-patterns)

## Responder Fundamentals

### What is a Responder?

A responder is a specialized worker that executes automated actions in response to security events. Unlike analyzers that provide intelligence, responders take concrete actions like blocking IPs, quarantining files, or sending notifications.

### Key Characteristics

- **Input**: Analysis results or direct observables
- **Output**: Action status and results
- **Purpose**: Automated response and remediation
- **Actions**: Blocking, alerting, quarantining, etc.

### Basic Structure

```python
from sentineliqsdk import Responder

class MyResponder(Responder):
    def run(self) -> None:
        # 1. Get input data
        observable = self.get_data()
        
        # 2. Determine action
        action = self._determine_action(observable)
        
        # 3. Execute action
        result = self._execute_action(action, observable)
        
        # 4. Report results
        self.report(result)
```

## Common Response Patterns

### 1. IP Blocking Responder

Block malicious IP addresses:

```python
import requests
from sentineliqsdk import Responder

class IPBlockResponder(Responder):
    """Responder that blocks malicious IP addresses."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.firewall_api = self.get_param("config.firewall_api_url")
        self.api_key = self.get_param("config.api_key", message="API key required")
    
    def run(self) -> None:
        ip_address = self.get_data()
        
        # Determine blocking action
        action = self._determine_blocking_action(ip_address)
        
        if action["should_block"]:
            result = self._block_ip(ip_address, action)
        else:
            result = self._monitor_ip(ip_address)
        
        self.report(result)
    
    def _determine_blocking_action(self, ip: str) -> dict:
        """Determine if IP should be blocked and for how long."""
        # Check if IP is in critical threat list
        if self._is_critical_threat(ip):
            return {
                "should_block": True,
                "duration": "permanent",
                "priority": "high",
                "reason": "critical_threat"
            }
        
        # Check if IP is in known malicious list
        if self._is_malicious(ip):
            return {
                "should_block": True,
                "duration": "24h",
                "priority": "medium",
                "reason": "malicious"
            }
        
        # Check if IP is suspicious
        if self._is_suspicious(ip):
            return {
                "should_block": False,
                "duration": "1h",
                "priority": "low",
                "reason": "suspicious"
            }
        
        return {
            "should_block": False,
            "duration": None,
            "priority": "none",
            "reason": "safe"
        }
    
    def _block_ip(self, ip: str, action: dict) -> dict:
        """Block IP address using firewall API."""
        try:
            # Prepare blocking request
            block_request = {
                "ip": ip,
                "action": "block",
                "duration": action["duration"],
                "priority": action["priority"],
                "reason": action["reason"],
                "timestamp": self._get_timestamp()
            }
            
            # Call firewall API
            response = requests.post(
                f"{self.firewall_api}/rules",
                json=block_request,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30
            )
            
            if response.status_code == 201:
                rule_data = response.json()
                return {
                    "action": "block",
                    "target": ip,
                    "status": "success",
                    "rule_id": rule_data["id"],
                    "duration": action["duration"],
                    "priority": action["priority"],
                    "timestamp": self._get_timestamp()
                }
            else:
                return {
                    "action": "block",
                    "target": ip,
                    "status": "failed",
                    "error": f"API returned {response.status_code}",
                    "timestamp": self._get_timestamp()
                }
                
        except requests.RequestException as e:
            return {
                "action": "block",
                "target": ip,
                "status": "failed",
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    def _monitor_ip(self, ip: str) -> dict:
        """Monitor IP without blocking."""
        return {
            "action": "monitor",
            "target": ip,
            "status": "active",
            "timestamp": self._get_timestamp()
        }
```

### 2. File Quarantine Responder

Quarantine malicious files:

```python
import shutil
import hashlib
from pathlib import Path
from sentineliqsdk import Responder

class FileQuarantineResponder(Responder):
    """Responder that quarantines malicious files."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.quarantine_dir = Path(self.get_param("config.quarantine_dir", "/quarantine"))
        self.quarantine_dir.mkdir(exist_ok=True)
    
    def run(self) -> None:
        file_path = self.get_data()
        
        # Validate file exists
        if not Path(file_path).exists():
            self.error(f"File not found: {file_path}")
        
        # Determine quarantine action
        action = self._determine_quarantine_action(file_path)
        
        if action["should_quarantine"]:
            result = self._quarantine_file(file_path, action)
        else:
            result = self._log_file(file_path)
        
        self.report(result)
    
    def _determine_quarantine_action(self, file_path: str) -> dict:
        """Determine if file should be quarantined."""
        file_info = self._analyze_file(file_path)
        
        if file_info["malware_family"]:
            return {
                "should_quarantine": True,
                "reason": "malware_detected",
                "malware_family": file_info["malware_family"],
                "severity": "high"
            }
        
        if file_info["suspicious_behavior"]:
            return {
                "should_quarantine": True,
                "reason": "suspicious_behavior",
                "severity": "medium"
            }
        
        return {
            "should_quarantine": False,
            "reason": "clean",
            "severity": "none"
        }
    
    def _quarantine_file(self, file_path: str, action: dict) -> dict:
        """Quarantine the file."""
        try:
            # Calculate file hash
            file_hash = self._calculate_hash(file_path)
            
            # Create quarantine filename
            quarantine_name = f"{file_hash}_{Path(file_path).name}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create quarantine record
            quarantine_record = {
                "original_path": file_path,
                "quarantine_path": str(quarantine_path),
                "file_hash": file_hash,
                "reason": action["reason"],
                "severity": action["severity"],
                "timestamp": self._get_timestamp()
            }
            
            # Save quarantine record
            self._save_quarantine_record(quarantine_record)
            
            return {
                "action": "quarantine",
                "target": file_path,
                "status": "success",
                "quarantine_path": str(quarantine_path),
                "file_hash": file_hash,
                "reason": action["reason"],
                "severity": action["severity"],
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "action": "quarantine",
                "target": file_path,
                "status": "failed",
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
```

### 3. Notification Responder

Send alerts and notifications:

```python
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sentineliqsdk import Responder

class NotificationResponder(Responder):
    """Responder that sends notifications for security events."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.smtp_server = self.get_param("config.smtp_server")
        self.smtp_port = self.get_param("config.smtp_port", default=587)
        self.smtp_user = self.get_param("config.smtp_user")
        self.smtp_password = self.get_param("config.smtp_password")
        self.recipients = self.get_param("config.recipients", default=[])
    
    def run(self) -> None:
        event_data = self.get_data()
        
        # Determine notification type
        notification_type = self._determine_notification_type(event_data)
        
        # Send notification
        result = self._send_notification(event_data, notification_type)
        
        self.report(result)
    
    def _determine_notification_type(self, event_data: dict) -> str:
        """Determine notification type based on event severity."""
        severity = event_data.get("severity", "low")
        
        if severity == "critical":
            return "immediate"
        elif severity == "high":
            return "urgent"
        elif severity == "medium":
            return "standard"
        else:
            return "info"
    
    def _send_notification(self, event_data: dict, notification_type: str) -> dict:
        """Send notification via email."""
        try:
            # Create email message
            msg = MIMEMultipart()
            msg["From"] = self.smtp_user
            msg["To"] = ", ".join(self.recipients)
            msg["Subject"] = f"Security Alert: {event_data.get('title', 'Unknown Event')}"
            
            # Create email body
            body = self._create_email_body(event_data, notification_type)
            msg.attach(MIMEText(body, "html"))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            return {
                "action": "notify",
                "target": self.recipients,
                "status": "success",
                "notification_type": notification_type,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "action": "notify",
                "target": self.recipients,
                "status": "failed",
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    def _create_email_body(self, event_data: dict, notification_type: str) -> str:
        """Create HTML email body."""
        return f"""
        <html>
        <body>
            <h2>Security Alert</h2>
            <p><strong>Type:</strong> {notification_type}</p>
            <p><strong>Severity:</strong> {event_data.get('severity', 'unknown')}</p>
            <p><strong>Description:</strong> {event_data.get('description', 'No description')}</p>
            <p><strong>Timestamp:</strong> {event_data.get('timestamp', 'Unknown')}</p>
            
            <h3>Details</h3>
            <pre>{json.dumps(event_data, indent=2)}</pre>
        </body>
        </html>
        """
```

## Error Handling and Recovery

### Comprehensive Error Handling

```python
class RobustResponder(Responder):
    """Responder with comprehensive error handling and recovery."""
    
    def run(self) -> None:
        """Main execution with error handling."""
        try:
            # Validate input
            self._validate_input()
            
            # Execute response
            result = self._execute_response()
            
            # Validate result
            self._validate_result(result)
            
            # Report success
            self.report(result)
            
        except ValidationError as e:
            self._handle_validation_error(e)
        except ExecutionError as e:
            self._handle_execution_error(e)
        except Exception as e:
            self._handle_unexpected_error(e)
    
    def _handle_validation_error(self, error: ValidationError) -> None:
        """Handle input validation errors."""
        error_result = {
            "action": "validate",
            "status": "failed",
            "error": str(error),
            "error_type": "validation",
            "timestamp": self._get_timestamp()
        }
        self.report(error_result)
    
    def _handle_execution_error(self, error: ExecutionError) -> None:
        """Handle execution errors with retry logic."""
        if self._should_retry(error):
            try:
                result = self._retry_execution()
                self.report(result)
            except Exception as retry_error:
                self._handle_retry_failure(retry_error)
        else:
            self._handle_execution_failure(error)
    
    def _should_retry(self, error: ExecutionError) -> bool:
        """Determine if operation should be retried."""
        retryable_errors = [
            "timeout",
            "connection_error",
            "temporary_failure"
        ]
        return any(err_type in str(error).lower() for err_type in retryable_errors)
    
    def _retry_execution(self) -> dict:
        """Retry the execution with exponential backoff."""
        import time
        
        max_retries = 3
        base_delay = 1
        
        for attempt in range(max_retries):
            try:
                return self._execute_response()
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
        
        raise ExecutionError("Max retries exceeded")
```

### State Management

```python
import json
from pathlib import Path

class StatefulResponder(Responder):
    """Responder that maintains state between executions."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.state_file = Path(self.get_param("config.state_file", "/tmp/responder_state.json"))
        self.state = self._load_state()
    
    def _load_state(self) -> dict:
        """Load state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        
        return {
            "processed_items": set(),
            "failed_items": set(),
            "last_cleanup": None,
            "statistics": {
                "total_processed": 0,
                "successful": 0,
                "failed": 0
            }
        }
    
    def _save_state(self) -> None:
        """Save state to file."""
        try:
            # Convert sets to lists for JSON serialization
            state_to_save = {
                "processed_items": list(self.state["processed_items"]),
                "failed_items": list(self.state["failed_items"]),
                "last_cleanup": self.state["last_cleanup"],
                "statistics": self.state["statistics"]
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(state_to_save, f, indent=2)
        except Exception as e:
            print(f"Failed to save state: {e}")
    
    def run(self) -> None:
        """Main execution with state management."""
        try:
            observable = self.get_data()
            
            # Check if already processed
            if observable in self.state["processed_items"]:
                self.report({
                    "action": "skip",
                    "target": observable,
                    "status": "already_processed",
                    "timestamp": self._get_timestamp()
                })
                return
            
            # Execute response
            result = self._execute_response(observable)
            
            # Update state
            self.state["processed_items"].add(observable)
            self.state["statistics"]["total_processed"] += 1
            
            if result["status"] == "success":
                self.state["statistics"]["successful"] += 1
            else:
                self.state["statistics"]["failed"] += 1
                self.state["failed_items"].add(observable)
            
            # Save state
            self._save_state()
            
            # Report result
            self.report(result)
            
        except Exception as e:
            self.state["statistics"]["failed"] += 1
            self.state["failed_items"].add(observable)
            self._save_state()
            raise
```

## Testing Responders

### Unit Testing

```python
import pytest
from unittest.mock import Mock, patch, MagicMock
from ip_block_responder import IPBlockResponder

class TestIPBlockResponder:
    def test_block_malicious_ip(self):
        """Test blocking a malicious IP."""
        input_data = {
            "dataType": "ip",
            "data": "1.2.3.4",
            "config": {
                "firewall_api_url": "https://api.firewall.com",
                "api_key": "test_key"
            }
        }
        
        responder = IPBlockResponder(input_data)
        
        # Mock the firewall API
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"id": "rule_123"}
            mock_post.return_value = mock_response
            
            # Mock threat intelligence checks
            with patch.object(responder, '_is_critical_threat', return_value=True):
                result = responder._block_ip("1.2.3.4", {
                    "should_block": True,
                    "duration": "permanent",
                    "priority": "high",
                    "reason": "critical_threat"
                })
                
                assert result["action"] == "block"
                assert result["status"] == "success"
                assert result["rule_id"] == "rule_123"
    
    def test_api_failure_handling(self):
        """Test handling of API failures."""
        input_data = {
            "dataType": "ip",
            "data": "1.2.3.4",
            "config": {
                "firewall_api_url": "https://api.firewall.com",
                "api_key": "test_key"
            }
        }
        
        responder = IPBlockResponder(input_data)
        
        # Mock API failure
        with patch('requests.post') as mock_post:
            mock_post.side_effect = requests.RequestException("Connection failed")
            
            result = responder._block_ip("1.2.3.4", {
                "should_block": True,
                "duration": "24h",
                "priority": "medium",
                "reason": "malicious"
            })
            
            assert result["action"] == "block"
            assert result["status"] == "failed"
            assert "Connection failed" in result["error"]
    
    def test_monitoring_safe_ip(self):
        """Test monitoring a safe IP."""
        input_data = {
            "dataType": "ip",
            "data": "8.8.8.8",
            "config": {
                "firewall_api_url": "https://api.firewall.com",
                "api_key": "test_key"
            }
        }
        
        responder = IPBlockResponder(input_data)
        
        # Mock safe IP checks
        with patch.object(responder, '_is_critical_threat', return_value=False), \
             patch.object(responder, '_is_malicious', return_value=False), \
             patch.object(responder, '_is_suspicious', return_value=False):
            
            result = responder._monitor_ip("8.8.8.8")
            
            assert result["action"] == "monitor"
            assert result["status"] == "active"
```

### Integration Testing

```python
def test_full_responder_workflow(self):
    """Test complete responder workflow."""
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "config": {
            "firewall_api_url": "https://api.firewall.com",
            "api_key": "test_key"
        }
    }
    
    responder = IPBlockResponder(input_data)
    
    # Mock all dependencies
    with patch('requests.post') as mock_post, \
         patch.object(responder, '_is_critical_threat', return_value=True):
        
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "rule_123"}
        mock_post.return_value = mock_response
        
        # Run responder
        result = responder.report({
            "action": "block",
            "target": "1.2.3.4",
            "status": "success",
            "rule_id": "rule_123"
        })
        
        # Verify output structure
        assert result["success"] is True
        assert result["full"]["action"] == "block"
        assert result["full"]["status"] == "success"
```

## Advanced Patterns

### 1. Chain of Responsibility

```python
from abc import ABC, abstractmethod

class ResponseHandler(ABC):
    """Base class for response handlers."""
    
    def __init__(self, next_handler=None):
        self.next_handler = next_handler
    
    @abstractmethod
    def can_handle(self, event: dict) -> bool:
        """Check if this handler can process the event."""
        pass
    
    @abstractmethod
    def handle(self, event: dict) -> dict:
        """Handle the event."""
        pass
    
    def process(self, event: dict) -> dict:
        """Process event through the chain."""
        if self.can_handle(event):
            return self.handle(event)
        elif self.next_handler:
            return self.next_handler.process(event)
        else:
            return {"status": "unhandled", "error": "No handler found"}

class CriticalThreatHandler(ResponseHandler):
    """Handler for critical threats."""
    
    def can_handle(self, event: dict) -> bool:
        return event.get("severity") == "critical"
    
    def handle(self, event: dict) -> dict:
        # Immediate blocking and alerting
        return {
            "action": "immediate_block",
            "status": "success",
            "priority": "critical"
        }

class MaliciousHandler(ResponseHandler):
    """Handler for malicious items."""
    
    def can_handle(self, event: dict) -> bool:
        return event.get("verdict") == "malicious"
    
    def handle(self, event: dict) -> dict:
        # Standard blocking
        return {
            "action": "block",
            "status": "success",
            "priority": "high"
        }

class SuspiciousHandler(ResponseHandler):
    """Handler for suspicious items."""
    
    def can_handle(self, event: dict) -> bool:
        return event.get("verdict") == "suspicious"
    
    def handle(self, event: dict) -> dict:
        # Monitoring and investigation
        return {
            "action": "monitor",
            "status": "success",
            "priority": "medium"
        }

class ChainResponder(Responder):
    """Responder using chain of responsibility pattern."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.handler_chain = self._build_handler_chain()
    
    def _build_handler_chain(self) -> ResponseHandler:
        """Build the handler chain."""
        suspicious_handler = SuspiciousHandler()
        malicious_handler = MaliciousHandler(suspicious_handler)
        critical_handler = CriticalThreatHandler(malicious_handler)
        return critical_handler
    
    def run(self) -> None:
        """Process event through handler chain."""
        event_data = self.get_data()
        result = self.handler_chain.process(event_data)
        self.report(result)
```

### 2. Observer Pattern

```python
from typing import List, Callable

class ResponseObserver:
    """Observer for response events."""
    
    def __init__(self, name: str):
        self.name = name
    
    def on_response_success(self, response: dict) -> None:
        """Called when response succeeds."""
        print(f"{self.name}: Response succeeded: {response['action']}")
    
    def on_response_failure(self, response: dict) -> None:
        """Called when response fails."""
        print(f"{self.name}: Response failed: {response['error']}")

class ObservableResponder(Responder):
    """Responder that notifies observers of events."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.observers: List[ResponseObserver] = []
    
    def add_observer(self, observer: ResponseObserver) -> None:
        """Add an observer."""
        self.observers.append(observer)
    
    def remove_observer(self, observer: ResponseObserver) -> None:
        """Remove an observer."""
        if observer in self.observers:
            self.observers.remove(observer)
    
    def notify_observers(self, event: str, response: dict) -> None:
        """Notify all observers of an event."""
        for observer in self.observers:
            if event == "success":
                observer.on_response_success(response)
            elif event == "failure":
                observer.on_response_failure(response)
    
    def run(self) -> None:
        """Main execution with observer notifications."""
        try:
            result = self._execute_response()
            self.notify_observers("success", result)
            self.report(result)
        except Exception as e:
            error_result = {
                "action": "error",
                "status": "failed",
                "error": str(e)
            }
            self.notify_observers("failure", error_result)
            self.report(error_result)
```

### 3. Circuit Breaker Pattern

```python
import time
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Circuit breaker for external service calls."""
    
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset."""
        return (time.time() - self.last_failure_time) >= self.timeout
    
    def _on_success(self) -> None:
        """Handle successful call."""
        self.failure_count = 0
        self.state = CircuitState.CLOSED
    
    def _on_failure(self) -> None:
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

class ResilientResponder(Responder):
    """Responder with circuit breaker protection."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.circuit_breaker = CircuitBreaker()
    
    def run(self) -> None:
        """Main execution with circuit breaker protection."""
        try:
            result = self.circuit_breaker.call(self._execute_response)
            self.report(result)
        except Exception as e:
            self.report({
                "action": "error",
                "status": "failed",
                "error": str(e),
                "circuit_state": self.circuit_breaker.state.value
            })
```

## Best Practices Summary

1. **Idempotency**: Ensure responses can be safely repeated
2. **Error Handling**: Implement comprehensive error handling
3. **State Management**: Maintain state when necessary
4. **Testing**: Write thorough tests for all scenarios
5. **Monitoring**: Add metrics and logging
6. **Recovery**: Implement retry and recovery mechanisms
7. **Security**: Validate all inputs and outputs
8. **Performance**: Optimize for your use case

## Next Steps

- [File Processing](../tutorials/file-processing.md) - Advanced file handling
- [Advanced Features](../tutorials/advanced-features.md) - Advanced techniques
- [Examples](../examples/incident-response.md) - Real-world examples
- [API Reference](../reference/api/responder.md) - Complete API documentation
