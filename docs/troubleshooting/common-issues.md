---
title: Common Issues
---

# Common Issues and Solutions

This guide covers common issues you might encounter when using the SentinelIQ SDK and provides solutions to resolve them.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Runtime Errors](#runtime-errors)
- [Configuration Problems](#configuration-problems)
- [Performance Issues](#performance-issues)
- [API Integration Issues](#api-integration-issues)
- [File Processing Issues](#file-processing-issues)
- [Debugging Tips](#debugging-tips)

## Installation Issues

### Python Version Compatibility

**Issue**: `ERROR: Package 'sentineliqsdk' requires a different Python: 3.12.0 not in '>=3.13,<4.0'`

**Solution**: The SDK requires Python 3.13 or higher. Upgrade your Python version:

```bash
# Using pyenv
pyenv install 3.13.0
pyenv global 3.13.0

# Using conda
conda create -n sentineliq python=3.13
conda activate sentineliq

# Using uv
uv python install 3.13
uv init --python 3.13
```

### Permission Denied During Installation

**Issue**: `ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied`

**Solution**: Use a virtual environment or install with user flag:

```bash
# Create virtual environment
python -m venv sentineliq-env
source sentineliq-env/bin/activate  # On Windows: sentineliq-env\Scripts\activate
pip install sentineliqsdk

# Or install for user only
pip install --user sentineliqsdk
```

### Import Errors

**Issue**: `ModuleNotFoundError: No module named 'sentineliqsdk'`

**Solutions**:

1. **Check virtual environment**:
   ```bash
   which python  # Should point to your virtual environment
   pip list | grep sentineliqsdk
   ```

2. **Reinstall the package**:
   ```bash
   pip uninstall sentineliqsdk
   pip install sentineliqsdk
   ```

3. **Check Python path**:
   ```python
   import sys
   print(sys.path)
   ```

## Runtime Errors

### Input Validation Errors

**Issue**: `Invalid URL format provided`

**Solution**: Validate your input data before passing it to the SDK:

```python
from urllib.parse import urlparse

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

# Use in your code
if not validate_url(observable):
    self.error("Invalid URL format provided")
```

### TLP/PAP Violations

**Issue**: `TLP is higher than allowed` or `PAP is higher than allowed`

**Solution**: Check your TLP/PAP configuration:

```python
# Check current TLP/PAP values
print(f"TLP: {self.tlp}, Max TLP: {self.max_tlp}")
print(f"PAP: {self.pap}, Max PAP: {self.max_pap}")

# Adjust configuration
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "tlp": 2,  # Lower TLP value
    "pap": 2,  # Lower PAP value
    "config": {
        "max_tlp": 3,  # Increase max TLP
        "max_pap": 3   # Increase max PAP
    }
}
```

### File Not Found Errors

**Issue**: `File not found: /path/to/file`

**Solution**: Validate file existence and permissions:

```python
import os
from pathlib import Path

def validate_file(file_path):
    path = Path(file_path)
    
    if not path.exists():
        self.error(f"File not found: {file_path}")
    
    if not path.is_file():
        self.error(f"Path is not a file: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        self.error(f"File not readable: {file_path}")
    
    return True
```

## Configuration Problems

### Missing API Keys

**Issue**: `API key required`

**Solution**: Provide API keys in configuration:

```python
# Method 1: In input data
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "config": {
        "virustotal_api_key": "your_api_key_here"
    }
}

# Method 2: Environment variables
import os
os.environ["VIRUSTOTAL_API_KEY"] = "your_api_key_here"

# Method 3: Configuration file
config = {
    "virustotal_api_key": self.get_param("config.virustotal_api_key", 
                                       message="VirusTotal API key required")
}
```

### Invalid Configuration Values

**Issue**: Configuration validation errors

**Solution**: Validate configuration values:

```python
def validate_config(self):
    """Validate configuration parameters."""
    # Check required parameters
    required_params = ["api_key", "api_url"]
    for param in required_params:
        if not self.get_param(f"config.{param}"):
            self.error(f"Required parameter missing: config.{param}")
    
    # Check parameter types
    timeout = self.get_param("config.timeout", default=30)
    if not isinstance(timeout, int) or timeout <= 0:
        self.error("config.timeout must be a positive integer")
    
    # Check parameter ranges
    max_retries = self.get_param("config.max_retries", default=3)
    if not 1 <= max_retries <= 10:
        self.error("config.max_retries must be between 1 and 10")
```

### Proxy Configuration Issues

**Issue**: Network requests failing through proxy

**Solution**: Configure proxy correctly:

```python
# In input data
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "config": {
        "proxy": {
            "http": "http://proxy.company.com:8080",
            "https": "https://proxy.company.com:8080"
        }
    }
}

# Verify proxy is set
import os
print(f"HTTP_PROXY: {os.environ.get('HTTP_PROXY')}")
print(f"HTTPS_PROXY: {os.environ.get('HTTPS_PROXY')}")
```

## Performance Issues

### Slow Analysis Performance

**Issue**: Analysis taking too long

**Solutions**:

1. **Implement caching**:
   ```python
   import time
   from functools import lru_cache
   
   class CachedAnalyzer(Analyzer):
       def __init__(self, input_data):
           super().__init__(input_data)
           self.cache = {}
           self.cache_ttl = 3600  # 1 hour
       
       def _is_cached(self, key):
           if key not in self.cache:
               return False
           return time.time() - self.cache[key]["timestamp"] < self.cache_ttl
       
       def _cache_result(self, key, result):
           self.cache[key] = {
               "result": result,
               "timestamp": time.time()
           }
   ```

2. **Use async processing**:
   ```python
   import asyncio
   import aiohttp
   
   async def analyze_async(self, observable):
       async with aiohttp.ClientSession() as session:
           tasks = [
               self._query_source1(session, observable),
               self._query_source2(session, observable),
               self._query_source3(session, observable)
           ]
           results = await asyncio.gather(*tasks)
           return self._combine_results(results)
   ```

3. **Optimize file processing**:
   ```python
   import mmap
   
   def analyze_large_file(self, file_path):
       with open(file_path, 'rb') as f:
           with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
               # Process file in chunks
               chunk_size = 1024 * 1024  # 1MB
               for i in range(0, len(mmapped_file), chunk_size):
                   chunk = mmapped_file[i:i + chunk_size]
                   self._process_chunk(chunk)
   ```

### Memory Issues

**Issue**: Out of memory errors

**Solutions**:

1. **Process files in chunks**:
   ```python
   def process_large_file(self, file_path):
       chunk_size = 1024 * 1024  # 1MB chunks
       with open(file_path, 'rb') as f:
           while True:
               chunk = f.read(chunk_size)
               if not chunk:
                   break
               self._process_chunk(chunk)
   ```

2. **Use generators**:
   ```python
   def process_data_generator(self, data):
       for item in data:
           yield self._process_item(item)
   ```

3. **Clear unused variables**:
   ```python
   def process_data(self, data):
       result = self._heavy_processing(data)
       # Clear large variables
       del data
       import gc
       gc.collect()
       return result
   ```

## API Integration Issues

### API Rate Limiting

**Issue**: `HTTP 429 Too Many Requests`

**Solution**: Implement rate limiting and retry logic:

```python
import time
import random
from functools import wraps

def rate_limit(calls_per_second=1):
    """Rate limiting decorator."""
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator

class RateLimitedAnalyzer(Analyzer):
    @rate_limit(calls_per_second=0.5)  # 2 seconds between calls
    def _call_api(self, url, params):
        # Your API call here
        pass
```

### API Authentication Failures

**Issue**: `HTTP 401 Unauthorized` or `HTTP 403 Forbidden`

**Solution**: Check authentication:

```python
def validate_api_auth(self, api_key, api_url):
    """Validate API authentication."""
    try:
        response = requests.get(
            f"{api_url}/auth/validate",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        
        if response.status_code == 401:
            self.error("Invalid API key")
        elif response.status_code == 403:
            self.error("API key lacks required permissions")
        elif response.status_code == 200:
            return True
        else:
            self.error(f"API authentication failed: {response.status_code}")
    
    except requests.RequestException as e:
        self.error(f"API authentication error: {str(e)}")
```

### Network Timeout Issues

**Issue**: `ReadTimeout` or `ConnectTimeout`

**Solution**: Implement timeout handling:

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session_with_retries(self):
    """Create requests session with retry logic."""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def call_api_with_timeout(self, url, params, timeout=30):
    """Call API with timeout and retry logic."""
    session = self.create_session_with_retries()
    
    try:
        response = session.get(url, params=params, timeout=timeout)
        return response
    except requests.Timeout:
        self.error(f"API call timed out after {timeout} seconds")
    except requests.RequestException as e:
        self.error(f"API call failed: {str(e)}")
```

## File Processing Issues

### File Permission Errors

**Issue**: `PermissionError: [Errno 13] Permission denied`

**Solution**: Check and fix file permissions:

```python
import os
import stat

def fix_file_permissions(self, file_path):
    """Fix file permissions if possible."""
    try:
        # Check current permissions
        current_perms = stat.filemode(os.stat(file_path).st_mode)
        print(f"Current permissions: {current_perms}")
        
        # Make file readable
        os.chmod(file_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        
        # Verify permissions
        if os.access(file_path, os.R_OK):
            print("File permissions fixed")
        else:
            self.error("Could not fix file permissions")
    
    except Exception as e:
        self.error(f"Permission fix failed: {str(e)}")
```

### File Lock Issues

**Issue**: `PermissionError: [Errno 13] Permission denied` (file in use)

**Solution**: Handle file locks gracefully:

```python
import time
import fcntl

def wait_for_file_unlock(self, file_path, max_wait=30):
    """Wait for file to be unlocked."""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            with open(file_path, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
        except (IOError, OSError):
            time.sleep(1)
    
    self.error(f"File locked for more than {max_wait} seconds")
```

### Large File Processing

**Issue**: Memory errors when processing large files

**Solution**: Use memory-efficient processing:

```python
import mmap

def process_large_file_efficiently(self, file_path):
    """Process large file using memory mapping."""
    try:
        with open(file_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                # Process file in chunks
                chunk_size = 1024 * 1024  # 1MB
                offset = 0
                
                while offset < len(mmapped_file):
                    chunk = mmapped_file[offset:offset + chunk_size]
                    self._process_chunk(chunk)
                    offset += chunk_size
    
    except Exception as e:
        self.error(f"Large file processing failed: {str(e)}")
```

## Debugging Tips

### Enable Debug Logging

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class DebugAnalyzer(Analyzer):
    def run(self):
        logger.debug(f"Starting analysis with input: {self.get_data()}")
        
        try:
            result = self._perform_analysis()
            logger.debug(f"Analysis completed successfully: {result}")
            self.report(result)
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            self.error(f"Analysis failed: {str(e)}")
```

### Add Debug Information to Reports

```python
def build_debug_report(self, result):
    """Add debug information to report."""
    debug_info = {
        "python_version": sys.version,
        "sdk_version": sentineliqsdk.__version__,
        "memory_usage": self._get_memory_usage(),
        "processing_time": self._get_processing_time(),
        "configuration": self._get_config_summary()
    }
    
    result["debug_info"] = debug_info
    return result

def _get_memory_usage(self):
    """Get current memory usage."""
    import psutil
    process = psutil.Process()
    return {
        "rss": process.memory_info().rss,
        "vms": process.memory_info().vms,
        "percent": process.memory_percent()
    }
```

### Test with Sample Data

```python
def test_with_sample_data(self):
    """Test analyzer with sample data."""
    test_cases = [
        {"dataType": "ip", "data": "8.8.8.8"},
        {"dataType": "url", "data": "https://google.com"},
        {"dataType": "domain", "data": "example.com"}
    ]
    
    for test_case in test_cases:
        print(f"Testing: {test_case}")
        try:
            analyzer = MyAnalyzer(test_case)
            result = analyzer.report({"test": "success"})
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error: {e}")
```

### Common Debugging Commands

```bash
# Check Python version
python --version

# Check installed packages
pip list | grep sentineliqsdk

# Check environment variables
env | grep -i proxy

# Test network connectivity
curl -I https://api.virustotal.com/vtapi/v2

# Check file permissions
ls -la /path/to/file

# Monitor memory usage
top -p $(pgrep -f python)

# Check disk space
df -h
```

## Getting Help

If you're still experiencing issues:

1. **Check the logs** for detailed error messages
2. **Search GitHub Issues** for similar problems
3. **Create a new issue** with:
   - Python version (`python --version`)
   - SDK version (`pip show sentineliqsdk`)
   - Complete error message
   - Steps to reproduce
   - Operating system
   - Sample input data (sanitized)

4. **Join the community** for discussions and support

## Prevention Tips

1. **Always use virtual environments**
2. **Validate input data** before processing
3. **Implement proper error handling**
4. **Use configuration validation**
5. **Monitor performance** and resource usage
6. **Keep dependencies updated**
7. **Test with various input types**
8. **Document your configuration**

Remember: Most issues can be resolved by checking the basics first - Python version, virtual environment, input validation, and proper error handling.
