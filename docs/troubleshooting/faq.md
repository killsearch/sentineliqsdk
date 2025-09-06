---
title: Frequently Asked Questions
---

# Frequently Asked Questions (FAQ)

This page answers the most common questions about the SentinelIQ SDK.

## General Questions

### What is the SentinelIQ SDK?

The SentinelIQ SDK is a Python library that provides utility classes for building security analyzers and responders. It simplifies the development of threat intelligence tools, malware analysis systems, and automated response workflows.

### What Python version do I need?

The SDK requires Python 3.13 or higher. This ensures compatibility with modern Python features and provides the best performance and security.

### Is the SDK free to use?

Yes, the SDK is open source and free to use. Check the license file in the repository for specific terms.

### How do I get started?

1. Install Python 3.13+
2. Install the SDK: `pip install sentineliqsdk`
3. Follow the [Quick Start Guide](../getting-started/quick-start.md)
4. Check out the [examples](../examples/threat-intelligence.md)

## Installation Questions

### How do I install the SDK?

```bash
pip install sentineliqsdk
```

### Can I install from source?

Yes, you can install from source:

```bash
git clone https://github.com/killsearch/sentineliqsdk.git
cd sentineliqsdk
pip install -e .
```

### Do I need a virtual environment?

While not strictly required, we strongly recommend using a virtual environment to avoid dependency conflicts:

```bash
python -m venv sentineliq-env
source sentineliq-env/bin/activate  # On Windows: sentineliq-env\Scripts\activate
pip install sentineliqsdk
```

### What are the dependencies?

The SDK has zero external dependencies - it only uses Python's standard library. This makes it lightweight and easy to deploy.

## Usage Questions

### How do I create a simple analyzer?

```python
from sentineliqsdk import Analyzer

class MyAnalyzer(Analyzer):
    def run(self):
        observable = self.get_data()
        result = {"observable": observable, "verdict": "safe"}
        self.report(result)

# Use it
input_data = {"dataType": "ip", "data": "1.2.3.4"}
analyzer = MyAnalyzer(input_data)
analyzer.run()
```

### What data types are supported?

The SDK supports various observable types:
- `ip` - IP addresses
- `url` - URLs
- `domain` - Domain names
- `hash` - File hashes (MD5, SHA1, SHA256)
- `file` - File paths
- Custom types as needed

### How do I handle different input types?

```python
def run(self):
    data_type = self.data_type
    observable = self.get_data()
    
    if data_type == "ip":
        result = self._analyze_ip(observable)
    elif data_type == "url":
        result = self._analyze_url(observable)
    elif data_type == "file":
        file_path = self.get_param("file")
        result = self._analyze_file(file_path)
    else:
        self.error(f"Unsupported data type: {data_type}")
    
    self.report(result)
```

### How do I access configuration parameters?

```python
def run(self):
    # Get required parameter (exits if not found)
    api_key = self.get_param("config.api_key", message="API key required")
    
    # Get optional parameter with default
    timeout = self.get_param("config.timeout", default=30)
    
    # Get environment variable
    debug_mode = self.get_env("DEBUG", default="false")
```

### How do I handle errors?

```python
def run(self):
    try:
        result = self._perform_analysis()
        self.report(result)
    except ValidationError as e:
        self.error(f"Validation failed: {str(e)}")
    except AnalysisError as e:
        self.error(f"Analysis failed: {str(e)}")
    except Exception as e:
        self.error(f"Unexpected error: {str(e)}")
```

## Configuration Questions

### How do I configure TLP/PAP enforcement?

```python
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "tlp": 2,
    "pap": 2,
    "config": {
        "check_tlp": True,
        "max_tlp": 2,
        "check_pap": True,
        "max_pap": 2
    }
}
```

### How do I set up proxy configuration?

```python
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
```

### How do I enable auto-extraction?

```python
input_data = {
    "dataType": "ip",
    "data": "1.2.3.4",
    "config": {
        "auto_extract": True
    }
}
```

## File Processing Questions

### How do I process files?

```python
def run(self):
    if self.data_type == "file":
        file_path = self.get_param("file")
        
        # Validate file exists
        if not os.path.exists(file_path):
            self.error(f"File not found: {file_path}")
        
        # Analyze file
        result = self._analyze_file(file_path)
    else:
        self.error(f"File processing only supports 'file' data type")
    
    self.report(result)
```

### How do I handle large files?

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

### How do I extract files from archives?

```python
import zipfile
import tempfile

def extract_archive(self, archive_path):
    extracted_files = []
    temp_dir = tempfile.mkdtemp()
    
    try:
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if not member.endswith('/'):  # Skip directories
                    zip_ref.extract(member, temp_dir)
                    extracted_files.append(os.path.join(temp_dir, member))
    except Exception as e:
        self.error(f"Archive extraction failed: {str(e)}")
    
    return extracted_files
```

## API Integration Questions

### How do I integrate with external APIs?

```python
import requests

def call_external_api(self, url, params):
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        self.error(f"API call failed: {str(e)}")
```

### How do I handle API rate limiting?

```python
import time
from functools import wraps

def rate_limit(calls_per_second=1):
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

@rate_limit(calls_per_second=0.5)  # 2 seconds between calls
def call_api(self, url, params):
    return requests.get(url, params=params)
```

### How do I handle API authentication?

```python
def call_authenticated_api(self, url, api_key):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        self.error(f"Authenticated API call failed: {str(e)}")
```

## Performance Questions

### How do I improve performance?

1. **Use caching**:
   ```python
   from functools import lru_cache
   
   @lru_cache(maxsize=1000)
   def expensive_operation(self, input_data):
       # Expensive computation
       return result
   ```

2. **Use async processing**:
   ```python
   import asyncio
   import aiohttp
   
   async def analyze_async(self, observable):
       async with aiohttp.ClientSession() as session:
           tasks = [
               self._query_source1(session, observable),
               self._query_source2(session, observable)
           ]
           results = await asyncio.gather(*tasks)
           return self._combine_results(results)
   ```

3. **Process in parallel**:
   ```python
   from concurrent.futures import ThreadPoolExecutor
   
   def process_multiple(self, observables):
       with ThreadPoolExecutor(max_workers=4) as executor:
           futures = [executor.submit(self.analyze, obs) for obs in observables]
           results = [future.result() for future in futures]
       return results
   ```

### How do I monitor performance?

```python
import time
import psutil

def monitor_performance(self):
    start_time = time.time()
    start_memory = psutil.Process().memory_info().rss
    
    # Your analysis code here
    result = self._perform_analysis()
    
    end_time = time.time()
    end_memory = psutil.Process().memory_info().rss
    
    performance_info = {
        "execution_time": end_time - start_time,
        "memory_used": end_memory - start_memory,
        "peak_memory": psutil.Process().memory_info().rss
    }
    
    result["performance"] = performance_info
    return result
```

## Testing Questions

### How do I test my analyzer?

```python
import pytest
from unittest.mock import Mock, patch

def test_analyzer():
    input_data = {
        "dataType": "ip",
        "data": "1.2.3.4",
        "tlp": 2,
        "pap": 2
    }
    
    analyzer = MyAnalyzer(input_data)
    
    # Mock external dependencies
    with patch.object(analyzer, '_call_api') as mock_api:
        mock_api.return_value = {"verdict": "safe"}
        
        result = analyzer.report({"test": "success"})
        
        assert result["success"] is True
        assert result["full"]["verdict"] == "safe"
```

### How do I test with different input types?

```python
def test_multiple_input_types():
    test_cases = [
        {"dataType": "ip", "data": "8.8.8.8"},
        {"dataType": "url", "data": "https://google.com"},
        {"dataType": "domain", "data": "example.com"}
    ]
    
    for test_case in test_cases:
        analyzer = MyAnalyzer(test_case)
        result = analyzer.report({"test": "success"})
        assert result["success"] is True
```

### How do I test error handling?

```python
def test_error_handling():
    input_data = {
        "dataType": "ip",
        "data": "invalid_ip",
        "tlp": 2,
        "pap": 2
    }
    
    analyzer = MyAnalyzer(input_data)
    
    with pytest.raises(SystemExit):  # error() calls sys.exit()
        analyzer.run()
```

## Deployment Questions

### How do I deploy my analyzer?

1. **Package your analyzer**:
   ```python
   # setup.py
   from setuptools import setup, find_packages
   
   setup(
       name="my-analyzer",
       version="1.0.0",
       packages=find_packages(),
       install_requires=["sentineliqsdk>=0.1.2"],
       entry_points={
           "console_scripts": [
               "my-analyzer=my_analyzer:main",
           ],
       },
   )
   ```

2. **Build and install**:
   ```bash
   python setup.py sdist bdist_wheel
   pip install dist/my_analyzer-1.0.0-py3-none-any.whl
   ```

### How do I run in production?

```python
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Job directory mode
        job_dir = sys.argv[1]
        input_file = os.path.join(job_dir, "input", "input.json")
        
        with open(input_file, 'r') as f:
            input_data = json.load(f)
        
        analyzer = MyAnalyzer(input_data)
        analyzer.run()
    else:
        # STDIN mode
        input_data = json.load(sys.stdin)
        analyzer = MyAnalyzer(input_data)
        analyzer.run()
```

### How do I handle logging in production?

```python
import logging
import sys

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('analyzer.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

class ProductionAnalyzer(Analyzer):
    def __init__(self, input_data):
        super().__init__(input_data)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def run(self):
        self.logger.info("Starting analysis")
        try:
            result = self._perform_analysis()
            self.logger.info("Analysis completed successfully")
            self.report(result)
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            self.error(f"Analysis failed: {str(e)}")
```

## Troubleshooting Questions

### Why is my analyzer not working?

1. **Check Python version**: `python --version` (should be 3.13+)
2. **Check SDK installation**: `pip show sentineliqsdk`
3. **Check input data format**: Ensure it matches the expected structure
4. **Check error messages**: Look for specific error details
5. **Enable debug logging**: Add logging to see what's happening

### Why am I getting import errors?

1. **Check virtual environment**: Make sure you're in the correct environment
2. **Reinstall SDK**: `pip uninstall sentineliqsdk && pip install sentineliqsdk`
3. **Check Python path**: `python -c "import sys; print(sys.path)"`

### Why is my analysis slow?

1. **Check for caching opportunities**: Cache expensive operations
2. **Use async processing**: For I/O bound operations
3. **Optimize file processing**: Use memory mapping for large files
4. **Profile your code**: Use `cProfile` to find bottlenecks

### Why am I getting API errors?

1. **Check API keys**: Ensure they're valid and have proper permissions
2. **Check rate limits**: Implement rate limiting if needed
3. **Check network connectivity**: Test API endpoints manually
4. **Check error responses**: Look at the actual error messages from APIs

## Still Have Questions?

If you can't find the answer to your question:

1. **Check the documentation**: Browse through the guides and examples
2. **Search GitHub Issues**: Look for similar problems
3. **Create a new issue**: Provide detailed information about your problem
4. **Join the community**: Ask questions in discussions

Remember to include:
- Python version
- SDK version
- Complete error message
- Steps to reproduce
- Sample input data (sanitized)
- Operating system
