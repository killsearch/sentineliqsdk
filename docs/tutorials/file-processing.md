---
title: File Processing
---

# File Processing

This guide covers advanced file processing techniques with the SentinelIQ SDK, including malware analysis, file extraction, and handling various file formats.

## Table of Contents

- [File Input Handling](#file-input-handling)
- [File Analysis Patterns](#file-analysis-patterns)
- [File Extraction](#file-extraction)
- [Malware Analysis](#malware-analysis)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)

## File Input Handling

### Basic File Processing

```python
from pathlib import Path
from sentineliqsdk import Analyzer

class FileAnalyzer(Analyzer):
    """Base file analyzer with common file handling patterns."""
    
    def run(self) -> None:
        if self.data_type == "file":
            file_path = self.get_param("file")
            result = self._analyze_file(file_path)
        else:
            self.error(f"Unsupported data type: {self.data_type}")
        
        self.report(result)
    
    def _analyze_file(self, file_path: str) -> dict:
        """Analyze a file and return results."""
        # Validate file exists
        if not Path(file_path).exists():
            self.error(f"File not found: {file_path}")
        
        # Get file information
        file_info = self._get_file_info(file_path)
        
        # Perform analysis based on file type
        analysis = self._analyze_by_type(file_path, file_info)
        
        # Build comprehensive report
        return self._build_file_report(file_path, file_info, analysis)
    
    def _get_file_info(self, file_path: str) -> dict:
        """Get basic file information."""
        path = Path(file_path)
        stat = path.stat()
        
        return {
            "filename": path.name,
            "size": stat.st_size,
            "created": stat.st_ctime,
            "modified": stat.st_mtime,
            "extension": path.suffix.lower(),
            "mime_type": self._detect_mime_type(file_path)
        }
    
    def _detect_mime_type(self, file_path: str) -> str:
        """Detect MIME type of file."""
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or "application/octet-stream"
```

### File Type Detection

```python
import magic
import hashlib
from pathlib import Path

class FileTypeAnalyzer(Analyzer):
    """Analyzer that detects file types and performs type-specific analysis."""
    
    def _analyze_by_type(self, file_path: str, file_info: dict) -> dict:
        """Analyze file based on its type."""
        mime_type = file_info["mime_type"]
        extension = file_info["extension"]
        
        # Determine file category
        if mime_type.startswith("text/"):
            return self._analyze_text_file(file_path, file_info)
        elif mime_type.startswith("image/"):
            return self._analyze_image_file(file_path, file_info)
        elif mime_type in ["application/pdf", "application/msword"]:
            return self._analyze_document_file(file_path, file_info)
        elif extension in [".exe", ".dll", ".sys"]:
            return self._analyze_executable_file(file_path, file_info)
        elif extension in [".zip", ".rar", ".7z"]:
            return self._analyze_archive_file(file_path, file_info)
        else:
            return self._analyze_unknown_file(file_path, file_info)
    
    def _analyze_text_file(self, file_path: str, file_info: dict) -> dict:
        """Analyze text files for IOCs and suspicious content."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract IOCs using the built-in extractor
            from sentineliqsdk import Extractor
            extractor = Extractor()
            iocs = extractor.check_iterable(content)
            
            # Check for suspicious patterns
            suspicious_patterns = self._check_suspicious_patterns(content)
            
            return {
                "file_type": "text",
                "iocs_found": iocs,
                "suspicious_patterns": suspicious_patterns,
                "content_length": len(content),
                "verdict": "suspicious" if suspicious_patterns else "safe"
            }
            
        except Exception as e:
            return {
                "file_type": "text",
                "error": str(e),
                "verdict": "error"
            }
    
    def _analyze_executable_file(self, file_path: str, file_info: dict) -> dict:
        """Analyze executable files for malware indicators."""
        try:
            # Calculate file hashes
            hashes = self._calculate_hashes(file_path)
            
            # Check against malware databases
            malware_check = self._check_malware_databases(hashes["sha256"])
            
            # Analyze PE headers if it's a Windows executable
            pe_analysis = self._analyze_pe_headers(file_path)
            
            return {
                "file_type": "executable",
                "hashes": hashes,
                "malware_check": malware_check,
                "pe_analysis": pe_analysis,
                "verdict": "malicious" if malware_check["is_malware"] else "safe"
            }
            
        except Exception as e:
            return {
                "file_type": "executable",
                "error": str(e),
                "verdict": "error"
            }
    
    def _analyze_archive_file(self, file_path: str, file_info: dict) -> dict:
        """Analyze archive files and extract contents."""
        try:
            # Extract archive contents
            extracted_files = self._extract_archive(file_path)
            
            # Analyze extracted files
            file_analyses = []
            for extracted_file in extracted_files:
                analysis = self._analyze_extracted_file(extracted_file)
                file_analyses.append(analysis)
            
            # Check for suspicious files in archive
            suspicious_files = [f for f in file_analyses if f.get("verdict") == "suspicious"]
            
            return {
                "file_type": "archive",
                "extracted_files": len(extracted_files),
                "file_analyses": file_analyses,
                "suspicious_files": len(suspicious_files),
                "verdict": "suspicious" if suspicious_files else "safe"
            }
            
        except Exception as e:
            return {
                "file_type": "archive",
                "error": str(e),
                "verdict": "error"
            }
```

## File Analysis Patterns

### 1. Hash-Based Analysis

```python
import hashlib
import os

class HashAnalyzer(Analyzer):
    """Analyzer that performs hash-based file analysis."""
    
    def _calculate_hashes(self, file_path: str) -> dict:
        """Calculate multiple hash types for a file."""
        hashes = {}
        file_size = os.path.getsize(file_path)
        
        # Initialize hash objects
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        # Read file in chunks to handle large files
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "size": file_size
        }
    
    def _check_malware_databases(self, sha256: str) -> dict:
        """Check file hash against malware databases."""
        # In production, this would query real malware databases
        known_malware_hashes = {
            "a1b2c3d4e5f6...": "Trojan.Win32.Malware",
            "f6e5d4c3b2a1...": "Ransomware.CryptoLocker"
        }
        
        if sha256 in known_malware_hashes:
            return {
                "is_malware": True,
                "malware_family": known_malware_hashes[sha256],
                "confidence": "high"
            }
        else:
            return {
                "is_malware": False,
                "malware_family": None,
                "confidence": "low"
            }
```

### 2. Content-Based Analysis

```python
import re
import base64

class ContentAnalyzer(Analyzer):
    """Analyzer that examines file content for suspicious patterns."""
    
    def _check_suspicious_patterns(self, content: str) -> list:
        """Check content for suspicious patterns."""
        patterns = []
        
        # Check for base64 encoded content
        if self._has_base64_content(content):
            patterns.append({
                "type": "base64_encoded",
                "severity": "medium",
                "description": "File contains base64 encoded content"
            })
        
        # Check for suspicious strings
        suspicious_strings = self._find_suspicious_strings(content)
        if suspicious_strings:
            patterns.append({
                "type": "suspicious_strings",
                "severity": "high",
                "strings": suspicious_strings,
                "description": "File contains suspicious strings"
            })
        
        # Check for obfuscated code
        if self._has_obfuscated_code(content):
            patterns.append({
                "type": "obfuscated_code",
                "severity": "high",
                "description": "File contains obfuscated code"
            })
        
        # Check for network indicators
        network_indicators = self._find_network_indicators(content)
        if network_indicators:
            patterns.append({
                "type": "network_indicators",
                "severity": "medium",
                "indicators": network_indicators,
                "description": "File contains network indicators"
            })
        
        return patterns
    
    def _has_base64_content(self, content: str) -> bool:
        """Check if content contains base64 encoded data."""
        # Look for base64 patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, content)
        
        # Check if matches are actually base64
        for match in matches[:5]:  # Check first 5 matches
            try:
                base64.b64decode(match)
                return True
            except:
                continue
        
        return False
    
    def _find_suspicious_strings(self, content: str) -> list:
        """Find suspicious strings in content."""
        suspicious_patterns = [
            r'CreateProcess',
            r'WriteProcessMemory',
            r'VirtualAlloc',
            r'LoadLibrary',
            r'GetProcAddress',
            r'RegOpenKey',
            r'RegSetValue',
            r'DeleteFile',
            r'MoveFile',
            r'CopyFile'
        ]
        
        found_strings = []
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_strings.extend(matches)
        
        return list(set(found_strings))
    
    def _has_obfuscated_code(self, content: str) -> bool:
        """Check if content contains obfuscated code."""
        # Look for common obfuscation patterns
        obfuscation_patterns = [
            r'eval\s*\(',
            r'unescape\s*\(',
            r'String\.fromCharCode',
            r'\\x[0-9a-fA-F]{2}',
            r'\\[0-7]{3}'
        ]
        
        for pattern in obfuscation_patterns:
            if re.search(pattern, content):
                return True
        
        return False
    
    def _find_network_indicators(self, content: str) -> list:
        """Find network indicators in content."""
        # IP address pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, content)
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        
        # Domain pattern
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b'
        domains = re.findall(domain_pattern, content)
        
        return {
            "ips": list(set(ips)),
            "urls": list(set(urls)),
            "domains": list(set(domains))
        }
```

### 3. PE File Analysis

```python
import struct

class PEAnalyzer(Analyzer):
    """Analyzer for Windows PE (Portable Executable) files."""
    
    def _analyze_pe_headers(self, file_path: str) -> dict:
        """Analyze PE file headers for suspicious characteristics."""
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return {"error": "Not a valid PE file"}
                
                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                
                # Read PE header
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return {"error": "Invalid PE signature"}
                
                # Read COFF header
                coff_header = f.read(20)
                machine, num_sections, timestamp, ptr_to_symbol_table, num_symbols, size_of_optional_header, characteristics = struct.unpack('<HHIIIII', coff_header)
                
                # Read optional header
                optional_header = f.read(size_of_optional_header)
                
                # Analyze characteristics
                analysis = {
                    "machine_type": self._get_machine_type(machine),
                    "num_sections": num_sections,
                    "timestamp": timestamp,
                    "characteristics": self._analyze_characteristics(characteristics),
                    "suspicious_indicators": []
                }
                
                # Check for suspicious characteristics
                if characteristics & 0x2000:  # IMAGE_FILE_DLL
                    analysis["suspicious_indicators"].append("DLL file")
                
                if characteristics & 0x0002:  # IMAGE_FILE_EXECUTABLE_IMAGE
                    analysis["suspicious_indicators"].append("Executable file")
                
                # Analyze sections
                sections = self._analyze_sections(f, num_sections)
                analysis["sections"] = sections
                
                return analysis
                
        except Exception as e:
            return {"error": str(e)}
    
    def _get_machine_type(self, machine: int) -> str:
        """Get machine type from PE header."""
        machine_types = {
            0x014c: "x86",
            0x8664: "x64",
            0x01c0: "ARM",
            0xaa64: "ARM64"
        }
        return machine_types.get(machine, f"Unknown (0x{machine:04x})")
    
    def _analyze_characteristics(self, characteristics: int) -> list:
        """Analyze PE file characteristics."""
        char_flags = []
        
        if characteristics & 0x0001:
            char_flags.append("RELOCS_STRIPPED")
        if characteristics & 0x0002:
            char_flags.append("EXECUTABLE_IMAGE")
        if characteristics & 0x0004:
            char_flags.append("LINE_NUMS_STRIPPED")
        if characteristics & 0x0008:
            char_flags.append("LOCAL_SYMS_STRIPPED")
        if characteristics & 0x0010:
            char_flags.append("AGGRESSIVE_WS_TRIM")
        if characteristics & 0x0020:
            char_flags.append("LARGE_ADDRESS_AWARE")
        if characteristics & 0x0080:
            char_flags.append("BYTES_REVERSED_LO")
        if characteristics & 0x0100:
            char_flags.append("32BIT_MACHINE")
        if characteristics & 0x0200:
            char_flags.append("DEBUG_STRIPPED")
        if characteristics & 0x0400:
            char_flags.append("REMOVABLE_RUN_FROM_SWAP")
        if characteristics & 0x0800:
            char_flags.append("NET_RUN_FROM_SWAP")
        if characteristics & 0x1000:
            char_flags.append("SYSTEM")
        if characteristics & 0x2000:
            char_flags.append("DLL")
        if characteristics & 0x4000:
            char_flags.append("UP_SYSTEM_ONLY")
        if characteristics & 0x8000:
            char_flags.append("BYTES_REVERSED_HI")
        
        return char_flags
    
    def _analyze_sections(self, file_handle, num_sections: int) -> list:
        """Analyze PE file sections."""
        sections = []
        
        for i in range(num_sections):
            section_header = file_handle.read(40)
            if len(section_header) < 40:
                break
            
            name, virtual_size, virtual_address, size_of_raw_data, ptr_to_raw_data, ptr_to_relocs, ptr_to_line_nums, num_relocs, num_line_nums, characteristics = struct.unpack('<8sIIIIIIHHI', section_header)
            
            section_info = {
                "name": name.decode('ascii', errors='ignore').rstrip('\x00'),
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "characteristics": characteristics,
                "suspicious": False
            }
            
            # Check for suspicious section characteristics
            if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                section_info["suspicious"] = True
                section_info["suspicious_reason"] = "Executable section"
            
            if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
                if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                    section_info["suspicious"] = True
                    section_info["suspicious_reason"] = "Readable and writable section"
            
            sections.append(section_info)
        
        return sections
```

## File Extraction

### Archive Extraction

```python
import zipfile
import tarfile
import rarfile
from pathlib import Path
import tempfile
import shutil

class ArchiveExtractor(Analyzer):
    """Analyzer that extracts and analyzes archive files."""
    
    def _extract_archive(self, file_path: str) -> list:
        """Extract archive and return list of extracted files."""
        extracted_files = []
        temp_dir = tempfile.mkdtemp()
        
        try:
            file_path_obj = Path(file_path)
            extension = file_path_obj.suffix.lower()
            
            if extension == '.zip':
                extracted_files = self._extract_zip(file_path, temp_dir)
            elif extension == '.tar':
                extracted_files = self._extract_tar(file_path, temp_dir)
            elif extension == '.rar':
                extracted_files = self._extract_rar(file_path, temp_dir)
            else:
                raise ValueError(f"Unsupported archive format: {extension}")
            
            return extracted_files
            
        except Exception as e:
            # Clean up on error
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise e
    
    def _extract_zip(self, file_path: str, extract_dir: str) -> list:
        """Extract ZIP file."""
        extracted_files = []
        
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                # Skip directories
                if member.endswith('/'):
                    continue
                
                # Extract file
                zip_ref.extract(member, extract_dir)
                extracted_path = Path(extract_dir) / member
                extracted_files.append(str(extracted_path))
        
        return extracted_files
    
    def _extract_tar(self, file_path: str, extract_dir: str) -> list:
        """Extract TAR file."""
        extracted_files = []
        
        with tarfile.open(file_path, 'r') as tar_ref:
            for member in tar_ref.getmembers():
                # Skip directories
                if member.isdir():
                    continue
                
                # Extract file
                tar_ref.extract(member, extract_dir)
                extracted_path = Path(extract_dir) / member.name
                extracted_files.append(str(extracted_path))
        
        return extracted_files
    
    def _extract_rar(self, file_path: str, extract_dir: str) -> list:
        """Extract RAR file."""
        extracted_files = []
        
        with rarfile.RarFile(file_path, 'r') as rar_ref:
            for member in rar_ref.namelist():
                # Skip directories
                if member.endswith('/'):
                    continue
                
                # Extract file
                rar_ref.extract(member, extract_dir)
                extracted_path = Path(extract_dir) / member
                extracted_files.append(str(extracted_path))
        
        return extracted_files
    
    def _analyze_extracted_file(self, file_path: str) -> dict:
        """Analyze an extracted file."""
        try:
            file_info = self._get_file_info(file_path)
            
            # Basic analysis
            analysis = {
                "filename": file_info["filename"],
                "size": file_info["size"],
                "mime_type": file_info["mime_type"],
                "verdict": "safe"
            }
            
            # Check for suspicious characteristics
            if file_info["extension"] in [".exe", ".dll", ".sys"]:
                analysis["verdict"] = "suspicious"
                analysis["reason"] = "Executable file in archive"
            
            # Check file size
            if file_info["size"] > 100 * 1024 * 1024:  # 100MB
                analysis["verdict"] = "suspicious"
                analysis["reason"] = "Large file in archive"
            
            return analysis
            
        except Exception as e:
            return {
                "filename": Path(file_path).name,
                "error": str(e),
                "verdict": "error"
            }
```

### Embedded File Extraction

```python
import re
import base64
import binascii

class EmbeddedFileExtractor(Analyzer):
    """Analyzer that extracts embedded files from various formats."""
    
    def _extract_embedded_files(self, file_path: str) -> list:
        """Extract embedded files from the main file."""
        embedded_files = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract base64 encoded files
            base64_files = self._extract_base64_files(content)
            embedded_files.extend(base64_files)
            
            # Extract hex encoded files
            hex_files = self._extract_hex_files(content)
            embedded_files.extend(hex_files)
            
            # Extract files from specific formats
            if file_path.endswith('.pdf'):
                pdf_files = self._extract_pdf_attachments(file_path)
                embedded_files.extend(pdf_files)
            
            return embedded_files
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def _extract_base64_files(self, content: bytes) -> list:
        """Extract base64 encoded files from content."""
        embedded_files = []
        
        # Find base64 patterns
        base64_pattern = rb'[A-Za-z0-9+/]{100,}={0,2}'
        matches = re.findall(base64_pattern, content)
        
        for i, match in enumerate(matches):
            try:
                # Decode base64
                decoded = base64.b64decode(match)
                
                # Check if it looks like a file
                if self._is_likely_file(decoded):
                    embedded_files.append({
                        "type": "base64",
                        "index": i,
                        "data": decoded,
                        "size": len(decoded)
                    })
            except:
                continue
        
        return embedded_files
    
    def _extract_hex_files(self, content: bytes) -> list:
        """Extract hex encoded files from content."""
        embedded_files = []
        
        # Find hex patterns
        hex_pattern = rb'[0-9a-fA-F]{200,}'
        matches = re.findall(hex_pattern, content)
        
        for i, match in enumerate(matches):
            try:
                # Decode hex
                decoded = binascii.unhexlify(match)
                
                # Check if it looks like a file
                if self._is_likely_file(decoded):
                    embedded_files.append({
                        "type": "hex",
                        "index": i,
                        "data": decoded,
                        "size": len(decoded)
                    })
            except:
                continue
        
        return embedded_files
    
    def _is_likely_file(self, data: bytes) -> bool:
        """Check if data looks like a file."""
        if len(data) < 100:
            return False
        
        # Check for common file signatures
        file_signatures = [
            b'\x50\x4B\x03\x04',  # ZIP
            b'\x50\x4B\x05\x06',  # ZIP (empty)
            b'\x50\x4B\x07\x08',  # ZIP (spanned)
            b'\x89PNG\r\n\x1a\n',  # PNG
            b'\xFF\xD8\xFF',      # JPEG
            b'GIF87a',            # GIF
            b'GIF89a',            # GIF
            b'BM',                # BMP
            b'%PDF',              # PDF
            b'MZ',                # PE/EXE
            b'\x7fELF',           # ELF
        ]
        
        for signature in file_signatures:
            if data.startswith(signature):
                return True
        
        return False
```

## Malware Analysis

### Static Analysis

```python
import yara
import pefile

class MalwareAnalyzer(Analyzer):
    """Comprehensive malware analyzer using static analysis techniques."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.yara_rules = self._load_yara_rules()
    
    def _load_yara_rules(self) -> yara.Rules:
        """Load YARA rules for malware detection."""
        try:
            # In production, load from file or database
            rules_source = """
            rule Malware_Generic {
                strings:
                    $s1 = "CreateProcess" ascii
                    $s2 = "WriteProcessMemory" ascii
                    $s3 = "VirtualAlloc" ascii
                condition:
                    2 of them
            }
            
            rule Ransomware {
                strings:
                    $s1 = "encrypt" ascii
                    $s2 = "decrypt" ascii
                    $s3 = "ransom" ascii
                condition:
                    2 of them
            }
            """
            
            return yara.compile(source=rules_source)
        except Exception as e:
            print(f"Failed to load YARA rules: {e}")
            return None
    
    def _analyze_malware(self, file_path: str) -> dict:
        """Perform comprehensive malware analysis."""
        analysis = {
            "file_path": file_path,
            "yara_matches": [],
            "pe_analysis": {},
            "behavioral_indicators": [],
            "verdict": "safe",
            "confidence": "low"
        }
        
        # YARA rule matching
        if self.yara_rules:
            yara_matches = self._run_yara_rules(file_path)
            analysis["yara_matches"] = yara_matches
        
        # PE file analysis
        if file_path.endswith(('.exe', '.dll', '.sys')):
            pe_analysis = self._analyze_pe_file(file_path)
            analysis["pe_analysis"] = pe_analysis
        
        # Behavioral indicators
        behavioral_indicators = self._analyze_behavioral_indicators(file_path)
        analysis["behavioral_indicators"] = behavioral_indicators
        
        # Determine final verdict
        analysis["verdict"], analysis["confidence"] = self._determine_verdict(analysis)
        
        return analysis
    
    def _run_yara_rules(self, file_path: str) -> list:
        """Run YARA rules against the file."""
        matches = []
        
        try:
            if self.yara_rules:
                yara_matches = self.yara_rules.match(file_path)
                for match in yara_matches:
                    matches.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [str(s) for s in match.strings]
                    })
        except Exception as e:
            matches.append({"error": str(e)})
        
        return matches
    
    def _analyze_pe_file(self, file_path: str) -> dict:
        """Analyze PE file for malware characteristics."""
        try:
            pe = pefile.PE(file_path)
            
            analysis = {
                "sections": [],
                "imports": [],
                "exports": [],
                "suspicious_characteristics": []
            }
            
            # Analyze sections
            for section in pe.sections:
                section_info = {
                    "name": section.Name.decode('ascii', errors='ignore').rstrip('\x00'),
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": section.Characteristics,
                    "entropy": self._calculate_entropy(section.get_data())
                }
                analysis["sections"].append(section_info)
            
            # Analyze imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('ascii', errors='ignore')
                    imports = [imp.name.decode('ascii', errors='ignore') for imp in entry.imports if imp.name]
                    analysis["imports"].append({
                        "dll": dll_name,
                        "functions": imports
                    })
            
            # Check for suspicious characteristics
            if self._has_suspicious_imports(analysis["imports"]):
                analysis["suspicious_characteristics"].append("Suspicious imports")
            
            if self._has_high_entropy_sections(analysis["sections"]):
                analysis["suspicious_characteristics"].append("High entropy sections")
            
            pe.close()
            return analysis
            
        except Exception as e:
            return {"error": str(e)}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _has_suspicious_imports(self, imports: list) -> bool:
        """Check for suspicious API imports."""
        suspicious_apis = {
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc',
            'LoadLibrary', 'GetProcAddress', 'RegOpenKey',
            'RegSetValue', 'DeleteFile', 'MoveFile', 'CopyFile',
            'FindWindow', 'SendMessage', 'SetWindowsHookEx'
        }
        
        for import_info in imports:
            for function in import_info.get("functions", []):
                if function in suspicious_apis:
                    return True
        
        return False
    
    def _has_high_entropy_sections(self, sections: list) -> bool:
        """Check for sections with high entropy (possible packed/encrypted data)."""
        for section in sections:
            if section.get("entropy", 0) > 7.0:  # High entropy threshold
                return True
        return False
    
    def _analyze_behavioral_indicators(self, file_path: str) -> list:
        """Analyze file for behavioral indicators."""
        indicators = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for network indicators
            if b'http://' in content or b'https://' in content:
                indicators.append("Network communication")
            
            # Check for file system operations
            if b'CreateFile' in content or b'DeleteFile' in content:
                indicators.append("File system operations")
            
            # Check for registry operations
            if b'RegOpenKey' in content or b'RegSetValue' in content:
                indicators.append("Registry operations")
            
            # Check for process operations
            if b'CreateProcess' in content or b'TerminateProcess' in content:
                indicators.append("Process operations")
            
        except Exception as e:
            indicators.append(f"Analysis error: {str(e)}")
        
        return indicators
    
    def _determine_verdict(self, analysis: dict) -> tuple:
        """Determine final verdict and confidence based on analysis."""
        yara_matches = analysis.get("yara_matches", [])
        suspicious_chars = analysis.get("pe_analysis", {}).get("suspicious_characteristics", [])
        behavioral_indicators = analysis.get("behavioral_indicators", [])
        
        # Calculate threat score
        threat_score = 0
        
        # YARA matches
        if yara_matches:
            threat_score += len(yara_matches) * 2
        
        # Suspicious characteristics
        threat_score += len(suspicious_chars)
        
        # Behavioral indicators
        threat_score += len(behavioral_indicators)
        
        # Determine verdict
        if threat_score >= 5:
            return "malicious", "high"
        elif threat_score >= 3:
            return "suspicious", "medium"
        elif threat_score >= 1:
            return "suspicious", "low"
        else:
            return "safe", "high"
```

## Performance Optimization

### Large File Handling

```python
import mmap
from pathlib import Path

class LargeFileAnalyzer(Analyzer):
    """Analyzer optimized for large files using memory mapping."""
    
    def _analyze_large_file(self, file_path: str) -> dict:
        """Analyze large file using memory mapping."""
        file_size = Path(file_path).stat().st_size
        
        if file_size > 100 * 1024 * 1024:  # 100MB
            return self._analyze_with_mmap(file_path)
        else:
            return self._analyze_with_standard_io(file_path)
    
    def _analyze_with_mmap(self, file_path: str) -> dict:
        """Analyze large file using memory mapping."""
        analysis = {
            "file_size": Path(file_path).stat().st_size,
            "method": "memory_mapped",
            "chunks_analyzed": 0,
            "iocs_found": [],
            "suspicious_patterns": []
        }
        
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    # Process file in chunks
                    chunk_size = 1024 * 1024  # 1MB chunks
                    offset = 0
                    
                    while offset < len(mmapped_file):
                        chunk = mmapped_file[offset:offset + chunk_size]
                        
                        # Analyze chunk
                        chunk_analysis = self._analyze_chunk(chunk, offset)
                        analysis["chunks_analyzed"] += 1
                        
                        # Merge results
                        analysis["iocs_found"].extend(chunk_analysis.get("iocs", []))
                        analysis["suspicious_patterns"].extend(chunk_analysis.get("patterns", []))
                        
                        offset += chunk_size
            
            # Deduplicate results
            analysis["iocs_found"] = list(set(analysis["iocs_found"]))
            analysis["suspicious_patterns"] = list(set(analysis["suspicious_patterns"]))
            
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
    
    def _analyze_chunk(self, chunk: bytes, offset: int) -> dict:
        """Analyze a chunk of data."""
        analysis = {
            "iocs": [],
            "patterns": []
        }
        
        # Convert to string for pattern matching
        try:
            text = chunk.decode('utf-8', errors='ignore')
            
            # Extract IOCs
            from sentineliqsdk import Extractor
            extractor = Extractor()
            iocs = extractor.check_iterable(text)
            analysis["iocs"] = [ioc["data"] for ioc in iocs]
            
            # Check for suspicious patterns
            if "CreateProcess" in text:
                analysis["patterns"].append("Process creation")
            if "WriteProcessMemory" in text:
                analysis["patterns"].append("Memory manipulation")
            if "VirtualAlloc" in text:
                analysis["patterns"].append("Memory allocation")
            
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
```

### Parallel Processing

```python
import concurrent.futures
from multiprocessing import Pool

class ParallelFileAnalyzer(Analyzer):
    """Analyzer that processes multiple files in parallel."""
    
    def _analyze_files_parallel(self, file_paths: list) -> list:
        """Analyze multiple files in parallel."""
        results = []
        
        # Use ThreadPoolExecutor for I/O bound operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Submit analysis tasks
            future_to_path = {
                executor.submit(self._analyze_single_file, path): path
                for path in file_paths
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        "file_path": path,
                        "error": str(e),
                        "verdict": "error"
                    })
        
        return results
    
    def _analyze_single_file(self, file_path: str) -> dict:
        """Analyze a single file."""
        try:
            file_info = self._get_file_info(file_path)
            analysis = self._analyze_by_type(file_path, file_info)
            return {
                "file_path": file_path,
                "analysis": analysis,
                "verdict": analysis.get("verdict", "unknown")
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "error": str(e),
                "verdict": "error"
            }
```

## Security Considerations

### Safe File Handling

```python
import os
import tempfile
import shutil
from pathlib import Path

class SecureFileAnalyzer(Analyzer):
    """Analyzer with security considerations for file handling."""
    
    def __init__(self, input_data):
        super().__init__(input_data)
        self.max_file_size = self.get_param("config.max_file_size", default=100 * 1024 * 1024)  # 100MB
        self.allowed_extensions = self.get_param("config.allowed_extensions", default=[])
        self.quarantine_dir = Path(self.get_param("config.quarantine_dir", "/tmp/quarantine"))
    
    def _validate_file_security(self, file_path: str) -> dict:
        """Validate file for security concerns."""
        validation = {
            "is_safe": True,
            "warnings": [],
            "errors": []
        }
        
        try:
            file_path_obj = Path(file_path)
            
            # Check file size
            file_size = file_path_obj.stat().st_size
            if file_size > self.max_file_size:
                validation["is_safe"] = False
                validation["errors"].append(f"File too large: {file_size} bytes")
            
            # Check file extension
            if self.allowed_extensions:
                if file_path_obj.suffix.lower() not in self.allowed_extensions:
                    validation["is_safe"] = False
                    validation["errors"].append(f"File extension not allowed: {file_path_obj.suffix}")
            
            # Check for suspicious filenames
            if self._is_suspicious_filename(file_path_obj.name):
                validation["warnings"].append("Suspicious filename detected")
            
            # Check for path traversal
            if ".." in str(file_path_obj):
                validation["is_safe"] = False
                validation["errors"].append("Path traversal detected")
            
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                validation["is_safe"] = False
                validation["errors"].append("File not readable")
            
        except Exception as e:
            validation["is_safe"] = False
            validation["errors"].append(f"Validation error: {str(e)}")
        
        return validation
    
    def _is_suspicious_filename(self, filename: str) -> bool:
        """Check if filename is suspicious."""
        suspicious_patterns = [
            r'\.exe$',
            r'\.bat$',
            r'\.cmd$',
            r'\.scr$',
            r'\.pif$',
            r'\.com$',
            r'\.vbs$',
            r'\.js$',
            r'\.jar$',
            r'\.zip$',
            r'\.rar$'
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        
        return False
    
    def _quarantine_file(self, file_path: str) -> str:
        """Move file to quarantine directory."""
        try:
            # Create quarantine directory
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate quarantine filename
            file_path_obj = Path(file_path)
            quarantine_name = f"{file_path_obj.stem}_{int(time.time())}{file_path_obj.suffix}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file
            shutil.move(file_path, quarantine_path)
            
            return str(quarantine_path)
            
        except Exception as e:
            raise Exception(f"Failed to quarantine file: {str(e)}")
    
    def _cleanup_temp_files(self, temp_files: list) -> None:
        """Clean up temporary files."""
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                print(f"Failed to clean up {temp_file}: {e}")
```

## Best Practices Summary

1. **File Validation**: Always validate file types, sizes, and permissions
2. **Memory Management**: Use memory mapping for large files
3. **Error Handling**: Implement comprehensive error handling
4. **Security**: Quarantine suspicious files and validate inputs
5. **Performance**: Use parallel processing for multiple files
6. **Cleanup**: Always clean up temporary files
7. **Logging**: Log all file operations for audit trails
8. **Sandboxing**: Consider running file analysis in sandboxed environments

## Next Steps

- [Advanced Features](../tutorials/advanced-features.md) - Advanced techniques
- [Examples](../examples/malware-analysis.md) - Real-world examples
- [API Reference](../reference/api/analyzer.md) - Complete API documentation
- [Troubleshooting](../troubleshooting/common-issues.md) - Common issues and solutions
