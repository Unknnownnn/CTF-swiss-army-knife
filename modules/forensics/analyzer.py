import os
from typing import Dict, Any, List, Tuple, Optional
import binascii
import string
import re
import math
import mimetypes
import subprocess
from pathlib import Path
import json
from datetime import datetime
import zipfile
import py7zr
import rarfile
import exifread
import zlib
import gzip
import bz2
import lzma
import struct
import platform

# Handle magic import differently on Windows
if platform.system() == 'Windows':
    try:
        import magic
    except ImportError:
        # Fallback for Windows if python-magic fails
        import mimetypes
        import filetype  # This is a pure-Python alternative
        
        class MagicFallback:
            @staticmethod
            def from_file(file_path):
                kind = filetype.guess(file_path)
                if kind is None:
                    # Fallback to mimetypes if filetype fails
                    mime_type, _ = mimetypes.guess_type(file_path)
                    return mime_type or 'application/octet-stream'
                return kind.mime
                
            @staticmethod
            def Magic(mime=False):
                return MagicFallback()
        
        magic = MagicFallback()
else:
    import magic

from .external_tools import (run_steghide, run_binwalk, run_stegsolve,
                          run_zsteg, run_exiftool, run_foremost,
                          ExternalToolError)

def format_size(size: int) -> str:
    """Convert size in bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def format_results(results: Dict[str, Any]) -> str:
    """Format analysis results in a readable way"""
    output = []
    
    # File Information Section
    output.append("=== File Information ===")
    file_info = results['file_info']
    output.append(f"Size: {format_size(file_info['size'])}")
    output.append(f"MIME Type: {file_info['mime']}")
    output.append(f"File Type: {file_info['type']}")
    output.append(f"Magic Bytes (hex): {file_info['magic_bytes']}")
    if 'created' in file_info:
        output.append(f"Created: {file_info['created']}")
    if 'modified' in file_info:
        output.append(f"Modified: {file_info['modified']}")
    output.append("")
    
    # External Tools Section
    if 'external_tools' in results and results['external_tools']:
        output.append("=== External Tools Analysis ===")
        ext_tools = results['external_tools']
        
        # Binwalk results
        if 'binwalk' in ext_tools:
            output.append("\nBinwalk Analysis:")
            if 'error' in ext_tools['binwalk']:
                output.append(f"  Error: {ext_tools['binwalk']['error']}")
            elif ext_tools['binwalk']['signatures']:
                for sig in ext_tools['binwalk']['signatures'][:10]:
                    output.append(f"  {sig}")
                if len(ext_tools['binwalk']['signatures']) > 10:
                    output.append(f"  ... and {len(ext_tools['binwalk']['signatures']) - 10} more findings")
        
        # Steghide results
        if 'steghide' in ext_tools:
            output.append("\nSteghide Analysis:")
            if 'error' in ext_tools['steghide']:
                output.append(f"  Error: {ext_tools['steghide']['error']}")
            elif ext_tools['steghide']['output']:
                output.append(f"  {ext_tools['steghide']['output']}")
        
        # Zsteg results
        if 'zsteg' in ext_tools:
            output.append("\nZsteg Analysis:")
            if 'error' in ext_tools['zsteg']:
                output.append(f"  Error: {ext_tools['zsteg']['error']}")
            elif ext_tools['zsteg']['findings']:
                for finding in ext_tools['zsteg']['findings'][:10]:
                    output.append(f"  {finding}")
                if len(ext_tools['zsteg']['findings']) > 10:
                    output.append(f"  ... and {len(ext_tools['zsteg']['findings']) - 10} more findings")
        
        # Foremost results
        if 'foremost' in ext_tools:
            output.append("\nForemost Analysis:")
            if 'error' in ext_tools['foremost']:
                output.append(f"  Error: {ext_tools['foremost']['error']}")
            elif ext_tools['foremost']['extracted_files']:
                output.append("  Extracted files:")
                for file in ext_tools['foremost']['extracted_files'][:10]:
                    output.append(f"  - {os.path.basename(file)}")
                if len(ext_tools['foremost']['extracted_files']) > 10:
                    output.append(f"  ... and {len(ext_tools['foremost']['extracted_files']) - 10} more files")
        
        output.append("")
    
    # Metadata Section
    if 'metadata' in results and results['metadata']:
        output.append("=== Metadata ===")
        metadata = results['metadata']
        if 'exif' in metadata:
            output.append("EXIF Data:")
            for key, value in metadata['exif'].items():
                output.append(f"  {key}: {value}")
        if 'file_attributes' in metadata:
            output.append("\nFile Attributes:")
            for key, value in metadata['file_attributes'].items():
                output.append(f"  {key}: {value}")
        output.append("")
    
    # Compression Information
    if 'compression_info' in results and results['compression_info']['is_compressed']:
        output.append("=== Compression Analysis ===")
        comp_info = results['compression_info']
        output.append(f"Type: {comp_info['compression_type']}")
        output.append(f"Can Extract: {comp_info['can_extract']}")
        if comp_info['contents']:
            output.append("\nContents:")
            for item in comp_info['contents'][:10]:  # Show first 10 items
                output.append(f"  - {item}")
            if len(comp_info['contents']) > 10:
                output.append(f"  ... and {len(comp_info['contents']) - 10} more files")
        output.append("")
    
    # Signature Analysis
    if 'signature_analysis' in results:
        output.append("=== File Signature Analysis ===")
        sig_info = results['signature_analysis']
        output.append(f"Declared Type: {sig_info['declared_type']}")
        output.append(f"Detected Type: {sig_info['actual_type'] or 'Unknown'}")
        output.append(f"Signature Match: {sig_info['signature_match']}")
        output.append("")
    
    # Content Analysis Section
    output.append("=== Content Analysis ===")
    content = results['content_analysis']
    output.append(f"Entropy: {content['entropy']:.4f} (0-8, higher = more random)")
    if 'encoding_guess' in content:
        output.append(f"Possible Encoding: {content['encoding_guess']}")
    output.append("")
    
    # Patterns Section
    output.append("=== Detected Patterns ===")
    patterns = results['patterns']
    if patterns['ips']:
        output.append("IP Addresses:")
        for ip in patterns['ips'][:10]:  # Limit to first 10
            output.append(f"  - {ip}")
        if len(patterns['ips']) > 10:
            output.append(f"  ... and {len(patterns['ips']) - 10} more")
    
    if patterns['urls']:
        output.append("\nURLs:")
        for url in patterns['urls'][:10]:
            output.append(f"  - {url}")
        if len(patterns['urls']) > 10:
            output.append(f"  ... and {len(patterns['urls']) - 10} more")
    
    if patterns['base64']:
        output.append("\nPotential Base64 Strings:")
        for b64 in patterns['base64'][:5]:
            output.append(f"  - {b64[:60]}..." if len(b64) > 60 else f"  - {b64}")
        if len(patterns['base64']) > 5:
            output.append(f"  ... and {len(patterns['base64']) - 5} more")
    
    # Strings Section
    output.append("\n=== Interesting Strings ===")
    strings = results['strings']
    if strings:
        for s in strings[:15]:  # Show first 15 strings
            if len(s) > 60:
                output.append(f"  - {s[:57]}...")
            else:
                output.append(f"  - {s}")
        if len(strings) > 15:
            output.append(f"  ... and {len(strings) - 15} more strings")
    else:
        output.append("  No interesting strings found")
    
    return "\n".join(output)

def get_file_type(file_path: str) -> tuple[str, str]:
    """Get MIME type and file description using built-in tools"""
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = 'application/octet-stream'
    
    # Try to get file description using the 'file' command if available
    try:
        result = subprocess.run(['file', file_path], capture_output=True, text=True)
        file_type = result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        # If 'file' command is not available, provide basic info
        file_type = f"File with extension: {Path(file_path).suffix}"
    
    return mime_type, file_type

def guess_encoding(data: bytes) -> str:
    """Try to guess the encoding of the data"""
    encodings = ['utf-8', 'ascii', 'iso-8859-1', 'utf-16', 'utf-32']
    for enc in encodings:
        try:
            data.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "binary"

def is_printable(byte_data: bytes) -> bool:
    """Check if a byte string contains printable characters"""
    return all(chr(b) in string.printable for b in byte_data)

def find_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Find printable strings in binary data"""
    strings = []
    current = []
    
    for byte in data:
        if chr(byte) in string.printable:
            current.append(chr(byte))
        elif current:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
            
    if current and len(current) >= min_length:
        strings.append(''.join(current))
        
    return strings

def extract_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from various file types"""
    metadata = {}
    
    try:
        # Use exifread for images
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            if tags:
                metadata['exif'] = {str(k): str(v) for k, v in tags.items()}
        
        # Use libmagic for detailed file info
        mime = magic.Magic(mime=True)
        magic_info = magic.Magic()
        metadata['mime_type'] = mime.from_file(file_path)
        metadata['file_type'] = magic_info.from_file(file_path)
        
        # Get file attributes
        stat = os.stat(file_path)
        metadata['file_attributes'] = {
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'accessed': datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            'permissions': oct(stat.st_mode)[-3:]
        }
        
    except Exception as e:
        metadata['error'] = str(e)
    
    return metadata

def check_compression(file_path: str) -> Dict[str, Any]:
    """Check if file is compressed and try to identify compression type"""
    results = {
        'is_compressed': False,
        'compression_type': None,
        'can_extract': False,
        'contents': []
    }
    
    try:
        # Check ZIP
        if zipfile.is_zipfile(file_path):
            results['is_compressed'] = True
            results['compression_type'] = 'ZIP'
            results['can_extract'] = True
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                results['contents'] = zip_ref.namelist()
        
        # Check 7Z
        elif py7zr.is_7zfile(file_path):
            results['is_compressed'] = True
            results['compression_type'] = '7Z'
            results['can_extract'] = True
            with py7zr.SevenZipFile(file_path, 'r') as sz:
                results['contents'] = sz.getnames()
        
        # Check RAR
        elif rarfile.is_rarfile(file_path):
            results['is_compressed'] = True
            results['compression_type'] = 'RAR'
            results['can_extract'] = True
            with rarfile.RarFile(file_path, 'r') as rf:
                results['contents'] = rf.namelist()
        
        # Check GZIP
        else:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                if magic_bytes.startswith(b'\x1f\x8b'):  # GZIP signature
                    results['is_compressed'] = True
                    results['compression_type'] = 'GZIP'
                    results['can_extract'] = True
                elif magic_bytes.startswith(b'BZh'):  # BZ2 signature
                    results['is_compressed'] = True
                    results['compression_type'] = 'BZ2'
                    results['can_extract'] = True
                elif magic_bytes.startswith(b'\xFD7zXZ'):  # XZ signature
                    results['is_compressed'] = True
                    results['compression_type'] = 'XZ'
                    results['can_extract'] = True
                
    except Exception as e:
        results['error'] = str(e)
    
    return results

def extract_compressed(file_path: str, output_dir: str) -> Dict[str, Any]:
    """Extract contents of compressed files"""
    results = {
        'success': False,
        'extracted_files': [],
        'error': None
    }
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
                results['extracted_files'] = zip_ref.namelist()
        
        elif py7zr.is_7zfile(file_path):
            with py7zr.SevenZipFile(file_path, 'r') as sz:
                sz.extractall(output_dir)
                results['extracted_files'] = sz.getnames()
        
        elif rarfile.is_rarfile(file_path):
            with rarfile.RarFile(file_path, 'r') as rf:
                rf.extractall(output_dir)
                results['extracted_files'] = rf.namelist()
        
        else:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                f.seek(0)
                content = f.read()
                
                if magic_bytes.startswith(b'\x1f\x8b'):  # GZIP
                    decompressed = gzip.decompress(content)
                elif magic_bytes.startswith(b'BZh'):  # BZ2
                    decompressed = bz2.decompress(content)
                elif magic_bytes.startswith(b'\xFD7zXZ'):  # XZ
                    decompressed = lzma.decompress(content)
                else:
                    raise ValueError("Unsupported compression format")
                
                output_file = os.path.join(output_dir, 'extracted_content')
                with open(output_file, 'wb') as out:
                    out.write(decompressed)
                results['extracted_files'] = ['extracted_content']
        
        results['success'] = True
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

def check_file_signatures(file_path: str) -> Dict[str, Any]:
    """Check file signatures and identify potential file type mismatches"""
    results = {
        'declared_type': None,
        'actual_type': None,
        'signature_match': False,
        'common_signatures': []
    }
    
    # Common file signatures
    signatures = {
        b'\x89PNG\r\n\x1a\n': 'PNG image',
        b'\xff\xd8\xff': 'JPEG image',
        b'GIF87a': 'GIF image',
        b'GIF89a': 'GIF image',
        b'%PDF': 'PDF document',
        b'PK\x03\x04': 'ZIP archive',
        b'7z\xbc\xaf\x27\x1c': '7-Zip archive',
        b'Rar!\x1a\x07': 'RAR archive',
        b'\x1f\x8b\x08': 'GZIP archive',
        b'BZh': 'BZ2 archive',
        b'\xfd7zXZ': 'XZ archive'
    }
    
    try:
        # Get declared type from extension
        ext = Path(file_path).suffix.lower()
        mime_type, _ = mimetypes.guess_type(file_path)
        results['declared_type'] = mime_type or f"Unknown ({ext})"
        
        # Read file header
        with open(file_path, 'rb') as f:
            header = f.read(16)
            
        # Check against known signatures
        for sig, file_type in signatures.items():
            if header.startswith(sig):
                results['actual_type'] = file_type
                results['common_signatures'].append(file_type)
                break
        
        # Check if declared type matches actual type
        if results['actual_type']:
            results['signature_match'] = results['actual_type'].lower() in results['declared_type'].lower()
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

def analyze_file(file_path: str, use_external_tools: bool = True) -> Dict[str, Any]:
    """
    Analyze a file for forensic investigation
    """
    results = {
        'file_info': {},
        'content_analysis': {},
        'strings': [],
        'patterns': {},
        'metadata': {},
        'compression_info': {},
        'signature_analysis': {},
        'external_tools': {}  # New section for external tool results
    }
    
    # Basic file information
    file_info = results['file_info']
    file_info['size'] = os.path.getsize(file_path)
    
    # Get file timestamps
    stat = os.stat(file_path)
    file_info['created'] = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    file_info['modified'] = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    
    # Get file type information
    mime_type, file_type = get_file_type(file_path)
    file_info['mime'] = mime_type
    file_info['type'] = file_type
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
            # File signature/magic bytes
            file_info['magic_bytes'] = binascii.hexlify(data[:8]).decode()
            
            # Content analysis
            content = results['content_analysis']
            content['entropy'] = calculate_entropy(data)
            content['encoding_guess'] = guess_encoding(data)
            
            # Extract strings
            results['strings'] = find_strings(data)
            
            # Look for common patterns
            patterns = results['patterns']
            
            # IP addresses
            ip_pattern = re.compile(br'(?:\d{1,3}\.){3}\d{1,3}')
            patterns['ips'] = [ip.decode() for ip in ip_pattern.findall(data)]
            
            # URLs
            url_pattern = re.compile(br'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
            patterns['urls'] = [url.decode() for url in url_pattern.findall(data)]
            
            # Base64
            b64_pattern = re.compile(br'[A-Za-z0-9+/]{32,}={0,2}')
            patterns['base64'] = [b64.decode() for b64 in b64_pattern.findall(data)]
            
            # Get metadata
            results['metadata'] = extract_metadata(file_path)
            
            # Check compression
            results['compression_info'] = check_compression(file_path)
            
            # Analyze file signatures
            results['signature_analysis'] = check_file_signatures(file_path)
            
            # Run external tools if enabled
            if use_external_tools:
                ext_tools = results['external_tools']
                
                # Create temporary directory for tool outputs
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Run binwalk
                    try:
                        ext_tools['binwalk'] = run_binwalk(file_path)
                    except ExternalToolError as e:
                        ext_tools['binwalk'] = {'error': str(e)}
                    
                    # Run foremost
                    try:
                        foremost_dir = os.path.join(temp_dir, 'foremost')
                        ext_tools['foremost'] = run_foremost(file_path, foremost_dir)
                    except ExternalToolError as e:
                        ext_tools['foremost'] = {'error': str(e)}
                    
                    # Run exiftool
                    try:
                        ext_tools['exiftool'] = run_exiftool(file_path)
                    except ExternalToolError as e:
                        ext_tools['exiftool'] = {'error': str(e)}
                    
                    # For image files
                    if mime_type and mime_type.startswith('image/'):
                        # Run steghide
                        try:
                            ext_tools['steghide'] = run_steghide(file_path, extract=False)
                        except ExternalToolError as e:
                            ext_tools['steghide'] = {'error': str(e)}
                        
                        # Run stegsolve
                        try:
                            stegsolve_dir = os.path.join(temp_dir, 'stegsolve')
                            ext_tools['stegsolve'] = run_stegsolve(file_path, stegsolve_dir)
                        except ExternalToolError as e:
                            ext_tools['stegsolve'] = {'error': str(e)}
                        
                        # Run zsteg for PNG/BMP
                        if mime_type in ['image/png', 'image/bmp']:
                            try:
                                ext_tools['zsteg'] = run_zsteg(file_path)
                            except ExternalToolError as e:
                                ext_tools['zsteg'] = {'error': str(e)}
            
    except Exception as e:
        results['error'] = str(e)
    
    return results, format_results(results)

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy 