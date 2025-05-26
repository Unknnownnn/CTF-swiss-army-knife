import os
import zipfile
import py7zr
import rarfile
import gzip
import bz2
import lzma
import shutil
from typing import Dict, Any, List
from pathlib import Path

def check_compression(file_path: str) -> Dict[str, Any]:
    """Check if file is compressed and identify compression type"""
    results = {
        'is_compressed': False,
        'compression_type': None,
        'can_extract': False,
        'contents': [],
        'error': None
    }
    
    try:
        # Check ZIP
        if zipfile.is_zipfile(file_path):
            results['is_compressed'] = True
            results['compression_type'] = 'ZIP'
            results['can_extract'] = True
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                results['contents'] = zip_ref.namelist()
            return results
        
        # Check 7Z
        if py7zr.is_7zfile(file_path):
            results['is_compressed'] = True
            results['compression_type'] = '7Z'
            results['can_extract'] = True
            with py7zr.SevenZipFile(file_path, 'r') as sz:
                results['contents'] = sz.getnames()
            return results
        
        # Check RAR
        if rarfile.is_rarfile(file_path):
            results['is_compressed'] = True
            results['compression_type'] = 'RAR'
            results['can_extract'] = True
            with rarfile.RarFile(file_path, 'r') as rf:
                results['contents'] = rf.namelist()
            return results
        
        # Check other compression formats
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(4)
            
            # GZIP
            if magic_bytes.startswith(b'\x1f\x8b'):
                results['is_compressed'] = True
                results['compression_type'] = 'GZIP'
                results['can_extract'] = True
                try:
                    with gzip.open(file_path, 'rb') as gz:
                        gz.read(1)  # Test if can be read
                    results['contents'] = ['compressed_content']
                except Exception as e:
                    results['error'] = str(e)
                return results
            
            # BZ2
            if magic_bytes.startswith(b'BZh'):
                results['is_compressed'] = True
                results['compression_type'] = 'BZ2'
                results['can_extract'] = True
                try:
                    with bz2.open(file_path, 'rb') as bz:
                        bz.read(1)  # Test if can be read
                    results['contents'] = ['compressed_content']
                except Exception as e:
                    results['error'] = str(e)
                return results
            
            # XZ
            if magic_bytes.startswith(b'\xfd7zXZ'):
                results['is_compressed'] = True
                results['compression_type'] = 'XZ'
                results['can_extract'] = True
                try:
                    with lzma.open(file_path, 'rb') as xz:
                        xz.read(1)  # Test if can be read
                    results['contents'] = ['compressed_content']
                except Exception as e:
                    results['error'] = str(e)
                return results
    
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
        
        # Extract ZIP
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
                results['extracted_files'] = zip_ref.namelist()
                results['success'] = True
            return results
        
        # Extract 7Z
        if py7zr.is_7zfile(file_path):
            with py7zr.SevenZipFile(file_path, 'r') as sz:
                sz.extractall(output_dir)
                results['extracted_files'] = sz.getnames()
                results['success'] = True
            return results
        
        # Extract RAR
        if rarfile.is_rarfile(file_path):
            with rarfile.RarFile(file_path, 'r') as rf:
                rf.extractall(output_dir)
                results['extracted_files'] = rf.namelist()
                results['success'] = True
            return results
        
        # Handle other compression formats
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(4)
            f.seek(0)
            content = f.read()
            
            output_file = os.path.join(output_dir, 'extracted_content')
            
            # GZIP
            if magic_bytes.startswith(b'\x1f\x8b'):
                decompressed = gzip.decompress(content)
                with open(output_file, 'wb') as out:
                    out.write(decompressed)
                results['extracted_files'] = ['extracted_content']
                results['success'] = True
                return results
            
            # BZ2
            if magic_bytes.startswith(b'BZh'):
                decompressed = bz2.decompress(content)
                with open(output_file, 'wb') as out:
                    out.write(decompressed)
                results['extracted_files'] = ['extracted_content']
                results['success'] = True
                return results
            
            # XZ
            if magic_bytes.startswith(b'\xfd7zXZ'):
                decompressed = lzma.decompress(content)
                with open(output_file, 'wb') as out:
                    out.write(decompressed)
                results['extracted_files'] = ['extracted_content']
                results['success'] = True
                return results
    
    except Exception as e:
        results['error'] = str(e)
    
    return results 