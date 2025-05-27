from PIL import Image
import os
from typing import Union, Dict, Any, List, Tuple
from stegano import lsb
import mimetypes
from pathlib import Path
import zlib
import struct

def analyze_image(image_path: str) -> Dict[str, Any]:
    """
    Analyze an image file for potential hidden data
    """
    results = {
        'file_info': {},
        'image_info': {},
        'analysis': []
    }
    
    # Basic file information
    file_info = results['file_info']
    file_info['size'] = os.path.getsize(image_path)
    mime_type, _ = mimetypes.guess_type(image_path)
    file_info['mime'] = mime_type or 'application/octet-stream'
    file_info['extension'] = Path(image_path).suffix
    
    # Image information
    try:
        with Image.open(image_path) as img:
            image_info = results['image_info']
            image_info['format'] = img.format
            image_info['mode'] = img.mode
            image_info['size'] = img.size
            
            # Check for metadata
            if hasattr(img, 'info'):
                image_info['metadata'] = img.info

            # For PNG files, analyze chunks
            if img.format == 'PNG':
                chunks = analyze_png_chunks(image_path)
                if chunks:
                    image_info['chunks'] = chunks
                    
                    # Look for suspicious chunks
                    for chunk_type, offset, length in chunks:
                        if chunk_type not in {b'IHDR', b'IDAT', b'IEND', b'PLTE', b'tRNS', b'gAMA', b'cHRM', b'sRGB', b'iCCP'}:
                            results['analysis'].append(f"Found unusual chunk type: {chunk_type.decode('ascii', 'ignore')}")
            

            # Analyze pixel data
            if img.mode in ('RGB', 'RGBA'):
                # Check LSB of random sample of pixels
                pixels = list(img.getdata())
                sample_size = min(1000, len(pixels))
                lsb_ones = 0
                
                for i in range(sample_size):
                    pixel = pixels[i]
                    for value in pixel[:3]:  # Only check RGB values
                        if value & 1:  # Check LSB
                            lsb_ones += 1
                
                lsb_ratio = lsb_ones / (sample_size * 3)
                if 0.45 <= lsb_ratio <= 0.55:
                    results['analysis'].append(
                        "LSB ratio suggests possible hidden data"
                    )
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def analyze_png_chunks(image_path: str) -> List[Tuple[bytes, int, int]]:
    """
    Analyze PNG file chunks and return a list of (chunk_type, offset, length) tuples
    """
    chunks = []
    try:
        with open(image_path, 'rb') as f:
            # Skip PNG signature
            f.seek(8)
            
            while True:
                chunk_start = f.tell()
                
                # Read chunk header
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                    
                length = struct.unpack('>I', length_bytes)[0]
                chunk_type = f.read(4)
                
                # Store chunk info
                chunks.append((chunk_type, chunk_start, length))
                
                # Skip chunk data and CRC
                f.seek(length + 4, 1)
                
    except Exception as e:
        print(f"Error analyzing PNG chunks: {e}")
    
    return chunks

def extract_data(image_path: str) -> Union[str, None]:
    """
    Attempt to extract hidden data from an image using various methods
    """
    try:
        # Try LSB steganography first
        secret = lsb.reveal(image_path)
        if secret:
            return f"Found hidden data using LSB method: {secret}"
        
        # If LSB fails, try other methods
        with Image.open(image_path) as img:
            # For PNG files, try to extract data from chunks
            if img.format == 'PNG':
                chunk_data = extract_png_chunk_data(image_path)
                if chunk_data:
                    return f"Found data in PNG chunks: {chunk_data}"
            
            # Check for data in EXIF
            if hasattr(img, '_getexif') and img._getexif():
                return f"Found EXIF data: {img._getexif()}"
            
    except Exception as e:
        return f"Error during extraction: {str(e)}"
    
    return None

def extract_png_chunk_data(image_path: str) -> Union[str, None]:
    """
    Extract and analyze data from PNG chunks, particularly focusing on IDAT chunks
    """
    try:
        with open(image_path, 'rb') as f:
            # Skip PNG signature
            f.seek(8)
            
            idat_data = bytearray()
            text_data = []
            
            while True:
                # Read chunk header
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                    
                length = struct.unpack('>I', length_bytes)[0]
                chunk_type = f.read(4)
                chunk_data = f.read(length)
                crc = f.read(4)
                
                # Collect IDAT chunks
                if chunk_type == b'IDAT':
                    idat_data.extend(chunk_data)
                
                # Look for tEXt chunks
                elif chunk_type == b'tEXt':
                    try:
                        # Split at null byte
                        keyword, text_value = chunk_data.split(b'\0', 1)
                        text_data.append(f"{keyword.decode('utf-8', 'ignore')}: {text_value.decode('utf-8', 'ignore')}")
                    except:
                        pass
            
            results = []
            
            # Try to decompress IDAT data
            if idat_data:
                try:
                    decompressed = zlib.decompress(idat_data)
                    # Look for readable strings in decompressed data
                    readable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decompressed)
                    if any(c != '.' for c in readable):
                        results.append(f"IDAT decoded data: {readable}")
                except:
                    pass
            
            # Add any text chunk data
            if text_data:
                results.append(f"Text chunks: {', '.join(text_data)}")
            
            return '\n'.join(results) if results else None
            
    except Exception as e:
        return f"Error extracting PNG chunk data: {str(e)}"
    
    return None

def hide_data(image_path: str, data: str, output_path: str) -> bool:
    """
    Hide data in an image using LSB steganography
    """
    try:
        secret = lsb.hide(image_path, data)
        secret.save(output_path)
        return True
    except Exception as e:
        print(f"Error hiding data: {str(e)}")
        return False 