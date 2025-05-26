from PIL import Image
import os
from typing import Union, Dict, Any
from stegano import lsb
import mimetypes
from pathlib import Path

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
            # Check for data in EXIF
            if hasattr(img, '_getexif') and img._getexif():
                return f"Found EXIF data: {img._getexif()}"
            
            # Add more extraction methods here
            
    except Exception as e:
        return f"Error during extraction: {str(e)}"
    
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