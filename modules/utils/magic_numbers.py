from typing import Dict, List, Tuple
import binascii

class MagicNumbers:
    # Common file format magic numbers
    MAGIC_NUMBERS = {
        'PNG': {
            'header': '89504E470D0A1A0A',
            'description': 'PNG image',
            'extension': '.png'
        },
        'JPEG': {
            'header': 'FFD8FF',
            'footer': 'FFD9',
            'description': 'JPEG image',
            'extension': '.jpg'
        },
        'GIF87a': {
            'header': '474946383761',
            'description': 'GIF87a image',
            'extension': '.gif'
        },
        'GIF89a': {
            'header': '474946383961',
            'description': 'GIF89a image',
            'extension': '.gif'
        },
        'PDF': {
            'header': '255044462D',
            'description': 'PDF document',
            'extension': '.pdf'
        },
        'ZIP': {
            'header': '504B0304',
            'description': 'ZIP archive',
            'extension': '.zip'
        },
        'RAR': {
            'header': '526172211A07',
            'description': 'RAR archive',
            'extension': '.rar'
        },
        '7Z': {
            'header': '377ABCAF271C',
            'description': '7-Zip archive',
            'extension': '.7z'
        },
        'GZIP': {
            'header': '1F8B08',
            'description': 'GZIP archive',
            'extension': '.gz'
        },
        'BZIP2': {
            'header': '425A68',
            'description': 'BZIP2 archive',
            'extension': '.bz2'
        },
        'ELF': {
            'header': '7F454C46',
            'description': 'ELF executable',
            'extension': ''
        },
        'CLASS': {
            'header': 'CAFEBABE',
            'description': 'Java class file',
            'extension': '.class'
        },
        'DOC': {
            'header': 'D0CF11E0A1B11AE1',
            'description': 'MS Office document',
            'extension': '.doc'
        },
        'MP3': {
            'header': '494433',
            'description': 'MP3 audio (ID3)',
            'extension': '.mp3'
        },
        'MP4': {
            'header': '66747970',
            'description': 'MP4 video',
            'extension': '.mp4'
        },
        'WAV': {
            'header': '52494646',
            'description': 'WAV audio',
            'extension': '.wav'
        }
    }

    @classmethod
    def detect_format(cls, data: bytes) -> List[Dict[str, str]]:
        """Detect file format based on magic numbers"""
        hex_data = binascii.hexlify(data).decode('utf-8').upper()
        matches = []
        
        for format_name, format_info in cls.MAGIC_NUMBERS.items():
            if hex_data.startswith(format_info['header']):
                matches.append({
                    'format': format_name,
                    'description': format_info['description'],
                    'header': format_info['header'],
                    'extension': format_info['extension']
                })
                
        return matches

    @classmethod
    def get_format_info(cls, format_name: str) -> Dict[str, str]:
        """Get information about a specific format"""
        return cls.MAGIC_NUMBERS.get(format_name, {})

    @classmethod
    def get_all_formats(cls) -> List[Tuple[str, str, str]]:
        """Get list of all supported formats with their headers"""
        return [(name, info['description'], info['header']) 
                for name, info in cls.MAGIC_NUMBERS.items()] 