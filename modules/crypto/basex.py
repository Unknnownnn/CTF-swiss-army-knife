from typing import Union, Dict, List, Tuple
import base64
import base58
import base32hex
import base91
import re

class BaseX:
    @staticmethod
    def encode_base16(data: Union[str, bytes]) -> str:
        """Encode data to base16 (hex uppercase)"""
        if isinstance(data, str):
            data = data.encode()
        return base64.b16encode(data).decode()

    @staticmethod
    def decode_base16(data: str) -> bytes:
        """Decode base16 data"""
        try:
            return base64.b16decode(data.upper())
        except:
            raise ValueError("Invalid base16 data")

    @staticmethod
    def encode_base32(data: Union[str, bytes]) -> str:
        """Encode data to base32"""
        if isinstance(data, str):
            data = data.encode()
        return base64.b32encode(data).decode()

    @staticmethod
    def decode_base32(data: str) -> bytes:
        """Decode base32 data"""
        try:
            return base64.b32decode(data.upper())
        except:
            raise ValueError("Invalid base32 data")

    @staticmethod
    def encode_base32hex(data: Union[str, bytes]) -> str:
        """Encode data to base32hex"""
        if isinstance(data, str):
            data = data.encode()
        return base32hex.b32encode(data).decode()

    @staticmethod
    def decode_base32hex(data: str) -> bytes:
        """Decode base32hex data"""
        try:
            return base32hex.b32decode(data.upper())
        except:
            raise ValueError("Invalid base32hex data")

    @staticmethod
    def encode_base58(data: Union[str, bytes]) -> str:
        """Encode data to base58"""
        if isinstance(data, str):
            data = data.encode()
        return base58.b58encode(data).decode()

    @staticmethod
    def decode_base58(data: str) -> bytes:
        """Decode base58 data"""
        try:
            return base58.b58decode(data)
        except:
            raise ValueError("Invalid base58 data")

    @staticmethod
    def encode_base64(data: Union[str, bytes]) -> str:
        """Encode data to base64"""
        if isinstance(data, str):
            data = data.encode()
        return base64.b64encode(data).decode()

    @staticmethod
    def decode_base64(data: str) -> bytes:
        """Decode base64 data"""
        try:
            return base64.b64decode(data)
        except:
            raise ValueError("Invalid base64 data")

    @staticmethod
    def encode_base85(data: Union[str, bytes]) -> str:
        """Encode data to base85 (ASCII85)"""
        if isinstance(data, str):
            data = data.encode()
        return base64.b85encode(data).decode()

    @staticmethod
    def decode_base85(data: str) -> bytes:
        """Decode base85 data"""
        try:
            return base64.b85decode(data)
        except:
            raise ValueError("Invalid base85 data")

    @staticmethod
    def encode_base91(data: Union[str, bytes]) -> str:
        """Encode data to base91"""
        if isinstance(data, str):
            data = data.encode()
        return base91.encode(data).decode()

    @staticmethod
    def decode_base91(data: str) -> bytes:
        """Decode base91 data"""
        try:
            return base91.decode(data.encode())
        except:
            raise ValueError("Invalid base91 data")

    @staticmethod
    def is_printable_text(data: bytes) -> bool:
        """Check if decoded data is printable text"""
        try:
            text = data.decode('utf-8')
            # Check if text contains mostly printable characters
            printable_ratio = sum(c.isprintable() for c in text) / len(text)
            return printable_ratio > 0.95 and len(text.strip()) > 0
        except:
            return False

    @staticmethod
    def looks_like_flag(text: str, flag_patterns: List[str] = None) -> bool:
        """Check if text matches common flag formats"""
        if flag_patterns is None:
            flag_patterns = [
                r'[A-Za-z0-9_]{2,8}{[^}]+}',  # Generic flag format XXX{...}
                r'flag{[^}]+}',                # Explicit flag{...}
                r'ctf{[^}]+}',                 # CTF{...}
                r'key{[^}]+}'                  # key{...}
            ]
        
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in flag_patterns)

    @classmethod
    def try_all_decoding(cls, data: str, flag_patterns: List[str] = None) -> Dict[str, List[Tuple[str, float]]]:
        """Try all base decoding methods and return results with confidence scores"""
        results = {
            'likely_flags': [],
            'printable_results': []
        }
        
        # List of all base encoding methods to try
        methods = [
            ('base16', cls.decode_base16),
            ('base32', cls.decode_base32),
            ('base32hex', cls.decode_base32hex),
            ('base58', cls.decode_base58),
            ('base64', cls.decode_base64),
            ('base85', cls.decode_base85),
            ('base91', cls.decode_base91)
        ]
        
        for name, decode_method in methods:
            try:
                decoded = decode_method(data)
                if cls.is_printable_text(decoded):
                    text = decoded.decode('utf-8')
                    
                    # Calculate confidence score based on character distribution
                    ascii_ratio = sum(32 <= ord(c) <= 126 for c in text) / len(text)
                    word_like_ratio = sum(c.isalnum() or c.isspace() for c in text) / len(text)
                    confidence = (ascii_ratio + word_like_ratio) / 2
                    
                    # Check for flag patterns
                    if cls.looks_like_flag(text, flag_patterns):
                        results['likely_flags'].append((name, text, confidence))
                    else:
                        results['printable_results'].append((name, text, confidence))
            except:
                continue
        
        # Sort results by confidence
        results['likely_flags'].sort(key=lambda x: x[2], reverse=True)
        results['printable_results'].sort(key=lambda x: x[2], reverse=True)
        
        return results 