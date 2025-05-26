from typing import Union, Optional, Dict, Any
import base64
import binascii
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
import struct

class AdvancedCrypto:
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
    def encode_hex(data: Union[str, bytes]) -> str:
        """Encode data to hexadecimal with spaces every 2 characters"""
        if isinstance(data, str):
            data = data.encode()
        hex_str = binascii.hexlify(data).decode().upper()
        return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

    @staticmethod
    def decode_hex(data: str) -> bytes:
        """Decode hexadecimal data (handles spaces)"""
        try:
            return binascii.unhexlify(data.replace(" ", ""))
        except:
            raise ValueError("Invalid hex data")

    @staticmethod
    def encode_binary(data: Union[str, bytes]) -> str:
        """Encode data to binary string"""
        if isinstance(data, str):
            data = data.encode()
        return ' '.join(format(b, '08b') for b in data)

    @staticmethod
    def decode_binary(data: str) -> bytes:
        """Decode binary string"""
        try:
            binary = data.replace(" ", "")
            return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
        except:
            raise ValueError("Invalid binary data")

    @staticmethod
    def encode_decimal(data: Union[str, bytes]) -> str:
        """Encode data to decimal"""
        if isinstance(data, str):
            data = data.encode()
        return ' '.join(str(b) for b in data)

    @staticmethod
    def decode_decimal(data: str) -> bytes:
        """Decode decimal data"""
        try:
            return bytes(int(x) for x in data.split())
        except:
            raise ValueError("Invalid decimal data")

    @staticmethod
    def encode_amf(data: Union[str, bytes]) -> bytes:
        """Basic AMF0 encoding (string only)"""
        if isinstance(data, str):
            data = data.encode()
        # AMF0 string marker (0x02) + length + data
        length = len(data)
        return b'\x02' + struct.pack('>H', length) + data

    @staticmethod
    def decode_amf(data: bytes) -> str:
        """Basic AMF0 decoding (string only)"""
        try:
            if data[0] != 0x02:  # Check for string marker
                raise ValueError("Not an AMF0 string")
            length = struct.unpack('>H', data[1:3])[0]
            return data[3:3+length].decode()
        except:
            raise ValueError("Invalid AMF data")

    @staticmethod
    def encrypt_aes(data: Union[str, bytes], key: Union[str, bytes], mode: str = 'ECB') -> bytes:
        """Encrypt data using AES"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        # Ensure key is 16, 24, or 32 bytes
        key = pad(key, AES.block_size)[:32]
        
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        else:  # CBC mode
            cipher = AES.new(key, AES.MODE_CBC)
            data = cipher.iv + cipher.encrypt(pad(data, AES.block_size))
            return data
        
        return cipher.encrypt(pad(data, AES.block_size))

    @staticmethod
    def decrypt_aes(data: bytes, key: Union[str, bytes], mode: str = 'ECB') -> bytes:
        """Decrypt data using AES"""
        if isinstance(key, str):
            key = key.encode()
        
        key = pad(key, AES.block_size)[:32]
        
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            return unpad(cipher.decrypt(data), AES.block_size)
        else:  # CBC mode
            iv = data[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data[16:]), AES.block_size)

    @staticmethod
    def encrypt_des(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """Encrypt data using DES"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        key = pad(key, DES.block_size)[:8]
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(pad(data, DES.block_size))

    @staticmethod
    def decrypt_des(data: bytes, key: Union[str, bytes]) -> bytes:
        """Decrypt data using DES"""
        if isinstance(key, str):
            key = key.encode()
        
        key = pad(key, DES.block_size)[:8]
        cipher = DES.new(key, DES.MODE_ECB)
        return unpad(cipher.decrypt(data), DES.block_size)

    @staticmethod
    def encrypt_triple_des(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """Encrypt data using Triple DES"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        key = pad(key, DES3.block_size)[:24]
        cipher = DES3.new(key, DES3.MODE_ECB)
        return cipher.encrypt(pad(data, DES3.block_size))

    @staticmethod
    def decrypt_triple_des(data: bytes, key: Union[str, bytes]) -> bytes:
        """Decrypt data using Triple DES"""
        if isinstance(key, str):
            key = key.encode()
        
        key = pad(key, DES3.block_size)[:24]
        cipher = DES3.new(key, DES3.MODE_ECB)
        return unpad(cipher.decrypt(data), DES3.block_size)

    @staticmethod
    def xor_with_key(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """XOR data with a key"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def try_decode_all(data: Union[str, bytes]) -> Dict[str, Any]:
    """Try to decode data using all available methods"""
    results = {}
    crypto = AdvancedCrypto()

    # Convert input to bytes if it's a string
    if isinstance(data, str):
        try:
            data_bytes = data.encode()
        except:
            data_bytes = None
    else:
        data_bytes = data

    # Try base64
    try:
        if isinstance(data, str):
            decoded = crypto.decode_base64(data)
            if any(32 <= b <= 126 for b in decoded):  # Check if result contains printable chars
                results['base64'] = decoded
    except:
        pass

    # Try hex
    try:
        if isinstance(data, str):
            decoded = crypto.decode_hex(data)
            if any(32 <= b <= 126 for b in decoded):
                results['hex'] = decoded
    except:
        pass

    # Try binary
    try:
        if isinstance(data, str) and all(c in '01 ' for c in data):
            decoded = crypto.decode_binary(data)
            if any(32 <= b <= 126 for b in decoded):
                results['binary'] = decoded
    except:
        pass

    # Try decimal
    try:
        if isinstance(data, str) and all(c.isdigit() or c.isspace() for c in data):
            decoded = crypto.decode_decimal(data)
            if any(32 <= b <= 126 for b in decoded):
                results['decimal'] = decoded
    except:
        pass

    # Try AMF
    if data_bytes and len(data_bytes) > 3:
        try:
            decoded = crypto.decode_amf(data_bytes)
            if decoded:
                results['amf'] = decoded
        except:
            pass

    # Try common XOR keys
    if data_bytes:
        common_keys = [bytes([i]) for i in range(1, 256)]
        for key in common_keys[:10]:  # Try first 10 single-byte keys
            try:
                decoded = crypto.xor_with_key(data_bytes, key)
                if all(32 <= b <= 126 for b in decoded):  # If result is all printable
                    results[f'xor_key_{key.hex()}'] = decoded
                    break  # Stop after finding first good match
            except:
                continue

    return results 