from typing import Union, List, Tuple, Optional
import binascii
import string
import re
import base64
from .magic_numbers import MagicNumbers

class HexEditor:
    def __init__(self, data: bytes):
        self.data = bytearray(data)  # Use bytearray for mutability
        self.bytes_per_line = 16
        self._detect_format()
    
    def _detect_format(self):
        """Detect file format using magic numbers"""
        self.detected_formats = MagicNumbers.detect_format(self.data)
    
    def to_hex(self) -> str:
        """Convert data to formatted hex view"""
        hex_lines = []
        ascii_chars = []
        
        # Add format detection header if formats were detected
        if self.detected_formats:
            hex_lines.append("=== Detected File Format(s) ===")
            for fmt in self.detected_formats:
                hex_lines.append(f"{fmt['format']}: {fmt['description']}")
                hex_lines.append(f"Expected Header: {fmt['header']}")
            hex_lines.append("="*40 + "\n")
        
        # Format hex dump
        for i in range(0, len(self.data), self.bytes_per_line):
            # Offset
            line = f"{i:08x}: "
            
            # Hex values
            chunk = self.data[i:i + self.bytes_per_line]
            hex_values = [f"{b:02x}" for b in chunk]
            
            # Pad with spaces if needed
            if len(hex_values) < self.bytes_per_line:
                hex_values.extend(['  '] * (self.bytes_per_line - len(hex_values)))
            
            # Group hex values by 8 bytes
            hex_part = ' '.join([' '.join(hex_values[j:j+8]) for j in range(0, 16, 8)])
            line += hex_part
            
            # ASCII representation
            ascii_part = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            line += f"  |{ascii_part}|"
            
            hex_lines.append(line)
        
        return '\n'.join(hex_lines)
    
    def edit_bytes(self, offset: int, new_bytes: bytes) -> bool:
        """Edit bytes at specified offset"""
        try:
            if offset + len(new_bytes) <= len(self.data):
                self.data[offset:offset + len(new_bytes)] = new_bytes
                self._detect_format()  # Re-detect format after edit
                return True
            return False
        except:
            return False
    
    def get_data(self) -> bytes:
        """Get current data as bytes"""
        return bytes(self.data)
    
    def find_pattern(self, pattern: str) -> List[int]:
        """Find all occurrences of a pattern (hex or text)"""
        try:
            # Try as hex pattern first
            if all(c in '0123456789ABCDEFabcdef ' for c in pattern):
                hex_pattern = pattern.replace(' ', '')
                search_bytes = binascii.unhexlify(hex_pattern)
            else:
                # Try as text pattern
                search_bytes = pattern.encode()
            
            positions = []
            pos = 0
            while True:
                pos = self.data.find(search_bytes, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += 1
            return positions
        except:
            return []
    
    def decode_as(self, encoding: str) -> str:
        """Decode data using specified encoding"""
        try:
            if encoding == 'hex':
                return binascii.hexlify(self.data).decode()
            elif encoding == 'ascii':
                return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in self.data)
            elif encoding == 'utf-8':
                return self.data.decode('utf-8', errors='replace')
            elif encoding == 'base64':
                import base64
                return base64.b64encode(self.data).decode()
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")
        except Exception as e:
            raise ValueError(f"Decoding failed: {str(e)}")
    
    def get_suggested_headers(self) -> List[Tuple[str, str, str]]:
        """Get list of suggested headers based on file size and content"""
        suggestions = []
        
        # Get all known formats
        all_formats = MagicNumbers.get_all_formats()
        
        # If we detected a format but it's corrupted, suggest the correct header
        if self.detected_formats:
            for fmt in self.detected_formats:
                if fmt['header'] != binascii.hexlify(self.data[:len(fmt['header'])//2]).decode().upper():
                    suggestions.append((
                        fmt['format'],
                        fmt['description'],
                        fmt['header']
                    ))
        
        # Based on file extension or content type, suggest possible headers
        # TODO: Add more heuristics for suggesting headers
        
        return suggestions
    
    def replace_header(self, new_header: str) -> bool:
        """Replace file header with new hex values"""
        try:
            new_bytes = binascii.unhexlify(new_header.replace(' ', ''))
            return self.edit_bytes(0, new_bytes)
        except:
            return False
    
    def get_offset_from_position(self, line: int, column: int) -> Optional[int]:
        """Convert text position (line, column) to byte offset"""
        try:
            # Calculate offset from line number (each line shows 16 bytes)
            base_offset = (line - 1) * self.bytes_per_line
            
            # Parse column position
            # Format: "00000000: 00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff  |0123456789abcdef|"
            # Skip offset (10 chars), then each byte is 3 chars (2 hex + 1 space)
            if column < 10:  # In offset section
                return None
                
            col = column - 10  # Remove offset section
            if col < 48:  # In hex section (16 bytes * 3 chars each)
                # Calculate which byte position we're at
                byte_pos = col // 3
                if byte_pos >= self.bytes_per_line:
                    return None
                return base_offset + byte_pos
                
            elif col > 50 and col < 67:  # In ASCII section
                byte_pos = col - 51
                if byte_pos >= self.bytes_per_line:
                    return None
                return base_offset + byte_pos
                
            return None
        except:
            return None
    
    def from_hex(self, hex_str: str) -> bytes:
        """Convert hex string to bytes"""
        # Remove formatting and whitespace
        hex_str = re.sub(r'[\s:]', '', hex_str)
        hex_str = re.sub(r'[^0-9a-fA-F]', '', hex_str)
        return bytes.fromhex(hex_str)
    
    def replace_pattern(self, old: Union[str, bytes], new: Union[str, bytes]) -> bool:
        """Replace all occurrences of a pattern"""
        if isinstance(old, str):
            try:
                old = bytes.fromhex(old.replace(' ', ''))
            except ValueError:
                old = old.encode('utf-8')
        
        if isinstance(new, str):
            try:
                new = bytes.fromhex(new.replace(' ', ''))
            except ValueError:
                new = new.encode('utf-8')
        
        self.data = self.data.replace(old, new)
        return True
    
    def encode_as(self, text: str, encoding: str) -> bool:
        """Encode text with specified encoding"""
        try:
            self.data = text.encode(encoding)
            return True
        except Exception as e:
            print(f"Error encoding as {encoding}: {str(e)}")
            return False
    
    def rotate_bytes(self, n: int) -> bytes:
        """Rotate each byte by n positions"""
        return bytes((b + n) % 256 for b in self.data)
    
    def xor_with_key(self, key: Union[str, bytes]) -> bytes:
        """XOR data with key"""
        if isinstance(key, str):
            key = key.encode('utf-8')
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(self.data))
    
    def bit_shift(self, n: int, direction: str = 'left') -> bytes:
        """Shift bits left or right"""
        if direction == 'left':
            return bytes((b << n) & 0xFF for b in self.data)
        else:
            return bytes((b >> n) for b in self.data)
    
    def set_data(self, data: Union[bytes, str]):
        """Set new data"""
        if isinstance(data, str):
            try:
                self.data = bytes.fromhex(data.replace(' ', ''))
            except ValueError:
                self.data = data.encode('utf-8')
        else:
            self.data = data

def detect_encodings(data: bytes) -> List[str]:
    """Try to detect possible encodings of the data"""
    possible_encodings = []
    
    # Check if it's printable ASCII
    try:
        decoded = data.decode('ascii')
        if all(c in string.printable for c in decoded):
            possible_encodings.append('ASCII')
    except UnicodeDecodeError:
        pass
    
    # Check if it's UTF-8
    try:
        data.decode('utf-8')
        possible_encodings.append('UTF-8')
    except UnicodeDecodeError:
        pass
    
    # Check if it's base64
    if len(data) % 4 == 0:
        try:
            decoded = base64.b64decode(data)
            possible_encodings.append('Base64')
        except Exception:
            pass
    
    # Check if it's hex
    hex_pattern = re.compile(b'^[0-9A-Fa-f]+$')
    if hex_pattern.match(data):
        try:
            bytes.fromhex(data.decode())
            possible_encodings.append('Hex')
        except Exception:
            pass
    
    return possible_encodings 