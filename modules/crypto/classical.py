from typing import Union, List, Dict, Tuple
import re

def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    """
    Implement Caesar cipher encryption/decryption
    """
    if decrypt:
        shift = -shift
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def try_all_caesar_shifts(text: str, flag_patterns: List[str] = None) -> Dict[str, List[Tuple[int, str, float]]]:
    """Try all possible Caesar shifts and return results with confidence scores"""
    if flag_patterns is None:
        flag_patterns = [
            r'[A-Za-z0-9_]{2,8}{[^}]+}',  # Generic flag format XXX{...}
            r'flag{[^}]+}',                # Explicit flag{...}
            r'ctf{[^}]+}',                 # CTF{...}
            r'key{[^}]+}'                  # key{...}
        ]
    
    results = {
        'likely_flags': [],
        'sensible_text': []
    }
    
    # Try all possible shifts
    for shift in range(1, 26):
        decoded = caesar_cipher(text, shift, decrypt=True)
        
        # Check if result matches flag pattern
        is_flag = any(re.search(pattern, decoded, re.IGNORECASE) for pattern in flag_patterns)
        
        # Calculate confidence score based on character distribution
        word_like_ratio = sum(c.isalnum() or c.isspace() for c in decoded) / len(decoded)
        space_ratio = decoded.count(' ') / len(decoded) if len(decoded) > 0 else 0
        vowel_ratio = sum(c.lower() in 'aeiou' for c in decoded) / len(decoded) if len(decoded) > 0 else 0
        
        # Weight the ratios to get a confidence score
        confidence = (word_like_ratio * 0.4 + space_ratio * 0.3 + vowel_ratio * 0.3)
        
        if is_flag:
            results['likely_flags'].append((shift, decoded, confidence))
        elif confidence > 0.5:  # Only include reasonably sensible text
            results['sensible_text'].append((shift, decoded, confidence))
    
    # Sort results by confidence
    results['likely_flags'].sort(key=lambda x: x[2], reverse=True)
    results['sensible_text'].sort(key=lambda x: x[2], reverse=True)
    
    return results

def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    """
    Implement Vigenère cipher encryption/decryption
    """
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key]
    
    i = 0  # Separate counter for key position
    for char in text:
        if char.isalpha():
            # Determine the shift based on the key character
            key_shift = key_as_int[i % key_length]
            
            # Get the base for uppercase/lowercase
            is_upper = char.isupper()
            char = char.upper()
            base = ord('A')
            
            if decrypt:
                # For decryption: plaintext = (ciphertext - key + 26) % 26
                shifted = (ord(char) - base - key_shift) % 26
            else:
                # For encryption: ciphertext = (plaintext + key) % 26
                shifted = (ord(char) - base + key_shift) % 26
            
            # Convert back to character and maintain original case
            result_char = chr(shifted + base)
            result += result_char if is_upper else result_char.lower()
            
            # Only increment key position for alphabetic characters
            i += 1
        else:
            result += char
            
    return result

def rot13(text: str) -> str:
    """
    ROT13 cipher (special case of Caesar cipher with shift 13)
    """
    return caesar_cipher(text, 13)

def atbash(text: str) -> str:
    """
    Atbash cipher implementation
    """
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(ord('Z') - (ord(char) - ord('A')))
            else:
                result += chr(ord('z') - (ord(char) - ord('a')))
        else:
            result += char
    return result

def break_caesar(text: str) -> list[tuple[int, str]]:
    """
    Attempt to break Caesar cipher by trying all possible shifts
    """
    results = []
    for shift in range(26):
        decrypted = caesar_cipher(text, shift, decrypt=True)
        results.append((shift, decrypted))
    return results 