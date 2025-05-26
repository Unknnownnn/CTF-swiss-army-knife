from typing import List, Dict, Any
import re
import string
import base64
import math
from collections import Counter

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text"""
    if not text:
        return 0.0
    
    counts = Counter(text)
    entropy = 0
    for count in counts.values():
        p = count / len(text)
        entropy += -p * math.log2(p)
    return entropy

def is_base64(text: str) -> bool:
    """Check if text is likely base64 encoded"""
    if not text:
        return False
    
    # Check characters are valid base64
    if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
        return False
    
    # Check length is valid for base64
    if len(text) % 4 != 0:
        return False
    
    try:
        decoded = base64.b64decode(text)
        # Check if decoded text contains printable characters
        printable_ratio = sum(chr(b) in string.printable for b in decoded) / len(decoded)
        return printable_ratio > 0.8
    except:
        return False

def is_hex(text: str) -> bool:
    """Check if text is likely hex encoded"""
    # Remove spaces and 0x prefixes
    text = text.replace(' ', '').lower()
    text = text[2:] if text.startswith('0x') else text
    
    return bool(re.match(r'^[0-9a-f]+$', text)) and len(text) % 2 == 0

def detect_caesar(text: str) -> List[Dict[str, Any]]:
    """Detect possible Caesar cipher variants"""
    results = []
    
    # Check if text contains mostly letters
    if sum(c.isalpha() for c in text) / len(text) < 0.7:
        return results
    
    # Common letter frequencies in English
    eng_freqs = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'.lower()
    
    # Get frequency analysis of the text
    freq = Counter(c.lower() for c in text if c.isalpha())
    most_common = ''.join(c for c, _ in freq.most_common())
    
    # Try to match frequency patterns
    for common_letter in eng_freqs[:5]:  # Try top 5 most common letters
        for cipher_letter in most_common[:5]:  # Try top 5 most common in cipher
            shift = (ord(cipher_letter) - ord(common_letter)) % 26
            results.append({
                'type': 'caesar',
                'shift': shift,
                'confidence': 0.8 if shift in [3, 13] else 0.5  # Higher confidence for common ROT-3 and ROT-13
            })
    
    return results

def detect_substitution(text: str) -> Dict[str, float]:
    """Detect if text might be a substitution cipher"""
    if not text or len(text) < 20:
        return {'confidence': 0}
    
    # Calculate letter frequencies
    freq = Counter(c.lower() for c in text if c.isalpha())
    if not freq:
        return {'confidence': 0}
    
    # Check frequency distribution
    total = sum(freq.values())
    freqs = [count/total for count in freq.values()]
    
    # Compare with typical English letter distribution
    confidence = 0.6  # Base confidence
    
    # Check if we have a good distribution of letters
    if len(freq) >= 20:  # Most letters of alphabet present
        confidence += 0.2
    
    # Check if frequency distribution is similar to English
    if max(freqs) < 0.2:  # No letter too frequent
        confidence += 0.1
    
    return {'confidence': confidence}

def detect_vigenere(text: str) -> Dict[str, float]:
    """Detect if text might be Vigenère cipher"""
    if not text or len(text) < 20:
        return {'confidence': 0}
    
    # Calculate Index of Coincidence
    text = ''.join(c.lower() for c in text if c.isalpha())
    if not text:
        return {'confidence': 0}
    
    n = len(text)
    freq = Counter(text)
    ioc = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
    
    # English text typically has IoC around 0.067
    # Random text has IoC around 0.038
    # Vigenère typically between these values
    if 0.038 < ioc < 0.065:
        return {'confidence': 0.7}
    return {'confidence': 0}

def analyze_text(text: str) -> List[Dict[str, Any]]:
    """Analyze text and suggest possible encodings/ciphers"""
    results = []
    
    # Basic text properties
    entropy = calculate_entropy(text)
    printable_ratio = sum(c in string.printable for c in text) / len(text)
    
    # Check for common encodings
    if is_base64(text):
        results.append({
            'type': 'encoding',
            'method': 'base64',
            'confidence': 0.9
        })
    
    if is_hex(text):
        results.append({
            'type': 'encoding',
            'method': 'hex',
            'confidence': 0.9
        })
    
    # Check for Caesar cipher variants
    caesar_results = detect_caesar(text)
    results.extend(caesar_results)
    
    # Check for substitution cipher
    sub_result = detect_substitution(text)
    if sub_result['confidence'] > 0.5:
        results.append({
            'type': 'cipher',
            'method': 'substitution',
            'confidence': sub_result['confidence']
        })
    
    # Check for Vigenère cipher
    vig_result = detect_vigenere(text)
    if vig_result['confidence'] > 0.5:
        results.append({
            'type': 'cipher',
            'method': 'vigenere',
            'confidence': vig_result['confidence']
        })
    
    # Add entropy information
    results.append({
        'type': 'analysis',
        'method': 'entropy',
        'value': entropy,
        'interpretation': 'high' if entropy > 4 else 'medium' if entropy > 3 else 'low'
    })
    
    return results

def format_analysis_results(results: List[Dict[str, Any]]) -> str:
    """Format analysis results in a readable way"""
    output = []
    
    # Group results by type
    encodings = []
    ciphers = []
    analysis = []
    
    for result in results:
        if result['type'] == 'encoding':
            encodings.append(result)
        elif result['type'] == 'cipher':
            ciphers.append(result)
        else:
            analysis.append(result)
    
    # Format encodings
    if encodings:
        output.append("=== Possible Encodings ===")
        for enc in encodings:
            output.append(f"- {enc['method'].upper()} (Confidence: {enc['confidence']*100:.0f}%)")
    
    # Format ciphers
    if ciphers:
        output.append("\n=== Possible Ciphers ===")
        for cipher in ciphers:
            if cipher['method'] == 'caesar':
                output.append(f"- Caesar ROT-{cipher['shift']} (Confidence: {cipher['confidence']*100:.0f}%)")
            else:
                output.append(f"- {cipher['method'].title()} (Confidence: {cipher['confidence']*100:.0f}%)")
    
    # Format analysis
    if analysis:
        output.append("\n=== Text Analysis ===")
        for item in analysis:
            if item['method'] == 'entropy':
                output.append(f"- Entropy: {item['value']:.2f} ({item['interpretation'].title()} randomness)")
    
    return '\n'.join(output) 