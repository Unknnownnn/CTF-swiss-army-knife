from typing import List, Dict, Any, Tuple
import re
import string
from collections import Counter
import math
from modules.crypto.detector import analyze_text, is_base64, is_hex, format_analysis_results
from modules.crypto.classical import caesar_cipher, vigenere_cipher, rot13, atbash
from modules.crypto.advanced import AdvancedCrypto, try_decode_all

class SmartDetector:
    def __init__(self):
        # Common English word patterns and frequencies
        self.common_words = set(['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 
                               'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
                               'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
                               'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what','{','}'])
        
        # English letter frequencies
        self.eng_freq = {'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
                        'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4,
                        'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0,
                        'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07}
        
        self.crypto = AdvancedCrypto()
    
    def score_text_likelihood(self, text: str) -> float:
        """Score how likely the text is to be valid English"""
        if not text:
            return 0.0
            
        # Convert to lowercase and remove non-letters
        text = ''.join(c.lower() for c in text if c.isalpha() or c.isspace())
        if not text:
            return 0.0
            
        # Calculate scores based on different metrics
        scores = []
        
        # 1. Word-based scoring
        words = text.lower().split()
        if words:
            common_word_ratio = sum(1 for word in words if word in self.common_words) / len(words)
            scores.append(common_word_ratio * 0.4)  # 40% weight
            
        # 2. Letter frequency scoring
        letter_counts = Counter(c for c in text.lower() if c.isalpha())
        total_letters = sum(letter_counts.values())
        if total_letters:
            freq_score = 0
            scored_chars = 0
            for char, count in letter_counts.items():
                expected_freq = self.eng_freq.get(char, 0) / 100
                if expected_freq > 0:  # Only score characters with expected frequencies
                    actual_freq = count / total_letters
                    freq_score += 1 - min(abs(expected_freq - actual_freq) / expected_freq, 1)
                    scored_chars += 1
            # Average the frequency score only for characters we actually scored
            if scored_chars > 0:
                scores.append((freq_score / scored_chars) * 0.3)  # 30% weight
            
        # 3. N-gram scoring
        if len(text) >= 3:
            # Get all 3-character sequences
            trigrams = [text[i:i+3] for i in range(len(text)-2)]
            valid_trigrams = sum(1 for t in trigrams if t.isalpha())
            if trigrams:
                scores.append((valid_trigrams / len(trigrams)) * 0.3)  # 30% weight
        
        return sum(scores) if scores else 0.0
    
    def analyze_and_decrypt(self, text: str, min_length: int = 5) -> Dict[str, Any]:
        """Analyze text and attempt to decrypt it with most likely algorithms"""
        if len(text) < min_length:
            return {
                'status': 'too_short',
                'message': f'Text must be at least {min_length} characters long',
                'results': []
            }
            
        # Get initial analysis
        analysis_results = analyze_text(text)
        
        # Try all advanced decoding methods
        advanced_results = try_decode_all(text)
        
        decryption_attempts = []
        
        # Add results from advanced decoding
        for method, decoded in advanced_results.items():
            try:
                if isinstance(decoded, bytes):
                    decoded_text = decoded.decode('utf-8', errors='ignore')
                else:
                    decoded_text = str(decoded)
                
                score = self.score_text_likelihood(decoded_text)
                if score > 0.3:  # Only include if it looks somewhat promising
                    decryption_attempts.append({
                        'method': method,
                        'result': decoded_text,
                        'score': score,
                        'confidence': score * 0.8  # Scale confidence based on score
                    })
            except:
                continue
        
        # Try classical ciphers
        for result in analysis_results:
            if result['type'] == 'cipher':
                if result['method'] == 'caesar':
                    shift = result.get('shift', 3)
                    decrypted = caesar_cipher(text, shift, decrypt=True)
                    score = self.score_text_likelihood(decrypted)
                    decryption_attempts.append({
                        'method': f'Caesar (ROT-{shift})',
                        'result': decrypted,
                        'score': score,
                        'confidence': result['confidence']
                    })
                    
                elif result['method'] == 'vigenere':
                    # Try some common short keys
                    common_keys = ['key', 'secret', 'password', 'cipher']
                    for key in common_keys:
                        try:
                            decrypted = vigenere_cipher(text, key, decrypt=True)
                            score = self.score_text_likelihood(decrypted)
                            if score > 0.5:  # Only include if it looks promising
                                decryption_attempts.append({
                                    'method': f'Vigenère (key="{key}")',
                                    'result': decrypted,
                                    'score': score,
                                    'confidence': result['confidence'] * score
                                })
                        except:
                            continue
        
        # Always try ROT13 since it's common
        rot13_result = rot13(text)
        score = self.score_text_likelihood(rot13_result)
        decryption_attempts.append({
            'method': 'ROT13',
            'result': rot13_result,
            'score': score,
            'confidence': 0.8 if score > 0.6 else 0.5
        })
        
        # Try Atbash
        atbash_result = atbash(text)
        score = self.score_text_likelihood(atbash_result)
        decryption_attempts.append({
            'method': 'Atbash',
            'result': atbash_result,
            'score': score,
            'confidence': 0.8 if score > 0.6 else 0.5
        })
        
        # Sort attempts by score
        decryption_attempts.sort(key=lambda x: x['score'], reverse=True)
        
        # Filter out low-scoring attempts
        decryption_attempts = [d for d in decryption_attempts if d['score'] > 0.3]
        
        return {
            'status': 'success',
            'message': 'Analysis complete',
            'original_analysis': analysis_results,
            'decryption_attempts': decryption_attempts
        }

def format_smart_analysis(analysis_result: Dict[str, Any]) -> str:
    """Format the smart analysis results in a readable way"""
    if analysis_result['status'] == 'too_short':
        return analysis_result['message']
        
    output = []
    
    if analysis_result['decryption_attempts']:
        output.append("=== Most Likely Decryptions ===")
        for attempt in analysis_result['decryption_attempts']:
            output.append(f"\nMethod: {attempt['method']}")
            output.append(f"Confidence: {attempt['confidence']*100:.0f}%")
            output.append(f"Score: {attempt['score']*100:.0f}%")
            output.append(f"Result: {attempt['result']}")
    else:
        output.append("No likely decryptions found")
        
    # Add original analysis
    output.append("\n=== Detected Patterns ===")
    
    # Group original analysis results by type
    orig_results = analysis_result['original_analysis']
    encodings = [r for r in orig_results if r['type'] == 'encoding']
    ciphers = [r for r in orig_results if r['type'] == 'cipher']
    analysis = [r for r in orig_results if r['type'] == 'analysis']
    
    # Format encodings
    if encodings:
        output.append("\nPossible Encodings:")
        for enc in encodings:
            output.append(f"- {enc['method'].upper()} (Confidence: {enc['confidence']*100:.0f}%)")
    
    # Format ciphers
    if ciphers:
        output.append("\nPossible Ciphers:")
        for cipher in ciphers:
            if 'shift' in cipher:
                output.append(f"- Caesar ROT-{cipher['shift']} (Confidence: {cipher['confidence']*100:.0f}%)")
            else:
                output.append(f"- {cipher['method'].title()} (Confidence: {cipher['confidence']*100:.0f}%)")
    
    # Format analysis
    if analysis:
        output.append("\nText Analysis:")
        for item in analysis:
            if item['method'] == 'entropy':
                output.append(f"- Entropy: {item['value']:.2f} ({item['interpretation'].title()} randomness)")
    
    return '\n'.join(output) 