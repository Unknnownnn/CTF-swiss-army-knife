from typing import List, Dict, Any, Optional
import re
from modules.crypto.smart_detector import SmartDetector
from modules.crypto.detector import analyze_text, is_base64, is_hex

class CryptoAIAgent:
    def __init__(self):
        self.smart_detector = SmartDetector()
        # Common flag formats - can be extended
        self.flag_patterns = [
            r'[A-Za-z0-9_]{2,8}{[^}]+}',  # Generic flag format XXX{...}
            r'flag{[^}]+}',                # Explicit flag{...}
            r'ctf{[^}]+}',                 # CTF{...}
            r'key{[^}]+}'                  # key{...}
        ]
    
    def find_flags(self, text: str) -> List[str]:
        """Find potential flags in the given text"""
        flags = []
        for pattern in self.flag_patterns:
            matches = re.finditer(pattern, text)
            flags.extend(match.group(0) for match in matches)
        return list(set(flags))  # Remove duplicates
    
    def analyze_text_for_flags(self, text: str) -> Dict[str, Any]:
        """
        Analyze text using various methods and look for flags in all possible decryptions
        """
        results = {
            'original_flags': self.find_flags(text),
            'decrypted_flags': [],
            'analysis_results': None,
            'most_likely_flags': []
        }
        
        # Get comprehensive analysis and decryption attempts
        analysis = self.smart_detector.analyze_and_decrypt(text)
        results['analysis_results'] = analysis
        
        # Look for flags in all decryption attempts
        if analysis['status'] == 'success':
            for attempt in analysis['decryption_attempts']:
                decrypted_text = attempt['result']
                flags = self.find_flags(decrypted_text)
                if flags:
                    results['decrypted_flags'].append({
                        'method': attempt['method'],
                        'confidence': attempt['confidence'],
                        'flags': flags
                    })
        
        # Sort decrypted flags by confidence and create most likely flags list
        results['decrypted_flags'].sort(key=lambda x: x['confidence'], reverse=True)
        
        # Combine original and high-confidence decrypted flags
        all_flags = set(results['original_flags'])
        for decrypted in results['decrypted_flags']:
            if decrypted['confidence'] > 0.6:  # Only include high confidence results
                all_flags.update(decrypted['flags'])
        
        results['most_likely_flags'] = list(all_flags)
        
        return results
    
    def format_flag_analysis(self, analysis_result: Dict[str, Any]) -> str:
        """Format the flag analysis results in a readable way"""
        output = []
        
        if analysis_result['original_flags']:
            output.append("=== Flags Found in Original Text ===")
            for flag in analysis_result['original_flags']:
                output.append(f"- {flag}")
        
        if analysis_result['decrypted_flags']:
            output.append("\n=== Flags Found in Decrypted Text ===")
            for result in analysis_result['decrypted_flags']:
                output.append(f"\nDecryption Method: {result['method']}")
                output.append(f"Confidence: {result['confidence']*100:.0f}%")
                for flag in result['flags']:
                    output.append(f"- {flag}")
        
        # Move Most Likely Flags to the bottom
        if analysis_result['most_likely_flags']:
            output.append("\n" + "="*50)  # Add separator line
            output.append("=== Most Likely Flags ===")
            for flag in analysis_result['most_likely_flags']:
                output.append(f"- {flag}")
        
        if not any([analysis_result['original_flags'], 
                   analysis_result['decrypted_flags'], 
                   analysis_result['most_likely_flags']]):
            output.append("No flags found in any analysis")
        
        return '\n'.join(output) 