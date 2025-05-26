import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QTabWidget,
                           QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                           QLineEdit, QTextEdit, QFileDialog, QComboBox,
                           QSpinBox, QMessageBox, QGroupBox, QRadioButton,
                           QScrollArea, QCheckBox, QSlider)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from qt_material import apply_stylesheet
import matplotlib.pyplot as plt
import numpy as np
from scipy.io import wavfile
import tempfile
import mimetypes
import binascii

from modules.crypto.classical import caesar_cipher, vigenere_cipher, rot13, atbash, try_all_caesar_shifts
from modules.stego.image import analyze_image, extract_data, hide_data
from modules.stego.audio import (analyze_audio, hide_data_in_audio, extract_data_from_audio,
                               hide_image_in_spectrogram, analyze_spectrogram)
from modules.forensics.analyzer import analyze_file
from modules.forensics.compression import check_compression, extract_compressed
from modules.utils.hexeditor import HexEditor, detect_encodings
from modules.utils.magic_numbers import MagicNumbers
from modules.forensics.external_tools import (run_steghide, run_binwalk, run_stegsolve,
                                          run_zsteg, run_exiftool, run_foremost,
                                          ExternalToolError)
from modules.crypto.ai_agent import CryptoAIAgent
from modules.crypto.basex import BaseX

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTF Swiss Army Knife")
        self.setMinimumSize(800, 600)
        
        # Initialize AI agent
        self.ai_agent = CryptoAIAgent()
        
        # Create the main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Create tabs for different tools
        tabs.addTab(self.create_auto_tab(), "AUTO")  # Add AUTO tab first
        tabs.addTab(self.create_crypto_tab(), "Cryptography")
        tabs.addTab(self.create_stego_tab(), "Image Steganography")
        tabs.addTab(self.create_audio_stego_tab(), "Audio Steganography ")
        tabs.addTab(self.create_hex_editor_tab(), "Hex Editor")
        tabs.addTab(self.create_forensics_tab(), "Forensics")
        
    def create_auto_tab(self):
        """Create the AUTO tab for automatic analysis"""
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create a scroll area for the entire content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        # Create a container widget for all content
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Input section with fixed width
        input_group = QGroupBox("Input")
        input_group.setMinimumWidth(400)  # Set minimum width
        input_layout = QVBoxLayout()
        input_layout.setSpacing(10)
        input_layout.setContentsMargins(10, 10, 10, 10)
        
        # Text input
        input_label = QLabel("Enter text to analyze:")
        self.auto_input_text = QTextEdit()
        self.auto_input_text.setPlaceholderText("Enter text to analyze for flags and encrypted content...")
        self.auto_input_text.setFixedHeight(40)
        self.auto_input_text.setMinimumWidth(380)  # Set minimum width
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.auto_input_text)
        
        # File input - using QHBoxLayout with stretch
        file_container = QWidget()
        file_layout = QHBoxLayout(file_container)
        file_layout.setContentsMargins(0, 0, 0, 0)
        file_layout.setSpacing(5)
        
        self.auto_file_path = QLineEdit()
        self.auto_file_path.setPlaceholderText("Or select a file to analyze...")
        self.auto_file_path.setFixedHeight(40)
        self.auto_file_path.setMinimumWidth(200)  # Set minimum width
        
        browse_btn = QPushButton("Browse")
        browse_btn.setFixedSize(100, 40)  # Fixed width and height
        clear_btn = QPushButton("Clear File")
        clear_btn.setFixedSize(100, 40)  # Fixed width and height
        
        browse_btn.clicked.connect(lambda: self.browse_file(self.auto_file_path))
        clear_btn.clicked.connect(lambda: self.auto_file_path.clear())
        
        file_layout.addWidget(self.auto_file_path, stretch=1)  # Give stretch priority to file path
        file_layout.addWidget(browse_btn, stretch=0)
        file_layout.addWidget(clear_btn, stretch=0)
        
        input_layout.addWidget(file_container)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Flag Format Configuration
        flag_group = QGroupBox("Flag Format Configuration")
        flag_group.setMinimumWidth(400)  # Set minimum width
        flag_layout = QVBoxLayout()
        flag_layout.setSpacing(10)
        flag_layout.setContentsMargins(10, 10, 10, 10)
        
        # Predefined formats
        predefined_container = QWidget()
        predefined_layout = QHBoxLayout(predefined_container)
        predefined_layout.setContentsMargins(0, 0, 0, 0)
        predefined_layout.setSpacing(5)
        
        format_label = QLabel("Predefined Formats:")
        format_label.setFixedWidth(120)  # Fixed width for label
        self.flag_format_combo = QComboBox()
        self.flag_format_combo.setFixedHeight(40)
        self.flag_format_combo.addItems([
            "All Formats",
            "CTF{...}",
            "flag{...}",
            "key{...}",
            "Custom Format"
        ])
        self.flag_format_combo.currentTextChanged.connect(self.update_flag_format)
        
        predefined_layout.addWidget(format_label)
        predefined_layout.addWidget(self.flag_format_combo, stretch=1)
        flag_layout.addWidget(predefined_container)
        
        # Custom format input
        custom_container = QWidget()
        custom_layout = QHBoxLayout(custom_container)
        custom_layout.setContentsMargins(0, 0, 0, 0)
        custom_layout.setSpacing(5)
        
        custom_label = QLabel("Custom Format:")
        custom_label.setFixedWidth(120)  # Fixed width for label
        self.custom_flag_format = QLineEdit()
        self.custom_flag_format.setFixedHeight(40)
        self.custom_flag_format.setPlaceholderText("Example: HTB{...} or xyz{.*}")
        self.custom_flag_format.setEnabled(False)
        
        custom_layout.addWidget(custom_label)
        custom_layout.addWidget(self.custom_flag_format, stretch=1)
        flag_layout.addWidget(custom_container)
        
        # Help text
        help_text = QLabel("Format Guide:\n"
                         "- Use {...} for standard capture\n"
                         "- Use {.*} for any characters\n"
                         "- Use {[a-zA-Z0-9_]} for specific characters\n"
                         "Example: CTF{[a-zA-Z0-9_]+}")
        help_text.setWordWrap(True)
        flag_layout.addWidget(help_text)
        
        flag_group.setLayout(flag_layout)
        layout.addWidget(flag_group)
        
        # Options
        options_group = QGroupBox("Analysis Options")
        options_group.setMinimumWidth(400)  # Set minimum width
        options_layout = QVBoxLayout()
        options_layout.setSpacing(10)
        options_layout.setContentsMargins(10, 10, 10, 10)
        
        # Checkboxes for different analysis types
        self.check_crypto = QCheckBox("Analyze Cryptography")
        self.check_crypto.setChecked(True)
        self.check_encodings = QCheckBox("Check Common Encodings")
        self.check_encodings.setChecked(True)
        self.check_patterns = QCheckBox("Search for Flag Patterns")
        self.check_patterns.setChecked(True)
        
        options_layout.addWidget(self.check_crypto)
        options_layout.addWidget(self.check_encodings)
        options_layout.addWidget(self.check_patterns)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Analyze button
        analyze_btn = QPushButton("Start Analysis")
        analyze_btn.setFixedHeight(40)
        analyze_btn.setMinimumWidth(200)  # Set minimum width
        analyze_btn.clicked.connect(self.process_auto_analysis)
        layout.addWidget(analyze_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Results
        results_group = QGroupBox("Analysis Results")
        results_group.setMinimumWidth(400)  # Set minimum width
        results_layout = QVBoxLayout()
        results_layout.setSpacing(10)
        results_layout.setContentsMargins(10, 10, 10, 10)
        
        self.auto_results = QTextEdit()
        self.auto_results.setReadOnly(True)
        self.auto_results.setMinimumHeight(200)  # Set minimum height for results
        results_layout.addWidget(self.auto_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Add stretch at the bottom to keep everything aligned to the top
        layout.addStretch()
        
        # Set the content widget in the scroll area
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)
        
        return widget
        
    def process_auto_analysis(self):
        """Process the automatic analysis"""
        # Get input text and file path
        text = self.auto_input_text.toPlainText()
        file_path = self.auto_file_path.text()
        
        if not text and not file_path:
            QMessageBox.warning(self, "Error", "Please enter text or select a file to analyze")
            return
            
        try:
            # Clear previous results
            self.auto_results.clear()
            
            # Store all found flags for final display
            all_most_likely_flags = set()
            all_decoded_results = []
            
            # Get custom flag pattern if specified
            custom_pattern = self.get_current_flag_pattern()
            if custom_pattern:
                self.ai_agent.flag_patterns = custom_pattern
            
            # Initialize analyzers
            basex = BaseX()
            
            # Process text input if present
            if text:
                self.auto_results.append("=== Text Analysis ===\n")
                
                # Try Caesar cipher shifts first
                caesar_results = try_all_caesar_shifts(text, custom_pattern)
                if caesar_results['likely_flags']:
                    self.auto_results.append("Caesar Cipher Analysis:")
                    for shift, decoded, confidence in caesar_results['likely_flags']:
                        self.auto_results.append(f"➜ Shift {shift} ({confidence*100:.1f}% confidence):")
                        self.auto_results.append(f"  {decoded}\n")
                        all_most_likely_flags.add(decoded)
                
                # Try BaseX decoding
                base_results = basex.try_all_decoding(text, custom_pattern)
                
                # Add any flags found from base decoding
                if base_results['likely_flags']:
                    self.auto_results.append("Base Encoding Analysis:")
                    for method, decoded, confidence in base_results['likely_flags']:
                        self.auto_results.append(f"➜ {method} ({confidence*100:.1f}% confidence):")
                        self.auto_results.append(f"  {decoded}\n")
                        all_most_likely_flags.add(decoded)
                
                # Add other promising decoded results
                if base_results['printable_results']:
                    self.auto_results.append("Other Base Decoded Results:")
                    for method, decoded, confidence in base_results['printable_results']:
                        if confidence > 0.8:  # Only show high confidence results
                            self.auto_results.append(f"➜ {method} ({confidence*100:.1f}% confidence):")
                            self.auto_results.append(f"  {decoded}\n")
                            all_decoded_results.append(decoded)
                
                # Run AI agent analysis
                results = self.ai_agent.analyze_text_for_flags(text)
                
                # Store most likely flags
                all_most_likely_flags.update(results.get('most_likely_flags', []))
                
                # Remove most likely flags section from formatted results
                results['most_likely_flags'] = []  # Clear to prevent showing here
                formatted_results = self.ai_agent.format_flag_analysis(results)
                
                # Add original analysis results if available
                if results['analysis_results'] and results['analysis_results']['status'] == 'success':
                    self.auto_results.append("\n=== Detailed Analysis ===\n")
                    for attempt in results['analysis_results']['decryption_attempts']:
                        self.auto_results.append(f"\nTried {attempt['method']}:")
                        self.auto_results.append(f"Confidence: {attempt['confidence']*100:.0f}%")
                        self.auto_results.append(f"Result: {attempt['result']}\n")
                        
                        # Check if result contains flag pattern
                        if basex.looks_like_flag(attempt['result'], custom_pattern):
                            all_most_likely_flags.add(attempt['result'])
                
                # Add formatted results (without most likely flags)
                self.auto_results.append(formatted_results)
            
            # Process file input if present
            if file_path:
                self.auto_results.append("\n=== File Analysis ===\n")
                
                # Determine file type
                mime_type, _ = mimetypes.guess_type(file_path)
                is_text = mime_type and ('text' in mime_type or mime_type in ['application/json', 'application/xml'])
                
                if is_text:
                    # Handle text file
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_text = f.read()
                    
                    # Try Caesar cipher shifts
                    caesar_results = try_all_caesar_shifts(file_text, custom_pattern)
                    if caesar_results['likely_flags']:
                        self.auto_results.append("Caesar Cipher Analysis:")
                        for shift, decoded, confidence in caesar_results['likely_flags']:
                            self.auto_results.append(f"➜ Shift {shift} ({confidence*100:.1f}% confidence):")
                            self.auto_results.append(f"  {decoded}\n")
                            all_most_likely_flags.add(decoded)
                    
                    # Try BaseX decoding
                    base_results = basex.try_all_decoding(file_text, custom_pattern)
                    
                    # Add any flags found from base decoding
                    if base_results['likely_flags']:
                        self.auto_results.append("Base Encoding Analysis:")
                        for method, decoded, confidence in base_results['likely_flags']:
                            self.auto_results.append(f"➜ {method} ({confidence*100:.1f}% confidence):")
                            self.auto_results.append(f"  {decoded}\n")
                            all_most_likely_flags.add(decoded)
                    
                    # Run AI agent analysis
                    results = self.ai_agent.analyze_text_for_flags(file_text)
                    all_most_likely_flags.update(results.get('most_likely_flags', []))
                    results['most_likely_flags'] = []  # Clear to prevent showing here
                    formatted_results = self.ai_agent.format_flag_analysis(results)
                    self.auto_results.append(formatted_results)
                else:
                    # Handle binary file
                    # First try to find any text/string patterns in the binary
                    with open(file_path, 'rb') as f:
                        binary_data = f.read()
                    
                    # Extract strings from binary
                    strings = []
                    current_string = ""
                    for byte in binary_data:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += chr(byte)
                        elif current_string:
                            if len(current_string) >= 4:  # Only keep strings of 4+ chars
                                strings.append(current_string)
                            current_string = ""
                    if current_string and len(current_string) >= 4:
                        strings.append(current_string)
                    
                    # Analyze extracted strings
                    if strings:
                        self.auto_results.append("Analyzing strings found in binary file...\n")
                        for string in strings:
                            # Try Caesar cipher shifts
                            caesar_results = try_all_caesar_shifts(string, custom_pattern)
                            if caesar_results['likely_flags']:
                                for shift, decoded, confidence in caesar_results['likely_flags']:
                                    all_most_likely_flags.add(decoded)
                            
                            # Try BaseX decoding
                            base_results = basex.try_all_decoding(string, custom_pattern)
                            if base_results['likely_flags']:
                                for method, decoded, confidence in base_results['likely_flags']:
                                    all_most_likely_flags.add(decoded)
                        
                        combined_text = "\n".join(strings)
                        results = self.ai_agent.analyze_text_for_flags(combined_text)
                        all_most_likely_flags.update(results.get('most_likely_flags', []))
                        results['most_likely_flags'] = []  # Clear to prevent showing here
                        formatted_results = self.ai_agent.format_flag_analysis(results)
                        self.auto_results.append(formatted_results)
                    
                    # Run forensics analysis
                    try:
                        from modules.forensics.analyzer import analyze_file
                        forensics_results, formatted_forensics = analyze_file(file_path, use_external_tools=True)
                        
                        if forensics_results:
                            self.auto_results.append("\n=== Forensics Analysis ===\n")
                            self.auto_results.append(formatted_forensics)
                    except Exception as e:
                        self.auto_results.append(f"\nForensics analysis failed: {str(e)}")
                    
                    # If it's an image, try stego analysis
                    if mime_type and 'image' in mime_type:
                        try:
                            from modules.stego.image import analyze_image
                            stego_results = analyze_image(file_path)
                            if stego_results:
                                self.auto_results.append("\n=== Image Steganography Analysis ===\n")
                                self.auto_results.append(str(stego_results))
                        except Exception as e:
                            self.auto_results.append(f"\nImage stego analysis failed: {str(e)}")
                    
                    # If it's an audio file, try audio analysis
                    elif mime_type and 'audio' in mime_type:
                        try:
                            from modules.stego.audio import analyze_audio, analyze_spectrogram
                            audio_results = analyze_audio(file_path)
                            if audio_results:
                                self.auto_results.append("\n=== Audio Analysis ===\n")
                                self.auto_results.append(str(audio_results))
                            
                            # Also analyze spectrogram
                            spec_results = analyze_spectrogram(file_path)
                            if spec_results:
                                self.auto_results.append("\n=== Spectrogram Analysis ===\n")
                                self.auto_results.append(str(spec_results))
                        except Exception as e:
                            self.auto_results.append(f"\nAudio analysis failed: {str(e)}")
            
            # Display all collected flags at the very end
            if all_most_likely_flags:
                self.auto_results.append("\n" + "="*80)  # Longer separator
                self.auto_results.append("\n=== POTENTIAL FLAGS FOUND ===")
                self.auto_results.append("="*80 + "\n")  # Longer separator
                for flag in sorted(all_most_likely_flags):  # Sort flags for consistency
                    self.auto_results.append(f"➜ {flag}")
                self.auto_results.append("\n" + "="*80)  # Longer separator
            
            # Restore default patterns after analysis
            if custom_pattern:
                self.ai_agent.flag_patterns = [
                    r'[A-Za-z0-9_]{2,8}{[^}]+}',  # Generic flag format XXX{...}
                    r'flag{[^}]+}',                # Explicit flag{...}
                    r'ctf{[^}]+}',                 # CTF{...}
                    r'key{[^}]+}'                  # key{...}
                ]
            
            # Scroll to the bottom to show the flags
            self.auto_results.verticalScrollBar().setValue(
                self.auto_results.verticalScrollBar().maximum()
            )
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Analysis failed: {str(e)}")
            return
        
    def create_crypto_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Cipher type selection
        cipher_layout = QHBoxLayout()
        cipher_label = QLabel("Cipher:")
        self.cipher_combo = QComboBox()
        self.cipher_combo.addItems([
            "Caesar", "Vigenère", "ROT13", "Atbash",
            "BaseX", "Hex", "Binary", "Decimal", "AMF",
            "AES (ECB)", "AES (CBC)", "DES", "Triple DES", "XOR"
        ])
        cipher_layout.addWidget(cipher_label)
        cipher_layout.addWidget(self.cipher_combo)
        layout.addLayout(cipher_layout)
        
        # Input text
        input_label = QLabel("Input Text:")
        self.input_text = QTextEdit()
        layout.addWidget(input_label)
        layout.addWidget(self.input_text)
        
        # Real-time analysis
        analysis_group = QGroupBox("Real-time Analysis")
        analysis_layout = QVBoxLayout()
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setMinimumHeight(150)
        analysis_layout.addWidget(self.analysis_text)
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        
        # Cipher specific options
        self.cipher_options = QWidget()
        self.cipher_options_layout = QHBoxLayout(self.cipher_options)
        
        # Create all the option widgets
        self.shift_slider = QSlider(Qt.Orientation.Horizontal)
        self.shift_slider.setRange(1, 25)
        self.shift_slider.setValue(3)
        self.shift_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.shift_slider.setTickInterval(1)
        self.shift_value_label = QLabel("3")
        self.shift_slider.valueChanged.connect(lambda v: self.shift_value_label.setText(str(v)))
        self.try_all_shifts_btn = QPushButton("Try All Shifts")
        self.try_all_shifts_btn.clicked.connect(self.try_all_caesar_shifts)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter key...")
        
        self.aes_key_input = QLineEdit()
        self.aes_key_input.setPlaceholderText("Enter AES key (16, 24, or 32 bytes)...")
        
        self.des_key_input = QLineEdit()
        self.des_key_input.setPlaceholderText("Enter DES key (8 bytes)...")
        
        self.triple_des_key_input = QLineEdit()
        self.triple_des_key_input.setPlaceholderText("Enter Triple DES key (24 bytes)...")
        
        self.xor_key_input = QLineEdit()
        self.xor_key_input.setPlaceholderText("Enter XOR key...")
        
        # Add BaseX combo box
        self.basex_combo = QComboBox()
        self.basex_combo.addItems([
            "Base16", "Base32", "Base32hex", "Base58",
            "Base64", "Base85", "Base91"
        ])
        
        self.update_cipher_options()
        layout.addWidget(self.cipher_options)
        
        # Buttons
        button_layout = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")
        button_layout.addWidget(encrypt_btn)
        button_layout.addWidget(decrypt_btn)
        layout.addLayout(button_layout)
        
        # Output text
        output_label = QLabel("Output Text:")
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(output_label)
        layout.addWidget(self.output_text)
        
        # Connect signals
        self.cipher_combo.currentTextChanged.connect(self.update_cipher_options)
        encrypt_btn.clicked.connect(lambda: self.process_crypto(False))
        decrypt_btn.clicked.connect(lambda: self.process_crypto(True))
        self.input_text.textChanged.connect(self.update_crypto_analysis)
        
        return widget
        
    def create_stego_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Mode selection
        mode_group = QGroupBox("Operation Mode")
        mode_layout = QHBoxLayout()
        self.analyze_radio = QRadioButton("Analyze")
        self.extract_radio = QRadioButton("Extract")
        self.hide_radio = QRadioButton("Hide")
        self.analyze_radio.setChecked(True)
        mode_layout.addWidget(self.analyze_radio)
        mode_layout.addWidget(self.extract_radio)
        mode_layout.addWidget(self.hide_radio)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # File selection
        file_layout = QHBoxLayout()
        self.stego_file_path = QLineEdit()
        self.stego_file_path.setPlaceholderText("Select an image file...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: self.browse_file(self.stego_file_path, "Image files (*.png *.jpg *.jpeg *.bmp)"))
        file_layout.addWidget(self.stego_file_path)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        # Hide data options
        self.hide_options = QWidget()
        hide_layout = QVBoxLayout(self.hide_options)
        self.hide_data_input = QTextEdit()
        self.hide_data_input.setPlaceholderText("Enter text to hide...")
        self.hide_data_input.setMaximumHeight(100)
        hide_layout.addWidget(QLabel("Text to Hide:"))
        hide_layout.addWidget(self.hide_data_input)
        
        output_file_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_path.setPlaceholderText("Output image path...")
        output_browse_btn = QPushButton("Browse")
        output_browse_btn.clicked.connect(lambda: self.save_file_dialog(self.output_file_path, "Image files (*.png)"))
        output_file_layout.addWidget(self.output_file_path)
        output_file_layout.addWidget(output_browse_btn)
        hide_layout.addWidget(QLabel("Output File:"))
        hide_layout.addLayout(output_file_layout)
        
        layout.addWidget(self.hide_options)
        self.hide_options.hide()
        
        # Action button
        self.stego_action_btn = QPushButton("Analyze Image")
        layout.addWidget(self.stego_action_btn)
        
        # Results
        results_label = QLabel("Results:")
        self.stego_results = QTextEdit()
        self.stego_results.setReadOnly(True)
        layout.addWidget(results_label)
        layout.addWidget(self.stego_results)
        
        # Connect signals
        self.analyze_radio.toggled.connect(self.update_stego_mode)
        self.extract_radio.toggled.connect(self.update_stego_mode)
        self.hide_radio.toggled.connect(self.update_stego_mode)
        self.stego_action_btn.clicked.connect(self.process_stego)
        
        return widget
        
    def create_audio_stego_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Mode selection
        mode_group = QGroupBox("Operation Mode")
        mode_layout = QHBoxLayout()
        self.analyze_audio_radio = QRadioButton("Analyze Audio")
        self.hide_audio_radio = QRadioButton("Hide Data")
        self.image_to_audio_radio = QRadioButton("Image to Spectrogram")
        self.analyze_audio_radio.setChecked(True)
        mode_layout.addWidget(self.analyze_audio_radio)
        mode_layout.addWidget(self.hide_audio_radio)
        mode_layout.addWidget(self.image_to_audio_radio)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        # Input file selection
        input_layout = QHBoxLayout()
        self.audio_file_path = QLineEdit()
        self.audio_file_path.setPlaceholderText("Select a WAV audio file...")
        self.browse_btn = QPushButton("Browse")  # Store as class member
        self.browse_btn.clicked.connect(lambda: self.browse_file(self.audio_file_path, "WAV files (*.wav)"))
        input_layout.addWidget(self.audio_file_path)
        input_layout.addWidget(self.browse_btn)
        file_layout.addLayout(input_layout)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Hide data options
        self.hide_audio_options = QWidget()
        hide_layout = QVBoxLayout(self.hide_audio_options)
        
        # Data input
        data_group = QGroupBox("Data to Hide")
        data_layout = QVBoxLayout()
        self.hide_audio_data_input = QTextEdit()
        self.hide_audio_data_input.setPlaceholderText("Enter text to hide...")
        self.hide_audio_data_input.setMaximumHeight(100)
        data_layout.addWidget(self.hide_audio_data_input)
        data_group.setLayout(data_layout)
        hide_layout.addWidget(data_group)
        
        # Output file
        output_group = QGroupBox("Output File")
        output_layout = QHBoxLayout()
        self.output_audio_path = QLineEdit()
        self.output_audio_path.setPlaceholderText("Output WAV file path...")
        output_browse_btn = QPushButton("Browse")
        output_browse_btn.clicked.connect(lambda: self.save_file_dialog(self.output_audio_path, "WAV files (*.wav)"))
        output_layout.addWidget(self.output_audio_path)
        output_layout.addWidget(output_browse_btn)
        output_group.setLayout(output_layout)
        hide_layout.addWidget(output_group)
        
        layout.addWidget(self.hide_audio_options)
        self.hide_audio_options.hide()
        
        # Image to Spectrogram options
        self.image_to_audio_options = QWidget()
        image_layout = QVBoxLayout(self.image_to_audio_options)
        
        # Duration setting
        duration_group = QGroupBox("Audio Settings")
        duration_layout = QHBoxLayout()
        duration_layout.addWidget(QLabel("Duration (seconds):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(1, 30)
        self.duration_spin.setValue(5)
        duration_layout.addWidget(self.duration_spin)
        duration_group.setLayout(duration_layout)
        image_layout.addWidget(duration_group)
        
        # Output file for image to audio
        image_output_group = QGroupBox("Output Audio File")
        image_output_layout = QHBoxLayout()
        self.image_output_path = QLineEdit()
        self.image_output_path.setPlaceholderText("Output WAV file path...")
        image_output_browse_btn = QPushButton("Browse")
        image_output_browse_btn.clicked.connect(lambda: self.save_file_dialog(self.image_output_path, "WAV files (*.wav)"))
        image_output_layout.addWidget(self.image_output_path)
        image_output_layout.addWidget(image_output_browse_btn)
        image_output_group.setLayout(image_output_layout)
        image_layout.addWidget(image_output_group)
        
        layout.addWidget(self.image_to_audio_options)
        self.image_to_audio_options.hide()
        
        # Action button
        self.audio_stego_action_btn = QPushButton("Analyze Audio")
        layout.addWidget(self.audio_stego_action_btn)
        
        # Results
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        # Add spectrogram label
        self.spectrogram_label = QLabel()
        self.spectrogram_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spectrogram_label.setMinimumHeight(300)
        results_layout.addWidget(self.spectrogram_label)
        
        # Text results
        self.audio_stego_results = QTextEdit()
        self.audio_stego_results.setReadOnly(True)
        self.audio_stego_results.setFont(QApplication.font())
        results_layout.addWidget(self.audio_stego_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Connect signals
        self.analyze_audio_radio.toggled.connect(self.update_audio_stego_mode)
        self.hide_audio_radio.toggled.connect(self.update_audio_stego_mode)
        self.image_to_audio_radio.toggled.connect(self.update_audio_stego_mode)
        self.audio_stego_action_btn.clicked.connect(self.process_audio_stego)
        
        return widget
        
    def create_hex_editor_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # File operations
        file_group = QGroupBox("File Operations")
        file_layout = QHBoxLayout()
        
        load_btn = QPushButton("Load File")
        save_btn = QPushButton("Save As")
        file_layout.addWidget(load_btn)
        file_layout.addWidget(save_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Magic number suggestions
        self.magic_group = QGroupBox("File Format Detection")
        magic_layout = QVBoxLayout()
        
        self.format_label = QLabel("No file loaded")
        magic_layout.addWidget(self.format_label)
        
        # Add auto-fix button
        auto_fix_layout = QHBoxLayout()
        self.auto_fix_btn = QPushButton("Auto-Fix Header")
        self.auto_fix_btn.setVisible(False)
        self.auto_fix_btn.clicked.connect(self.auto_fix_header)
        auto_fix_layout.addWidget(self.auto_fix_btn)
        magic_layout.addLayout(auto_fix_layout)
        
        self.header_combo = QComboBox()
        self.header_combo.setVisible(False)
        magic_layout.addWidget(self.header_combo)
        
        self.apply_header_btn = QPushButton("Apply Selected Header")
        self.apply_header_btn.setVisible(False)
        self.apply_header_btn.clicked.connect(self.apply_magic_header)
        magic_layout.addWidget(self.apply_header_btn)
        
        self.magic_group.setLayout(magic_layout)
        layout.addWidget(self.magic_group)
        
        # Hex view with editing support
        self.hex_view = QTextEdit()
        self.hex_view.setFont(QApplication.font())
        self.hex_view.textChanged.connect(self.on_hex_edit)
        layout.addWidget(self.hex_view)
        
        # Operations group
        ops_group = QGroupBox("Operations")
        ops_layout = QVBoxLayout()
        
        # Pattern search
        search_layout = QHBoxLayout()
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("Enter pattern (hex or text)...")
        search_btn = QPushButton("Find Pattern")
        search_layout.addWidget(self.pattern_input)
        search_layout.addWidget(search_btn)
        ops_layout.addLayout(search_layout)
        
        # Encoding operations
        encoding_layout = QHBoxLayout()
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(['hex', 'ascii', 'utf-8', 'base64'])
        decode_btn = QPushButton("Decode As")
        encoding_layout.addWidget(self.encoding_combo)
        encoding_layout.addWidget(decode_btn)
        ops_layout.addLayout(encoding_layout)
        
        # Edit operations
        edit_layout = QHBoxLayout()
        self.edit_offset = QLineEdit()
        self.edit_offset.setPlaceholderText("Offset (hex)")
        self.edit_value = QLineEdit()
        self.edit_value.setPlaceholderText("New value (hex)")
        edit_btn = QPushButton("Edit Bytes")
        edit_layout.addWidget(self.edit_offset)
        edit_layout.addWidget(self.edit_value)
        edit_layout.addWidget(edit_btn)
        ops_layout.addLayout(edit_layout)
        
        ops_group.setLayout(ops_layout)
        layout.addWidget(ops_group)
        
        # Results
        results_label = QLabel("Results/Decoded Data:")
        self.hex_results = QTextEdit()
        self.hex_results.setReadOnly(True)
        layout.addWidget(results_label)
        layout.addWidget(self.hex_results)
        
        # Connect signals
        load_btn.clicked.connect(self.load_hex_file)
        save_btn.clicked.connect(self.save_hex_file)
        search_btn.clicked.connect(self.find_hex_pattern)
        decode_btn.clicked.connect(self.decode_hex_data)
        edit_btn.clicked.connect(self.edit_hex_bytes)
        
        return widget
        
    def create_forensics_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)  # Increased spacing between sections
        
        # File selection - Fixed size section with more height
        file_group = QGroupBox("File Selection")
        file_group.setFixedHeight(150)  # Increased height
        file_layout = QHBoxLayout()
        file_layout.setContentsMargins(8, 8, 8, 8)  # Increased padding
        
        # Wider fixed width container for file path and button
        file_container = QWidget()
        file_container.setFixedWidth(800)  # Increased width
        container_layout = QHBoxLayout(file_container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(15)  # Added spacing between elements
        
        self.forensics_file_path = QLineEdit()
        self.forensics_file_path.setFixedWidth(650)  # Increased width
        self.forensics_file_path.setMinimumHeight(30)  # Added minimum height
        self.forensics_file_path.setPlaceholderText("Select a file to analyze...")
        
        browse_btn = QPushButton("Browse")
        browse_btn.setFixedWidth(120)  # Increased width
        browse_btn.setMinimumHeight(30)  # Added minimum height
        browse_btn.clicked.connect(lambda: self.browse_file(self.forensics_file_path))
        
        container_layout.addWidget(self.forensics_file_path)
        container_layout.addWidget(browse_btn)
        
        file_layout.addWidget(file_container)
        file_layout.addStretch()
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Analysis options - Scrollable section with reduced height
        options_scroll = QScrollArea()
        options_scroll.setWidgetResizable(True)
        options_scroll.setFixedHeight(250)  # Reduced height
        options_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        options_widget = QWidget()
        options_layout = QVBoxLayout(options_widget)
        options_layout.setSpacing(10)
        options_layout.setContentsMargins(10, 10, 10, 10)
        
        options_group = QGroupBox("Analysis Options")
        options_inner_layout = QVBoxLayout()
        options_inner_layout.setSpacing(10)
        
        # Built-in analysis options
        builtin_group = QGroupBox("Built-in Analysis")
        builtin_layout = QHBoxLayout()
        builtin_layout.setSpacing(20)
        
        self.check_metadata = QCheckBox("Extract Metadata")
        self.check_metadata.setChecked(True)
        self.check_compression = QCheckBox("Check Compression")
        self.check_compression.setChecked(True)
        self.check_signatures = QCheckBox("Check Signatures")
        self.check_signatures.setChecked(True)
        
        builtin_layout.addWidget(self.check_metadata)
        builtin_layout.addWidget(self.check_compression)
        builtin_layout.addWidget(self.check_signatures)
        builtin_layout.addStretch()
        builtin_group.setLayout(builtin_layout)
        options_inner_layout.addWidget(builtin_group)
        
        # External tools options
        external_group = QGroupBox("External Tools")
        external_layout = QVBoxLayout()
        external_layout.setSpacing(10)
        
        # First row of tools
        tools_row1 = QHBoxLayout()
        tools_row1.setSpacing(20)
        self.check_binwalk = QCheckBox("Binwalk")
        self.check_binwalk.setChecked(True)
        self.check_foremost = QCheckBox("Foremost")
        self.check_foremost.setChecked(True)
        self.check_exiftool = QCheckBox("ExifTool")
        self.check_exiftool.setChecked(True)
        tools_row1.addWidget(self.check_binwalk)
        tools_row1.addWidget(self.check_foremost)
        tools_row1.addWidget(self.check_exiftool)
        tools_row1.addStretch()
        external_layout.addLayout(tools_row1)
        
        # Second row of tools
        tools_row2 = QHBoxLayout()
        tools_row2.setSpacing(20)
        self.check_steghide = QCheckBox("Steghide")
        self.check_steghide.setChecked(True)
        self.check_stegsolve = QCheckBox("Stegsolve")
        self.check_stegsolve.setChecked(True)
        self.check_zsteg = QCheckBox("Zsteg")
        self.check_zsteg.setChecked(True)
        tools_row2.addWidget(self.check_steghide)
        tools_row2.addWidget(self.check_stegsolve)
        tools_row2.addWidget(self.check_zsteg)
        tools_row2.addStretch()
        external_layout.addLayout(tools_row2)
        
        # Password for Steghide
        password_layout = QHBoxLayout()
        password_layout.setContentsMargins(0, 5, 0, 5)
        self.steghide_password = QLineEdit()
        self.steghide_password.setFixedWidth(200)  # Fixed width
        self.steghide_password.setPlaceholderText("Steghide password (optional)")
        self.steghide_password.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.steghide_password)
        password_layout.addStretch()
        external_layout.addLayout(password_layout)
        
        external_group.setLayout(external_layout)
        options_inner_layout.addWidget(external_group)
        
        options_group.setLayout(options_inner_layout)
        options_layout.addWidget(options_group)
        options_layout.addStretch()
        
        options_scroll.setWidget(options_widget)
        layout.addWidget(options_scroll)
        
        # Action buttons - Fixed size section with more height
        button_container = QWidget()
        button_container.setFixedHeight(60)  # Increased height
        button_layout = QHBoxLayout(button_container)
        button_layout.setSpacing(15)  # Increased spacing
        button_layout.setContentsMargins(15, 0, 15, 0)  # Added horizontal padding
        
        analyze_btn = QPushButton("Analyze File")
        analyze_btn.setFixedWidth(200)  # Increased width
        analyze_btn.setMinimumHeight(35)  # Increased height
        analyze_btn.clicked.connect(self.analyze_forensics)
        
        extract_btn = QPushButton("Extract Contents")
        extract_btn.setFixedWidth(200)  # Increased width
        extract_btn.setMinimumHeight(35)  # Increased height
        extract_btn.clicked.connect(self.extract_forensics)
        
        button_layout.addWidget(analyze_btn)
        button_layout.addWidget(extract_btn)
        button_layout.addStretch()
        layout.addWidget(button_container)
        
        # Results - Scrollable section with reduced height
        results_scroll = QScrollArea()
        results_scroll.setWidgetResizable(True)
        results_scroll.setFixedHeight(250)  # Reduced height
        
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(10, 10, 10, 10)
        
        results_group = QGroupBox("Analysis Results")
        results_inner_layout = QVBoxLayout()
        
        # Results text area
        self.forensics_results = QTextEdit()
        self.forensics_results.setReadOnly(True)
        self.forensics_results.setFont(QApplication.font())
        results_inner_layout.addWidget(self.forensics_results)
        
        # Extracted files list
        self.extracted_files_list = QTextEdit()
        self.extracted_files_list.setReadOnly(True)
        self.extracted_files_list.setFixedHeight(100)  # Fixed height
        self.extracted_files_list.setVisible(False)
        results_inner_layout.addWidget(self.extracted_files_list)
        
        results_group.setLayout(results_inner_layout)
        results_layout.addWidget(results_group)
        
        results_scroll.setWidget(results_widget)
        layout.addWidget(results_scroll)
        
        return widget
    
    def update_cipher_options(self):
        # Clear previous options
        while self.cipher_options_layout.count():
            item = self.cipher_options_layout.takeAt(0)
            if item.widget():
                item.widget().hide()
        
        cipher = self.cipher_combo.currentText()
        if cipher == "Caesar":
            shift_container = QWidget()
            shift_layout = QHBoxLayout(shift_container)
            shift_layout.setContentsMargins(0, 0, 0, 0)
            
            shift_layout.addWidget(QLabel("Shift:"))
            shift_layout.addWidget(self.shift_slider)
            shift_layout.addWidget(self.shift_value_label)
            shift_layout.addWidget(self.try_all_shifts_btn)
            
            self.cipher_options_layout.addWidget(shift_container)
        elif cipher == "Vigenère":
            self.cipher_options_layout.addWidget(QLabel("Key:"))
            self.cipher_options_layout.addWidget(self.key_input)
        elif cipher in ["AES (ECB)", "AES (CBC)"]:
            self.cipher_options_layout.addWidget(QLabel("Key:"))
            self.cipher_options_layout.addWidget(self.aes_key_input)
        elif cipher == "DES":
            self.cipher_options_layout.addWidget(QLabel("Key:"))
            self.cipher_options_layout.addWidget(self.des_key_input)
        elif cipher == "Triple DES":
            self.cipher_options_layout.addWidget(QLabel("Key:"))
            self.cipher_options_layout.addWidget(self.triple_des_key_input)
        elif cipher == "XOR":
            self.cipher_options_layout.addWidget(QLabel("Key:"))
            self.cipher_options_layout.addWidget(self.xor_key_input)
        elif cipher == "BaseX":
            self.cipher_options_layout.addWidget(QLabel("Base Type:"))
            self.cipher_options_layout.addWidget(self.basex_combo)
        # Base64, Hex, Binary, Decimal, AMF, ROT13, and Atbash don't need options
    
    def update_stego_mode(self):
        if self.hide_radio.isChecked():
            self.hide_options.show()
            self.stego_action_btn.setText("Hide Data")
        else:
            self.hide_options.hide()
            self.stego_action_btn.setText("Analyze Image" if self.analyze_radio.isChecked() else "Extract Data")
    
    def process_crypto(self, decrypt=False):
        cipher = self.cipher_combo.currentText()
        text = self.input_text.toPlainText()
        
        try:
            from modules.crypto.advanced import AdvancedCrypto
            crypto = AdvancedCrypto()
            basex = BaseX()
            
            if cipher == "Caesar":
                shift = self.shift_slider.value()
                result = caesar_cipher(text, shift, decrypt)
            elif cipher == "Vigenère":
                key = self.key_input.text()
                if not key:
                    raise ValueError("Key is required for Vigenère cipher")
                result = vigenere_cipher(text, key, decrypt)
            elif cipher == "ROT13":
                result = rot13(text)  # ROT13 is its own inverse
            elif cipher == "Atbash":
                result = atbash(text)  # Atbash is its own inverse
            elif cipher == "BaseX":
                base_type = self.basex_combo.currentText()
                if decrypt:
                    method = getattr(basex, f"decode_{base_type.lower()}")
                    result = method(text).decode('utf-8', errors='ignore')
                else:
                    method = getattr(basex, f"encode_{base_type.lower()}")
                    result = method(text)
            elif cipher == "Hex":
                if decrypt:
                    result = crypto.decode_hex(text).decode('utf-8', errors='ignore')
                else:
                    result = crypto.encode_hex(text)
            elif cipher == "Binary":
                if decrypt:
                    result = crypto.decode_binary(text).decode('utf-8', errors='ignore')
                else:
                    result = crypto.encode_binary(text)
            elif cipher == "Decimal":
                if decrypt:
                    result = crypto.decode_decimal(text).decode('utf-8', errors='ignore')
                else:
                    result = crypto.encode_decimal(text)
            elif cipher == "AMF":
                if decrypt:
                    result = crypto.decode_amf(text.encode())
                else:
                    result = crypto.encode_amf(text).hex()
            elif cipher in ["AES (ECB)", "AES (CBC)"]:
                key = self.aes_key_input.text()
                if not key:
                    raise ValueError("Key is required for AES")
                mode = 'CBC' if cipher == "AES (CBC)" else 'ECB'
                if decrypt:
                    try:
                        data = bytes.fromhex(text)
                        result = crypto.decrypt_aes(data, key, mode).decode('utf-8', errors='ignore')
                    except ValueError:
                        raise ValueError("Invalid hex input for AES decryption")
                else:
                    result = crypto.encrypt_aes(text, key, mode).hex()
            elif cipher == "DES":
                key = self.des_key_input.text()
                if not key:
                    raise ValueError("Key is required for DES")
                if decrypt:
                    try:
                        data = bytes.fromhex(text)
                        result = crypto.decrypt_des(data, key).decode('utf-8', errors='ignore')
                    except ValueError:
                        raise ValueError("Invalid hex input for DES decryption")
                else:
                    result = crypto.encrypt_des(text, key).hex()
            elif cipher == "Triple DES":
                key = self.triple_des_key_input.text()
                if not key:
                    raise ValueError("Key is required for Triple DES")
                if decrypt:
                    try:
                        data = bytes.fromhex(text)
                        result = crypto.decrypt_triple_des(data, key).decode('utf-8', errors='ignore')
                    except ValueError:
                        raise ValueError("Invalid hex input for Triple DES decryption")
                else:
                    result = crypto.encrypt_triple_des(text, key).hex()
            elif cipher == "XOR":
                key = self.xor_key_input.text()
                if not key:
                    raise ValueError("Key is required for XOR")
                result = crypto.xor_with_key(text, key).hex() if not decrypt else \
                        crypto.xor_with_key(bytes.fromhex(text), key).decode('utf-8', errors='ignore')
            
            self.output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def process_stego(self):
        file_path = self.stego_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select an image file")
            return
        
        try:
            if self.analyze_radio.isChecked():
                results = analyze_image(file_path)
                self.stego_results.setPlainText(str(results))
            elif self.extract_radio.isChecked():
                data = extract_data(file_path)
                self.stego_results.setPlainText(str(data) if data else "No hidden data found")
            else:  # Hide data
                output_path = self.output_file_path.text()
                if not output_path:
                    QMessageBox.warning(self, "Warning", "Please specify output file path")
                    return
                data = self.hide_data_input.toPlainText()
                if not data:
                    QMessageBox.warning(self, "Warning", "Please enter data to hide")
                    return
                if hide_data(file_path, data, output_path):
                    self.stego_results.setPlainText("Data hidden successfully!")
                else:
                    self.stego_results.setPlainText("Failed to hide data")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def browse_file(self, line_edit, file_filter="All files (*)"):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", file_filter)
        if file_path:
            line_edit.setText(file_path)
    
    def save_file_dialog(self, line_edit, file_filter="All files (*)"):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", file_filter)
        if file_path:
            line_edit.setText(file_path)
    
    def analyze_forensics(self):
        file_path = self.forensics_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file")
            return
            
        try:
            self.forensics_results.setPlainText("Analyzing file...")
            QApplication.processEvents()  # Update UI
            
            # Get file type to determine which tools to use
            mime_type, _ = mimetypes.guess_type(file_path)
            
            # Configure which external tools to use
            use_external_tools = any([
                self.check_binwalk.isChecked(),
                self.check_foremost.isChecked(),
                self.check_exiftool.isChecked(),
                self.check_steghide.isChecked(),
                self.check_stegsolve.isChecked(),
                self.check_zsteg.isChecked()
            ])
            
            # Create temporary directory for tool outputs
            with tempfile.TemporaryDirectory() as temp_dir:
                results = {}
                
                # Run built-in analysis
                results, formatted_results = analyze_file(
                    file_path,
                    use_external_tools=use_external_tools
                )
                
                # Check if file is compressed
                if results['compression_info']['is_compressed']:
                    comp_info = results['compression_info']
                    self.extracted_files_list.show()
                    self.extracted_files_list.setPlainText(
                        f"Compressed file detected ({comp_info['compression_type']}):\n" +
                        "\n".join(f"- {item}" for item in comp_info['contents'][:10]) +
                        (f"\n... and {len(comp_info['contents']) - 10} more files" 
                         if len(comp_info['contents']) > 10 else "")
                    )
                else:
                    self.extracted_files_list.hide()
                
                self.forensics_results.setPlainText(formatted_results)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.forensics_results.setPlainText(f"Error during analysis: {str(e)}")
    
    def extract_forensics(self):
        file_path = self.forensics_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file")
            return
        
        try:
            # First check if file is compressed
            comp_info = check_compression(file_path)
            
            # Get output directory
            output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
            if not output_dir:
                return
            
            self.forensics_results.setPlainText("Extracting contents...")
            QApplication.processEvents()  # Update UI
            
            results = []
            debug_info = []
            
            # Extract with built-in tools if compressed
            if comp_info['is_compressed']:
                extract_results = extract_compressed(file_path, output_dir)
                if extract_results['success']:
                    results.append(f"Successfully extracted {len(extract_results['extracted_files'])} files")
                    
            # Try steghide if enabled
            if self.check_steghide.isChecked():
                try:
                    password = self.steghide_password.text() or None
                    steghide_results = run_steghide(file_path, password=password, extract=True)
                    
                    if steghide_results['success']:
                        steghide_output = os.path.join(output_dir, 'steghide_extracted.txt')
                        with open(steghide_output, 'wb') as f:
                            f.write(steghide_results['output'])
                        results.append(f"Steghide extracted data to: {steghide_output}")
                    else:
                        error_msg = steghide_results['error'] or "Unknown error"
                        results.append(f"Steghide extraction failed: {error_msg}")
                        
                        # Add debug information
                        if 'debug_info' in steghide_results:
                            debug_info.append("\nSteghide Debug Information:")
                            debug_info.append(f"Command: {steghide_results['debug_info'].get('command', 'N/A')}")
                            debug_info.append(f"Return Code: {steghide_results['debug_info'].get('returncode', 'N/A')}")
                            debug_info.append(f"Stdout: {steghide_results['debug_info'].get('stdout', 'N/A')}")
                            debug_info.append(f"Stderr: {steghide_results['debug_info'].get('stderr', 'N/A')}")
                            if 'exception' in steghide_results['debug_info']:
                                debug_info.append(f"Exception: {steghide_results['debug_info']['exception']}")
                            
                except ExternalToolError as e:
                    results.append(f"Steghide: {str(e)}")
            
            # Try foremost if enabled
            if self.check_foremost.isChecked():
                try:
                    foremost_dir = os.path.join(output_dir, 'foremost')
                    foremost_results = run_foremost(file_path, foremost_dir)
                    if foremost_results['success']:
                        results.append(
                            f"Foremost extracted {len(foremost_results['extracted_files'])} files to: {foremost_dir}"
                        )
                except ExternalToolError as e:
                    results.append(f"Foremost: {str(e)}")
            
            # Try binwalk if enabled
            if self.check_binwalk.isChecked():
                try:
                    binwalk_results = run_binwalk(file_path, extract=True)
                    if binwalk_results['success'] and binwalk_results['extracted_files']:
                        results.append(
                            f"Binwalk extracted {len(binwalk_results['extracted_files'])} files"
                        )
                except ExternalToolError as e:
                    results.append(f"Binwalk: {str(e)}")
            
            if results:
                # Combine results and debug info
                output = results + debug_info
                self.forensics_results.setPlainText("\n".join(output))
                self.extracted_files_list.show()
                self.extracted_files_list.setPlainText(f"Files extracted to: {output_dir}")
            else:
                self.forensics_results.setPlainText("No data could be extracted")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.forensics_results.setPlainText(f"Error during extraction: {str(e)}")
    
    def update_audio_stego_mode(self):
        if self.hide_audio_radio.isChecked():
            self.hide_audio_options.show()
            self.image_to_audio_options.hide()
            self.audio_stego_action_btn.setText("Hide Data")
            # Update file selection for audio input
            self.audio_file_path.setPlaceholderText("Select a WAV audio file...")
            self.browse_btn.clicked.disconnect()
            self.browse_btn.clicked.connect(lambda: self.browse_file(self.audio_file_path, "WAV files (*.wav)"))
        elif self.image_to_audio_radio.isChecked():
            self.hide_audio_options.hide()
            self.image_to_audio_options.show()
            self.audio_stego_action_btn.setText("Convert Image to Audio")
            # Update file selection for image input
            self.audio_file_path.setPlaceholderText("Select an image file...")
            self.browse_btn.clicked.disconnect()
            self.browse_btn.clicked.connect(lambda: self.browse_file(self.audio_file_path, "Image files (*.png *.jpg *.jpeg *.bmp)"))
        else:
            self.hide_audio_options.hide()
            self.image_to_audio_options.hide()
            self.audio_stego_action_btn.setText("Analyze Audio")
            # Update file selection for audio input
            self.audio_file_path.setPlaceholderText("Select a WAV audio file...")
            self.browse_btn.clicked.disconnect()
            self.browse_btn.clicked.connect(lambda: self.browse_file(self.audio_file_path, "WAV files (*.wav)"))
    
    def process_audio_stego(self):
        if self.image_to_audio_radio.isChecked():
            # Process image to spectrogram
            image_path = self.audio_file_path.text()  # Using the main file input for image
            output_path = self.image_output_path.text()
            
            if not image_path:
                QMessageBox.warning(self, "Warning", "Please select an image file")
                return
                
            if not output_path:
                QMessageBox.warning(self, "Warning", "Please specify output audio file path")
                return
            
            # Check if input file is an image
            if not any(image_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.bmp']):
                QMessageBox.warning(self, "Warning", "Please select a valid image file (PNG, JPG, or BMP)")
                return
            
            # Ensure output file has .wav extension
            if not output_path.lower().endswith('.wav'):
                output_path += '.wav'
                self.image_output_path.setText(output_path)
            
            try:
                self.audio_stego_results.setPlainText("Converting image to audio...")
                QApplication.processEvents()  # Update UI
                
                duration = self.duration_spin.value()
                if hide_image_in_spectrogram(image_path, output_path, duration=float(duration)):
                    self.audio_stego_results.setPlainText("Image successfully converted to audio!")
                    # Generate and display the spectrogram
                    self.generate_spectrogram(output_path)
                else:
                    self.audio_stego_results.setPlainText("Failed to convert image to audio")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                self.audio_stego_results.setPlainText(f"Error: {str(e)}")
            return
            
        # Original audio stego processing
        file_path = self.audio_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select an audio file")
            return
        
        try:
            if self.analyze_audio_radio.isChecked():
                # Add debug information
                self.audio_stego_results.setPlainText("Analyzing file: " + file_path)
                QApplication.processEvents()  # Update UI
                
                if not os.path.exists(file_path):
                    raise FileNotFoundError(f"Audio file not found: {file_path}")
                
                # Check file extension
                if not file_path.lower().endswith('.wav'):
                    QMessageBox.warning(self, "Warning", "Currently only WAV files are supported for analysis")
                    return
                
                # Generate and display spectrogram
                self.generate_spectrogram(file_path)
                
                # Analyze audio file
                results = analyze_audio(file_path)
                if not results:
                    raise ValueError("No analysis results returned")
                    
                # Also analyze spectrogram for potential hidden images
                spec_results = analyze_spectrogram(file_path)
                if spec_results and not 'error' in spec_results:
                    results['spectrogram_analysis'] = spec_results
                
                formatted_results = self.format_audio_analysis(results)
                self.audio_stego_results.setPlainText(formatted_results)
            else:  # Hide data
                output_path = self.output_audio_path.text()
                if not output_path:
                    QMessageBox.warning(self, "Warning", "Please specify output file path")
                    return
                    
                # Ensure output file has .wav extension
                if not output_path.lower().endswith('.wav'):
                    output_path += '.wav'
                    self.output_audio_path.setText(output_path)
                
                data = self.hide_audio_data_input.toPlainText()
                if not data:
                    QMessageBox.warning(self, "Warning", "Please enter data to hide")
                    return
                
                self.audio_stego_results.setPlainText("Processing...")
                QApplication.processEvents()  # Update UI
                
                if hide_data_in_audio(file_path, data, output_path):
                    self.audio_stego_results.setPlainText("Data hidden successfully!")
                else:
                    self.audio_stego_results.setPlainText("Failed to hide data")
        except FileNotFoundError as e:
            QMessageBox.critical(self, "Error", str(e))
            self.audio_stego_results.setPlainText(f"Error: {str(e)}")
        except ValueError as e:
            QMessageBox.critical(self, "Error", str(e))
            self.audio_stego_results.setPlainText(f"Error: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {str(e)}")
            self.audio_stego_results.setPlainText(f"Error: {str(e)}\nType: {type(e).__name__}")
            
    def generate_spectrogram(self, audio_path):
        try:
            # Clear previous spectrogram
            self.spectrogram_label.clear()
            QApplication.processEvents()
            
            # Read audio file
            sample_rate, data = wavfile.read(audio_path)
            
            # Convert stereo to mono if necessary
            if len(data.shape) > 1:
                data = np.mean(data, axis=1)
            
            # Create spectrogram
            plt.figure(figsize=(10, 4))
            plt.specgram(data, Fs=sample_rate, cmap='viridis')
            plt.colorbar(label='Intensity [dB]')
            plt.xlabel('Time [s]')
            plt.ylabel('Frequency [Hz]')
            plt.title('Audio Spectrogram Analysis')
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                plt.savefig(tmp.name, bbox_inches='tight', dpi=100)
                plt.close()
                
                # Load and display the image
                pixmap = QPixmap(tmp.name)
                scaled_pixmap = pixmap.scaled(self.spectrogram_label.size(), 
                                           Qt.AspectRatioMode.KeepAspectRatio,
                                           Qt.TransformationMode.SmoothTransformation)
                self.spectrogram_label.setPixmap(scaled_pixmap)
                
            # Clean up
            os.unlink(tmp.name)
            
        except Exception as e:
            self.audio_stego_results.setPlainText(f"Error generating spectrogram: {str(e)}")

    def format_audio_analysis(self, results):
        output = []
        
        if not results:
            return "No analysis results available"
            
        if 'error' in results:
            return f"Error during analysis: {results['error']}"
        
        # Format file info
        if 'audio_info' in results:
            output.append("=== Audio Information ===")
            for key, value in results['audio_info'].items():
                if isinstance(value, float):
                    value = f"{value:.2f}"
                output.append(f"{key.replace('_', ' ').title()}: {value}")
        
        # Format analysis results
        if 'analysis' in results:
            output.append("\n=== Steganography Analysis ===")
            for finding in results['analysis']:
                output.append(f"- {finding}")
        
        # Format spectrogram analysis results
        if 'spectrogram_analysis' in results:
            output.append("\n=== Spectrogram Analysis ===")
            if 'spectrogram_info' in results['spectrogram_analysis']:
                for key, value in results['spectrogram_analysis']['spectrogram_info'].items():
                    output.append(f"{key.replace('_', ' ').title()}: {value}")
            if 'analysis' in results['spectrogram_analysis']:
                output.append("\nFindings:")
                for finding in results['spectrogram_analysis']['analysis']:
                    output.append(f"- {finding}")
                
        if not output:
            return "No analysis data found in results"
        
        return '\n'.join(output)
    
    def load_hex_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                self.hex_editor = HexEditor(data)
                self.hex_editor.current_file = file_path  # Store file path
                self.update_hex_view()
                self.update_magic_suggestions()
                
                # Show auto-fix button if file has extension
                if os.path.splitext(file_path)[1]:
                    self.auto_fix_btn.setVisible(True)
                else:
                    self.auto_fix_btn.setVisible(False)
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
    
    def update_hex_view(self):
        """Update the hex view with current data"""
        if hasattr(self, 'hex_editor'):
            self.hex_view.setPlainText(self.hex_editor.to_hex())
    
    def update_magic_suggestions(self):
        """Update magic number suggestions"""
        if not hasattr(self, 'hex_editor'):
            return
            
        # Clear previous items
        self.header_combo.clear()
        
        # Get detected formats and suggestions
        detected = self.hex_editor.detected_formats
        suggestions = self.hex_editor.get_suggested_headers()
        
        if detected:
            formats_str = []
            for fmt in detected:
                formats_str.append(f"{fmt['format']}: {fmt['description']}")
                # Add header to suggestions if it doesn't match current
                if fmt['header'] != binascii.hexlify(self.hex_editor.data[:len(fmt['header'])//2]).decode().upper():
                    self.header_combo.addItem(f"{fmt['format']} - Original Header", fmt['header'])
            
            self.format_label.setText("Detected formats:\n" + "\n".join(formats_str))
            self.header_combo.setVisible(True)
            self.apply_header_btn.setVisible(True)
        else:
            self.format_label.setText("No known format detected")
            
        # Add other suggested headers
        for fmt, desc, header in suggestions:
            if not any(header == item.data() for item in [self.header_combo.itemData(i) for i in range(self.header_combo.count())]):
                self.header_combo.addItem(f"{fmt} - Suggested Header", header)

    def apply_magic_header(self):
        """Apply selected magic number header"""
        if not hasattr(self, 'hex_editor'):
            return
            
        current_data = self.header_combo.currentData()
        if current_data:
            if self.hex_editor.replace_header(current_data):
                self.update_hex_view()
                self.update_magic_suggestions()
                self.hex_results.setPlainText("Header replaced successfully")
            else:
                self.hex_results.setPlainText("Failed to replace header")

    def on_hex_edit(self):
        """Handle hex view edits"""
        if not hasattr(self, 'hex_editor'):
            return
            
        # Get cursor position
        cursor = self.hex_view.textCursor()
        line = cursor.blockNumber() + 1
        column = cursor.columnNumber()
        
        # Convert position to byte offset
        offset = self.hex_editor.get_offset_from_position(line, column)
        if offset is not None:
            self.edit_offset.setText(f"{offset:x}")

    def edit_hex_bytes(self):
        """Edit bytes at specified offset"""
        if not hasattr(self, 'hex_editor'):
            return
            
        try:
            # Parse offset
            offset = int(self.edit_offset.text(), 16)
            
            # Parse new value
            hex_value = self.edit_value.text().replace(' ', '')
            new_bytes = binascii.unhexlify(hex_value)
            
            if self.hex_editor.edit_bytes(offset, new_bytes):
                self.update_hex_view()
                self.update_magic_suggestions()
                self.hex_results.setPlainText("Bytes edited successfully")
            else:
                self.hex_results.setPlainText("Failed to edit bytes")
        except Exception as e:
            self.hex_results.setPlainText(f"Error: {str(e)}")

    def save_hex_file(self):
        if not hasattr(self, 'hex_editor'):
            QMessageBox.warning(self, "Warning", "No data to save")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File")
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.hex_editor.get_data())
                QMessageBox.information(self, "Success", "File saved successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")

    def find_hex_pattern(self):
        if not hasattr(self, 'hex_editor'):
            QMessageBox.warning(self, "Warning", "No data loaded")
            return
            
        pattern = self.pattern_input.text()
        if not pattern:
            QMessageBox.warning(self, "Warning", "Please enter a pattern")
            return
            
        try:
            positions = self.hex_editor.find_pattern(pattern)
            if positions:
                self.hex_results.setPlainText(f"Pattern found at offsets: {', '.join(f'0x{pos:x}' for pos in positions)}")
            else:
                self.hex_results.setPlainText("Pattern not found")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Search failed: {str(e)}")

    def decode_hex_data(self):
        if not hasattr(self, 'hex_editor'):
            QMessageBox.warning(self, "Warning", "No data loaded")
            return
            
        encoding = self.encoding_combo.currentText()
        try:
            result = self.hex_editor.decode_as(encoding)
            self.hex_results.setPlainText(result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decoding failed: {str(e)}")

    def update_crypto_analysis(self):
        """Update real-time cryptographic analysis"""
        text = self.input_text.toPlainText()
        if len(text) < 5:  # Minimum length for analysis
            self.analysis_text.setPlainText("Enter at least 5 characters for analysis...")
            return
            
        try:
            from modules.crypto.smart_detector import SmartDetector
            from modules.crypto.basex import BaseX
            
            # Initialize analyzers
            detector = SmartDetector()
            basex = BaseX()
            
            # Get current flag format if custom is set
            flag_patterns = self.get_current_flag_pattern()
            
            # Try base decoding
            base_results = basex.try_all_decoding(text, flag_patterns)
            
            # Run smart detector analysis
            smart_analysis = detector.analyze_and_decrypt(text)
            
            # Format results
            output = []
            
            # Add base decoding results first if they found flags
            if base_results['likely_flags']:
                output.append("=== Potential Flags Found (Base Decoding) ===")
                for method, decoded, confidence in base_results['likely_flags'][:3]:  # Show top 3
                    output.append(f"➜ {method} ({confidence*100:.1f}% confidence):")
                    output.append(f"  {decoded}\n")
            
            # Add other promising base decoding results
            if base_results['printable_results']:
                output.append("=== Other Base Decoding Results ===")
                for method, decoded, confidence in base_results['printable_results'][:3]:  # Show top 3
                    if confidence > 0.8:  # Only show high confidence results
                        output.append(f"➜ {method} ({confidence*100:.1f}% confidence):")
                        output.append(f"  {decoded}\n")
            
            # Add smart detector results
            if smart_analysis['status'] == 'success':
                from modules.crypto.smart_detector import format_smart_analysis
                output.append("=== Other Analysis Results ===")
                output.append(format_smart_analysis(smart_analysis))
            
            self.analysis_text.setPlainText('\n'.join(output) if output else "No promising decodings found...")
            
        except Exception as e:
            self.analysis_text.setPlainText(f"Analysis error: {str(e)}")

    def update_flag_format(self, selected_format):
        """Update the custom flag format input based on selection"""
        if selected_format == "Custom Format":
            self.custom_flag_format.setEnabled(True)
        else:
            self.custom_flag_format.setEnabled(False)
            if selected_format != "All Formats":
                # Set example in the custom format field
                format_map = {
                    "CTF{...}": "CTF{[a-zA-Z0-9_]+}",
                    "flag{...}": "flag{[a-zA-Z0-9_]+}",
                    "key{...}": "key{[a-zA-Z0-9_]+}"
                }
                self.custom_flag_format.setText(format_map.get(selected_format, ""))
                
    def get_current_flag_pattern(self):
        """Get the current flag pattern based on user selection"""
        selected_format = self.flag_format_combo.currentText()
        
        if selected_format == "Custom Format":
            custom_pattern = self.custom_flag_format.text()
            if custom_pattern:
                # Convert user-friendly format to regex
                if "{...}" in custom_pattern:
                    custom_pattern = custom_pattern.replace("{...}", "{[a-zA-Z0-9_]+}")
                if "{.*}" in custom_pattern:
                    custom_pattern = custom_pattern.replace("{.*}", "{.*?}")
                return [custom_pattern]
        elif selected_format == "All Formats":
            return None  # Use default patterns
        else:
            # Convert predefined format to regex
            format_map = {
                "CTF{...}": r"CTF{[a-zA-Z0-9_]+}",
                "flag{...}": r"flag{[a-zA-Z0-9_]+}",
                "key{...}": r"key{[a-zA-Z0-9_]+}"
            }
            return [format_map.get(selected_format)]
        
        return None  # Use default patterns if nothing is selected

    def try_all_caesar_shifts(self):
        """Try all possible Caesar shifts and show results"""
        text = self.input_text.toPlainText()
        if not text:
            return
            
        # Get current flag format if custom is set
        flag_patterns = self.get_current_flag_pattern()
        
        # Try all shifts
        results = try_all_caesar_shifts(text, flag_patterns)
        
        output = []
        
        # Show flag matches first
        if results['likely_flags']:
            output.append("=== Potential Flags Found ===")
            for shift, decoded, confidence in results['likely_flags']:
                output.append(f"➜ Shift {shift} ({confidence*100:.1f}% confidence):")
                output.append(f"  {decoded}\n")
        
        # Show other sensible results
        if results['sensible_text']:
            output.append("=== Other Likely Shifts ===")
            for shift, decoded, confidence in results['sensible_text'][:5]:  # Show top 5
                output.append(f"➜ Shift {shift} ({confidence*100:.1f}% confidence):")
                output.append(f"  {decoded}\n")
        
        # Update output
        self.output_text.setPlainText('\n'.join(output) if output else "No promising shifts found...")
        
        # If we found a likely flag, set the slider to that shift
        if results['likely_flags']:
            best_shift = results['likely_flags'][0][0]  # Use the shift from the highest confidence flag
            self.shift_slider.setValue(best_shift)
        elif results['sensible_text']:
            best_shift = results['sensible_text'][0][0]  # Use the shift from the highest confidence text
            self.shift_slider.setValue(best_shift)

    def auto_fix_header(self):
        """Automatically fix file header based on extension"""
        if not hasattr(self, 'hex_editor') or not hasattr(self.hex_editor, 'current_file'):
            return
            
        file_ext = os.path.splitext(self.hex_editor.current_file)[1].lower()
        
        # Map extensions to format names
        ext_to_format = {
            '.png': 'PNG',
            '.jpg': 'JPEG',
            '.jpeg': 'JPEG',
            '.gif': 'GIF89a',  # Prefer newer GIF format
            '.pdf': 'PDF',
            '.zip': 'ZIP',
            '.rar': 'RAR',
            '.7z': '7Z',
            '.gz': 'GZIP',
            '.bz2': 'BZIP2',
            '.class': 'CLASS',
            '.doc': 'DOC',
            '.mp3': 'MP3',
            '.mp4': 'MP4',
            '.wav': 'WAV'
        }
        
        format_name = ext_to_format.get(file_ext)
        if not format_name:
            QMessageBox.warning(self, "Warning", "Could not determine format from file extension")
            return
            
        # Get magic number for this format
        format_info = MagicNumbers.get_format_info(format_name)
        if not format_info:
            QMessageBox.warning(self, "Warning", f"No magic number information for {format_name} format")
            return
            
        # Check if current header matches expected
        current_header = binascii.hexlify(self.hex_editor.data[:len(format_info['header'])//2]).decode().upper()
        if current_header == format_info['header']:
            QMessageBox.information(self, "Info", "File header is already correct")
            return
            
        # Ask for confirmation
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Question)
        msg.setText(f"Fix file header for {format_name} format?")
        msg.setInformativeText(f"Current header: {current_header}\nExpected header: {format_info['header']}")
        msg.setWindowTitle("Confirm Header Fix")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if msg.exec() == QMessageBox.StandardButton.Yes:
            if self.hex_editor.replace_header(format_info['header']):
                self.update_hex_view()
                self.update_magic_suggestions()
                self.hex_results.setPlainText(f"Successfully fixed header for {format_name} format")
            else:
                self.hex_results.setPlainText("Failed to fix header")

def main():
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_teal.xml')
    
    # Set default font to a monospace font for better formatting
    font = app.font()
    font.setFamily('Courier New')
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main() 