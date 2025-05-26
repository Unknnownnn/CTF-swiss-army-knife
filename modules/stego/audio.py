import wave
import numpy as np
from typing import Union, Dict, Any
import os
from PIL import Image
import scipy.signal as signal
from scipy.io import wavfile

def analyze_audio(audio_path: str) -> Dict[str, Any]:
    """
    Analyze audio file for potential hidden data
    """
    results = {
        'file_info': {},
        'audio_info': {},
        'analysis': []
    }
    
    try:
        with wave.open(audio_path, 'rb') as wav:
            # Get basic audio information
            params = wav.getparams()
            results['audio_info'] = {
                'channels': params.nchannels,
                'sample_width': params.sampwidth,
                'frame_rate': params.framerate,
                'frame_count': params.nframes,
                'duration': params.nframes / params.framerate
            }
            
            # Read frames and convert to numpy array
            frames = wav.readframes(params.nframes)
            audio_data = np.frombuffer(frames, dtype=np.int16)
            
            # Analyze LSB distribution
            lsb_ones = np.sum(audio_data & 1)
            lsb_ratio = lsb_ones / len(audio_data)
            
            if 0.45 <= lsb_ratio <= 0.55:
                results['analysis'].append("LSB ratio suggests possible hidden data")
            
            # Check for sudden changes in amplitude
            amplitude_changes = np.abs(np.diff(audio_data))
            sudden_changes = np.where(amplitude_changes > np.mean(amplitude_changes) * 3)[0]
            if len(sudden_changes) > 0:
                results['analysis'].append(f"Found {len(sudden_changes)} suspicious amplitude changes")
            
            # Basic spectral analysis
            if len(audio_data) > 1024:
                spectrum = np.abs(np.fft.fft(audio_data[:1024]))
                unusual_freqs = np.where(spectrum > np.mean(spectrum) * 2)[0]
                if len(unusual_freqs) > 0:
                    results['analysis'].append(f"Found {len(unusual_freqs)} unusual frequency components")
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def hide_data_in_audio(audio_path: str, data: str, output_path: str) -> bool:
    """
    Hide data in audio file using LSB steganography
    """
    try:
        # Convert data to binary
        binary_data = ''.join(format(ord(c), '08b') for c in data)
        binary_data += '00000000'  # Add null terminator
        
        with wave.open(audio_path, 'rb') as wav_in:
            params = wav_in.getparams()
            frames = wav_in.readframes(params.nframes)
            audio_data = np.frombuffer(frames, dtype=np.int16).copy()  # Create a copy of the array
            
            if len(binary_data) > len(audio_data):
                raise ValueError("Audio file too small to hide this much data")
            
            # Modify LSBs to hide data
            for i in range(len(binary_data)):
                audio_data[i] = (audio_data[i] & ~1) | int(binary_data[i])
            
            # Save modified audio
            with wave.open(output_path, 'wb') as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(audio_data.tobytes())
        
        return True
        
    except Exception as e:
        print(f"Error hiding data: {str(e)}")
        return False

def extract_data_from_audio(audio_path: str) -> Union[str, None]:
    """
    Extract hidden data from audio file
    """
    try:
        with wave.open(audio_path, 'rb') as wav:
            frames = wav.readframes(wav.getnframes())
            audio_data = np.frombuffer(frames, dtype=np.int16)
            
            # Extract LSBs
            bits = ''.join(str(x & 1) for x in audio_data)
            
            # Convert bits to bytes and then to string
            chars = []
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if byte == '00000000':  # Null terminator
                    break
                chars.append(chr(int(byte, 2)))
            
            return ''.join(chars)
            
    except Exception as e:
        return f"Error during extraction: {str(e)}"
    
    return None 

def hide_image_in_spectrogram(image_path: str, output_path: str, duration: float = 5.0, sample_rate: int = 44100) -> bool:
    """
    Convert an image into an audio file where the image is visible in the spectrogram.
    
    Args:
        image_path: Path to the input image
        output_path: Path to save the output WAV file
        duration: Duration of the audio file in seconds (default: 5.0)
        sample_rate: Sample rate of the audio file (default: 44100 Hz)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Load and preprocess the image
        img = Image.open(image_path).convert('L')  # Convert to grayscale
        
        # Resize image to appropriate dimensions for spectrogram
        # Height determines frequency range, width determines time
        target_width = int(duration * 30)  # 30 pixels per second
        target_height = 512  # Number of frequency bins
        img = img.resize((target_width, target_height), Image.Resampling.LANCZOS)
        img_array = np.array(img)
        
        # Normalize image array to [0, 1]
        img_array = img_array / 255.0
        
        # Create time array
        t = np.linspace(0, duration, int(duration * sample_rate))
        
        # Generate audio signal
        audio = np.zeros_like(t)
        freqs = np.linspace(20, 20000, target_height)  # Frequency range from 20 Hz to 20 kHz
        
        # For each time step in the image
        for i in range(img_array.shape[1]):
            # Get the amplitudes for this time slice
            amplitudes = img_array[:, i]
            
            # Calculate the time indices for this slice
            t_start = int((i / img_array.shape[1]) * len(t))
            t_end = int(((i + 1) / img_array.shape[1]) * len(t))
            
            # Generate the signal for this time slice
            for j, (freq, amp) in enumerate(zip(freqs, amplitudes)):
                if amp > 0.1:  # Only add frequencies with significant amplitude
                    audio[t_start:t_end] += amp * np.sin(2 * np.pi * freq * t[t_start:t_end])
        
        # Normalize audio to prevent clipping
        audio = audio / np.max(np.abs(audio))
        
        # Convert to 16-bit PCM
        audio = (audio * 32767).astype(np.int16)
        
        # Save as WAV file
        wavfile.write(output_path, sample_rate, audio)
        return True
        
    except Exception as e:
        print(f"Error creating spectrogram audio: {str(e)}")
        return False

def analyze_spectrogram(audio_path: str) -> Dict[str, Any]:
    """
    Analyze the spectrogram of an audio file for potential hidden images
    """
    results = {
        'spectrogram_info': {},
        'analysis': []
    }
    
    try:
        # Read audio file
        sample_rate, audio_data = wavfile.read(audio_path)
        
        # Convert stereo to mono if necessary
        if len(audio_data.shape) > 1:
            audio_data = np.mean(audio_data, axis=1)
        
        # Compute spectrogram
        frequencies, times, Sxx = signal.spectrogram(
            audio_data,
            fs=sample_rate,
            nperseg=1024,
            noverlap=512,
            scaling='spectrum'
        )
        
        # Analyze spectrogram characteristics
        results['spectrogram_info'] = {
            'frequency_range': f"{int(frequencies[0])} - {int(frequencies[-1])} Hz",
            'duration': f"{times[-1]:.2f} seconds",
            'frequency_bins': len(frequencies),
            'time_bins': len(times)
        }
        
        # Check for image-like patterns
        spectral_std = np.std(10 * np.log10(Sxx + 1e-10))
        spectral_mean = np.mean(10 * np.log10(Sxx + 1e-10))
        
        if spectral_std > 10:  # High variation in spectrogram
            results['analysis'].append("High spectral variation detected - possible hidden image")
        
        # Check for unusual frequency distributions
        freq_distribution = np.mean(Sxx, axis=1)
        peaks = signal.find_peaks(freq_distribution)[0]
        if len(peaks) > 50:  # Many frequency peaks
            results['analysis'].append(f"Found {len(peaks)} frequency peaks - possible image encoding")
            
    except Exception as e:
        results['error'] = str(e)
    
    return results 