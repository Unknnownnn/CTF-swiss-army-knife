import subprocess
import os
import tempfile
import shutil
from typing import Dict, Any, List, Optional
import json
from pathlib import Path
import platform
import sys

class ExternalToolError(Exception):
    """Exception raised when an external tool fails"""
    pass

def check_tool_installed(tool_name: str) -> bool:
    """Check if a command-line tool is installed and provide installation instructions"""
    is_windows = platform.system() == 'Windows'
    
    try:
        # First check in our tools directory for all tools
        tools_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools")
        tool_exe = f"{tool_name}.exe" if is_windows else tool_name
        local_tool = os.path.join(tools_dir, tool_exe)
        
        # Special case for exiftool which might be named exiftool.exe or exiftool(-k).exe
        if tool_name == 'exiftool' and is_windows:
            local_tool_alt = os.path.join(tools_dir, "exiftool(-k).exe")
            if os.path.exists(local_tool_alt):
                return True
        
        if os.path.exists(local_tool):
            return True
        
        # If not in tools dir, try specific tool checks
        if tool_name == 'binwalk':
            try:
                import binwalk
                return True
            except ImportError:
                try:
                    subprocess.run(['binwalk', '--help'], capture_output=True, check=True)
                    return True
                except (subprocess.CalledProcessError, FileNotFoundError):
                    if is_windows:
                        raise ExternalToolError(
                            "Binwalk not found. Click Install to install automatically, or follow these steps:\n"
                            "1. Download from GitHub\n"
                            "2. Install Python 2.7\n"
                            "3. Run: pip install python-lzma\n"
                            "4. Run: python setup.py install\n"
                            "5. Create executable with PyInstaller\n"
                            "6. Place binwalk.exe in tools directory or add to PATH"
                        )
                    else:
                        raise ExternalToolError(
                            "Binwalk not found. To install:\n"
                            "sudo apt-get install binwalk"
                        )
        
        if tool_name == 'steghide' and is_windows:
            try:
                subprocess.run(['steghide', '--version'], capture_output=True, check=True)
                return True
            except subprocess.CalledProcessError:
                return True
            except FileNotFoundError:
                common_paths = [
                    os.path.join(os.environ.get('ProgramFiles', ''), 'steghide', 'steghide.exe'),
                    os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'steghide', 'steghide.exe'),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'steghide', 'steghide.exe')
                ]
                for path in common_paths:
                    if os.path.exists(path):
                        return True
                raise ExternalToolError(
                    "Steghide not found. Please install it:\n"
                    "1. Download from http://steghide.sourceforge.net/download.php\n"
                    "2. Extract to a folder (e.g., C:\\Program Files\\steghide)\n"
                    "3. Add the folder to your system PATH or place in tools directory\n"
                    "Or use Windows Subsystem for Linux (WSL) and install with: sudo apt-get install steghide"
                )
        
        # For other tools, try command line
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError as e:
            # Command exists but returned error (this is fine, as --help might not be supported)
            return True
        except FileNotFoundError:
            # Tool is not installed
            raise ExternalToolError(
                f"{tool_name} not found. Please download and either:\n"
                f"1. Add it to your system PATH, or\n"
                f"2. Place it in the tools directory: {tools_dir}"
            )
    
    except Exception as e:
        if not isinstance(e, ExternalToolError):
            raise ExternalToolError(f"Error checking {tool_name}: {str(e)}")
        raise

def find_steghide_path() -> str:
    """Find the steghide executable path on Windows"""
    if platform.system() != 'Windows':
        return 'steghide'
        
    # Common installation paths
    common_paths = [
        os.path.join(os.environ.get('ProgramFiles', ''), 'steghide', 'steghide.exe'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'steghide', 'steghide.exe'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'steghide', 'steghide.exe'),
        # Add the current directory and its subdirectories
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'tools', 'steghide', 'steghide.exe'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'tools', 'steghide.exe'),
    ]
    
    # Also check if it's in PATH
    if os.environ.get('PATH'):
        for path in os.environ['PATH'].split(os.pathsep):
            common_paths.append(os.path.join(path, 'steghide.exe'))
    
    # Try to find steghide
    for path in common_paths:
        if os.path.exists(path):
            return path
            
    # If we can't find it, try WSL
    try:
        # Check if WSL is available
        wsl_check = subprocess.run(['wsl', 'which', 'steghide'], 
                                 capture_output=True, 
                                 text=True)
        if wsl_check.returncode == 0:
            return 'wsl steghide'
    except Exception:
        pass
    
    raise ExternalToolError(
        "Steghide not found. Please ensure it's installed and in your PATH.\n"
        "Installation options:\n"
        "1. Windows native:\n"
        "   - Download from http://steghide.sourceforge.net/download.php\n"
        "   - Extract to a folder (e.g., C:\\Program Files\\steghide)\n"
        "   - Add the folder to your system PATH\n"
        "2. Windows Subsystem for Linux (WSL):\n"
        "   - Install WSL: wsl --install\n"
        "   - In WSL terminal: sudo apt-get update && sudo apt-get install steghide"
    )

def run_steghide(image_path: str, password: Optional[str] = None, extract: bool = True) -> Dict[str, Any]:
    """Run steghide to extract or analyze hidden data"""
    results = {
        'success': False,
        'output': None,
        'extracted_file': None,
        'error': None,
        'debug_info': {}
    }
    
    try:
        # Get steghide path
        steghide_path = find_steghide_path()
        results['debug_info']['steghide_path'] = steghide_path
        
        # Convert file path for WSL if needed
        if steghide_path.startswith('wsl '):
            # Convert Windows path to WSL path
            image_path = subprocess.run(
                ['wsl', 'wslpath', '-a', image_path],
                capture_output=True,
                text=True
            ).stdout.strip()
        
        if extract:
            # Create temp directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                output_file = os.path.join(temp_dir, 'steghide_extracted.txt')
                
                # Convert output path for WSL if needed
                if steghide_path.startswith('wsl '):
                    output_file = subprocess.run(
                        ['wsl', 'wslpath', '-a', output_file],
                        capture_output=True,
                        text=True
                    ).stdout.strip()
                
                # Build command
                base_cmd = steghide_path.split()  # Split 'wsl steghide' if needed
                cmd = base_cmd + ['extract', '-sf', image_path, '-xf', output_file]
                if password:
                    cmd.extend(['-p', password])
                else:
                    cmd.extend(['-p', ''])
                
                # Store command for debugging
                results['debug_info']['command'] = ' '.join(cmd)
                results['debug_info']['working_dir'] = os.getcwd()
                
                # Run steghide
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )
                
                # Store process info for debugging
                results['debug_info']['returncode'] = process.returncode
                results['debug_info']['stdout'] = process.stdout
                results['debug_info']['stderr'] = process.stderr
                
                if process.returncode == 0:
                    # Check if file was actually created
                    output_check = output_file
                    if steghide_path.startswith('wsl '):
                        # Convert back to Windows path
                        output_check = subprocess.run(
                            ['wsl', 'wslpath', '-w', output_file],
                            capture_output=True,
                            text=True
                        ).stdout.strip()
                    
                    if os.path.exists(output_check):
                        try:
                            with open(output_check, 'rb') as f:
                                results['output'] = f.read()
                                results['success'] = True
                                results['extracted_file'] = output_check
                        except Exception as e:
                            results['error'] = f"File created but couldn't read it: {str(e)}"
                    else:
                        results['error'] = "Extract command succeeded but no file was created"
                else:
                    results['error'] = process.stderr or "Unknown error during extraction"
        else:
            # Info mode
            base_cmd = steghide_path.split()  # Split 'wsl steghide' if needed
            cmd = base_cmd + ['info', image_path]
            if password:
                cmd.extend(['-p', password])
            
            # Store command for debugging
            results['debug_info']['command'] = ' '.join(cmd)
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            # Store process info for debugging
            results['debug_info']['returncode'] = process.returncode
            results['debug_info']['stdout'] = process.stdout
            results['debug_info']['stderr'] = process.stderr
            
            results['output'] = process.stdout
            results['success'] = process.returncode == 0
            if process.returncode != 0:
                results['error'] = process.stderr
    
    except Exception as e:
        results['error'] = str(e)
        results['debug_info']['exception'] = str(e)
    
    return results

def run_binwalk(file_path: str, extract: bool = False) -> Dict[str, Any]:
    """Run binwalk analysis on a file"""
    if not check_tool_installed('binwalk'):
        raise ExternalToolError("binwalk is not installed. Please install it first.")
    
    results = {
        'success': False,
        'signatures': [],
        'extracted_files': [],
        'error': None
    }
    
    try:
        # Run signature scan
        cmd = ['binwalk', file_path]
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode == 0:
            results['success'] = True
            # Parse binwalk output
            for line in process.stdout.split('\n'):
                if line.strip() and not line.startswith('DECIMAL'):
                    results['signatures'].append(line.strip())
        
        # Extract files if requested
        if extract:
            extract_dir = f"{file_path}_binwalk"
            cmd = ['binwalk', '-e', file_path]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0 and os.path.exists(extract_dir):
                for root, _, files in os.walk(extract_dir):
                    for file in files:
                        results['extracted_files'].append(os.path.join(root, file))
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def run_stegsolve(image_path: str, output_dir: str) -> Dict[str, Any]:
    """Run Stegsolve analysis on an image"""
    results = {
        'success': False,
        'analyzed_files': [],
        'error': None
    }
    
    try:
        # Check if Java is installed
        if not check_tool_installed('java'):
            raise ExternalToolError("Java is not installed. Stegsolve requires Java to run.")
        
        # Check if Stegsolve.jar exists in the tools directory
        stegsolve_path = os.path.join(os.path.dirname(__file__), 'tools', 'Stegsolve.jar')
        if not os.path.exists(stegsolve_path):
            raise ExternalToolError("Stegsolve.jar not found in tools directory.")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate different color planes and filters
        filters = [
            'red_plane', 'green_plane', 'blue_plane',
            'alpha_plane', 'inverted', 'grayscale'
        ]
        
        for filter_name in filters:
            output_file = os.path.join(output_dir, f"{filter_name}.png")
            cmd = [
                'java', '-jar', stegsolve_path,
                image_path, output_file, filter_name
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode == 0:
                results['analyzed_files'].append(output_file)
        
        results['success'] = True
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

def run_zsteg(image_path: str) -> Dict[str, Any]:
    """Run zsteg analysis on PNG/BMP files"""
    if not check_tool_installed('zsteg'):
        raise ExternalToolError("zsteg is not installed. Please install it first.")
    
    results = {
        'success': False,
        'findings': [],
        'error': None
    }
    
    try:
        cmd = ['zsteg', image_path]
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode == 0:
            results['success'] = True
            results['findings'] = [
                line.strip() for line in process.stdout.split('\n')
                if line.strip()
            ]
        else:
            results['error'] = process.stderr
            
    except Exception as e:
        results['error'] = str(e)
    
    return results

def run_exiftool(file_path: str) -> Dict[str, Any]:
    """Run exiftool for detailed metadata analysis"""
    if not check_tool_installed('exiftool'):
        raise ExternalToolError("exiftool is not installed. Please install it first.")
    
    results = {
        'success': False,
        'metadata': {},
        'error': None
    }
    
    try:
        cmd = ['exiftool', '-json', file_path]
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode == 0:
            results['success'] = True
            results['metadata'] = json.loads(process.stdout)[0]
        else:
            results['error'] = process.stderr
            
    except Exception as e:
        results['error'] = str(e)
    
    return results

def run_foremost(file_path: str, output_dir: str) -> Dict[str, Any]:
    """Run foremost to extract embedded files"""
    if not check_tool_installed('foremost'):
        raise ExternalToolError("foremost is not installed. Please install it first.")
    
    results = {
        'success': False,
        'extracted_files': [],
        'error': None
    }
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        cmd = ['foremost', '-i', file_path, '-o', output_dir]
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode == 0:
            results['success'] = True
            # Walk through the output directory to find extracted files
            for root, _, files in os.walk(output_dir):
                for file in files:
                    results['extracted_files'].append(os.path.join(root, file))
        else:
            results['error'] = process.stderr
            
    except Exception as e:
        results['error'] = str(e)
    
    return results 