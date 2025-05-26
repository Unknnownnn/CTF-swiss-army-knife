# External Tools Setup

This directory contains external tools used by the CTF Swiss Army Knife application. Some tools need to be installed separately on your system.

## Python Dependencies

First, install the Python dependencies:
```bash
pip install -r requirements.txt
```

For Windows users, some additional steps might be needed:
1. Install Visual C++ Redistributable if not already installed
2. Some tools might require Windows Subsystem for Linux (WSL)

## Required Tools

### 1. Steghide
A steganography tool that can hide data in various image and audio files.

**Installation:**
- Linux: `sudo apt-get install steghide`
- Windows: 
  1. Download from [Steghide Website](http://steghide.sourceforge.net/)
  2. Or install through WSL: `sudo apt-get install steghide`
  3. Add the installation directory to your system PATH
- macOS: `brew install steghide`

### 2. Binwalk
A tool for analyzing, reverse engineering, and extracting firmware images.

**Installation:**
- Linux: `sudo apt-get install binwalk`
- Windows:
  1. Install via pip: `pip install binwalk`
  2. Install dependencies:
     ```bash
     pip install pycrypto
     pip install matplotlib
     ```
  3. Or use WSL (recommended): `sudo apt-get install binwalk`
- macOS: `brew install binwalk`

### 3. Foremost
A forensic program to recover files based on their headers, footers, and data structures.

**Installation:**
- Linux: `sudo apt-get install foremost`
- Windows:
  1. Install WSL (Windows Subsystem for Linux)
  2. In WSL: `sudo apt-get install foremost`
- macOS: `brew install foremost`

### 4. ExifTool
A library and command-line tool for reading, writing, and manipulating image, audio, video, and PDF metadata.

**Installation:**
- Linux: `sudo apt-get install exiftool`
- Windows:
  1. Download from [ExifTool Website](https://exiftool.org/)
  2. Extract the archive
  3. Rename `exiftool(-k).exe` to `exiftool.exe`
  4. Add the directory to your system PATH
- macOS: `brew install exiftool`

### 5. Zsteg
A tool for detecting stegano-hidden data in PNG and BMP files.

**Installation:**
- Linux/macOS:
  ```bash
  gem install zsteg
  ```
- Windows:
  1. Install Ruby from [RubyInstaller](https://rubyinstaller.org/)
  2. Open command prompt and run:
     ```bash
     gem install zsteg
     ```

### 6. Stegsolve
A Java tool for solving steganographic challenges.

**Setup:**
1. Make sure Java is installed on your system
2. Download Stegsolve.jar from [GitHub](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install)
3. Place it in this directory
4. Make it executable:
   - Linux/macOS: `chmod +x Stegsolve.jar`
   - Windows: No additional steps needed

## Troubleshooting

### Windows-specific Issues

1. **python-magic/libmagic issues**:
   - If you get errors with python-magic, try:
     ```bash
     pip uninstall python-magic
     pip install python-magic-bin
     ```

2. **Binwalk extraction issues**:
   - Install 7-Zip and add it to your system PATH
   - Use WSL for better compatibility

3. **Steghide not found**:
   - Verify the installation path is in your system PATH
   - Try using WSL instead

### General Issues

1. **Permission errors**:
   - Run the command prompt/terminal as administrator
   - Check file permissions

2. **Tool not found errors**:
   - Verify the tool is installed correctly
   - Check if the installation directory is in your system PATH
   - Try running through WSL if on Windows

## Verification

You can verify the installation of these tools by running:
```bash
steghide --version
binwalk --version
foremost -V
exiftool -ver
zsteg -V
java -jar Stegsolve.jar --version
```

## Note

Some tools might require additional dependencies or specific system configurations. Please refer to their respective documentation for detailed installation instructions and troubleshooting.

The application will check for the presence of these tools before using them and will display appropriate error messages if any tool is missing. 