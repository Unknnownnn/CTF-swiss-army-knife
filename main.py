#!/usr/bin/env python3
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import os

console = Console()

def print_banner():
    banner = """
    ╔═══════════════════════════════════════╗
    ║        CTF Swiss Army Knife           ║
    ║      All-in-One CTF Solving Tool      ║
    ╚═══════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))

@click.group()
def cli():
    """CTF Swiss Army Knife - All-in-one CTF solving tool"""
    print_banner()

@cli.group()
def crypto():
    """Cryptography related tools"""
    pass

@cli.group()
def stego():
    """Steganography related tools"""
    pass

@cli.group()
def forensics():
    """Forensics related tools"""
    pass

@cli.group()
def web():
    """Web exploitation tools"""
    pass

@cli.group()
def binary():
    """Binary analysis tools"""
    pass

# Crypto commands
@crypto.command()
@click.option('--text', required=True, help='Text to encrypt/decrypt')
@click.option('--shift', default=3, help='Shift value for Caesar cipher')
def caesar(text, shift):
    """Caesar cipher encryption/decryption"""
    from modules.crypto.classical import caesar_cipher
    result = caesar_cipher(text, shift)
    console.print(Panel(f"[green]Original:[/green] {text}\n[blue]Result:[/blue] {result}"))

@crypto.command()
@click.option('--text', required=True, help='Text to encrypt/decrypt')
@click.option('--key', required=True, help='Key for Vigenère cipher')
def vigenere(text, key):
    """Vigenère cipher encryption/decryption"""
    from modules.crypto.classical import vigenere_cipher
    result = vigenere_cipher(text, key)
    console.print(Panel(f"[green]Original:[/green] {text}\n[blue]Result:[/blue] {result}"))

# Stego commands
@stego.command()
@click.option('--image', required=True, type=click.Path(exists=True), help='Image file to analyze')
def analyze(image):
    """Analyze an image for hidden data"""
    from modules.stego.image import analyze_image
    results = analyze_image(image)
    console.print(Panel(str(results), title="Image Analysis Results"))

@stego.command()
@click.option('--image', required=True, type=click.Path(exists=True), help='Image file to extract data from')
def extract(image):
    """Extract hidden data from an image"""
    from modules.stego.image import extract_data
    data = extract_data(image)
    console.print(Panel(str(data), title="Extracted Data"))

# Forensics commands
@forensics.command()
@click.option('--file', required=True, type=click.Path(exists=True), help='File to analyze')
def analyze(file):
    """Analyze a file for forensic investigation"""
    from modules.forensics.analyzer import analyze_file
    results = analyze_file(file)
    console.print(Panel(str(results), title="File Analysis Results"))

if __name__ == '__main__':
    cli() 