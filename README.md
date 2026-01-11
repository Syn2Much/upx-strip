# noMoreUPX! - UPX Packer Detection & String Removal Tool

A simple Python tool that detects and removes UPX packer signatures from files in a directory.

## Features
- Detects multiple UPX packer signatures and version strings
- Automatically replaces UPX markers with null bytes
- Processes all files in a specified directory
- Lightweight and easy to use

## Installation
```bash
# Clone the repository or download the script
chmod +x noMoreUPX.py
```

## Usage
```bash
./noMoreUPX.py <directory_path>
```

### Example
```bash
./noMoreUPX.py ./malware_samples/
```

## What it Does
The script scans all files in the specified directory and removes the following UPX signatures:
- UPX version strings (e.g., "$Id: UPX 4.22")
- UPX magic bytes ("UPX!")
- UPX website reference ("http://upx.sf.net")
- Other UPX-related markers

## Requirements
- Python 3.x
- Standard library only (no external dependencies)

## Important Notes
- **WARNING**: This tool modifies files in place. Make backups before use.
- Designed for security research and malware analysis
- Only processes regular files (skips directories and symlinks)
- Use responsibly and only on files you own or have permission to modify

## Build Information
- Build date: 01/09/2026
- Contact: t.me/sinackrst

## License
Tool provided for educational and research purposes.
