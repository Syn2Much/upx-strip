# noMoreUPX! 🔧

A simple Python script to strip UPX signatures and metadata from files in a directory.

## What it does

This tool scans all files in a specified directory and replaces known UPX-related strings with null bytes. This can be useful for research, analysis, or obfuscation purposes when working with UPX-packed executables.

## Features

- Scans all files in a target directory
- Replaces multiple UPX signatures and metadata strings
- Non-destructive to file functionality (only modifies specific byte patterns)
- Simple command-line interface

## Usage

```bash
python3 noMoreUPX.py <directory_path>
```

### Example
```bash
python3 noMoreUPX.py ./malware_samples/
```

## UPX Signatures Removed

The script targets various UPX identifiers including:
- UPX magic strings (`UPX!`, `$Id: UPX`)
- Version information (`UPX 0.` through `UPX 5.`)
- Copyright notices and team credits
- Website references (`upx.sf.net`, `http://upx.sf.net`)
- Compression method identifiers (`LZMA`, `NRV2`, etc.)
- Various descriptive strings (`UPX packed`, `UPX compressed`, etc.)

## Requirements

- Python 3.x
- No external dependencies

## Important Notes

⚠️ **Use responsibly and ethically**
- This tool is for educational and research purposes only
- Only use on files you own or have permission to modify
- The tool modifies files in-place - make backups if needed

## Disclaimer

This tool is provided for legitimate security research, malware analysis, and educational purposes only. The author assumes no liability for any misuse or damage caused by this software.

---
**Build Date**: 01/09/2026  
**Contact**: https://t.me/sinackrst
