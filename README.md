# NoMoreUPX! is a Python script to detect and/or remove UPX strings from packed binary executables 

![Animation](https://github.com/user-attachments/assets/ee546d59-f75c-43cc-8259-ec6006f88843)

## Features
- **Detection:** 28+ UPX strings/artifacts (magic bytes, section names, URLs, metadata, version strings)
- **Obfuscation:** mixed padding strategies (valid x86-looking bytes, structured noise, true randomness)
- **Backups:** auto backup folder, hashed filenames, `operation.log`, rollback-friendly
- **CLI:** file/dir support, `--dry-run`, `--verbose`, built-in help

## Installation
```bash
chmod +x noMoreUPX.py
sudo cp noMoreUPX.py /usr/local/bin/nomoreupx  # optional
```

**Requirements:** Python 3.6+ (stdlib only)

## Usage
```bash
# single file
./noMoreUPX.py suspicious.exe

# directory (recursive)
./noMoreUPX.py ./samples/

# scan only
./noMoreUPX.py target.bin --dry-run

# verbose
./noMoreUPX.py ./samples/ --verbose
```

## What it does (high level)
1. **Detects** common UPX markers (strings/sections/URLs/etc.)
2. **Creates backups** in a timestamped folder (with hashed names + log)
3. **Replaces** detected markers with realistic, high-entropy padding (unique per hit)

## Notes
- Always run **`--dry-run` first** and test on copies.
- See `operation.log` inside the backup directory for details.

## License / Disclaimer
**Educational use only.** Use responsibly and only with proper authorization.

**Author:** Syn • **Version:** 2.1 • **Build:** 2026-01-09
