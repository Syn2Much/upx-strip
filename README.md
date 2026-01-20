# noMoreUPX! ☠️ 
## Enjoy the compression and benefits of UPX packing without the artifacts that pop out in analysis. 

## 📋 Features

### 🔍 **Enhanced Detection**
- 28+ UPX signatures, patterns, and artifacts
- Version strings, copyright notices, and metadata
- Section names (UPX0, UPX1, UPX2) and URLs

### 🛡️ **Smart Obfuscation**
- Intelligent padding with mixed strategies:
- Valid x86 opcodes for plausible deniability
- Structured but meaningless data patterns
- Truly random bytes for maximum entropy
- Context-aware replacement strategies
- No obvious patterns (unlike null bytes)

### 💾 **Comprehensive Backup System**
- Automatic backup directory creation
- Hashed filenames for uniqueness
- Operation logs with detailed statistics
- Safe rollback capability

![Animation](https://github.com/user-attachments/assets/ee546d59-f75c-43cc-8259-ec6006f88843)

---

### 🎯 **Professional CLI**
- Clean ASCII art banner
- Support for files and directories
- Dry-run mode for preview
- Verbose output options
- Help system with examples

---

## 🚀 Installation

```bash
# Clone or download the script
chmod +x noMoreUPX.py

# Optional: Install globally
sudo cp noMoreUPX.py /usr/local/bin/nomoreupx
```

**Requirements:**
- Python 3.6+
- Standard library only (no external dependencies)

---

## 📖 Usage

### Basic Operations

```bash
# Process a single file (with automatic backup)
./noMoreUPX.py suspicious.exe

# Process all files in a directory (recursive)
./noMoreUPX.py ./malware_samples/

# Scan only - preview changes without modifying
./noMoreUPX.py target.bin --dry-run

# Verbose output for detailed information
./noMoreUPX.py ./folder/ --verbose

# Show help with examples
./noMoreUPX.py -h
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `target` | File or directory to process (required) |
| `--dry-run`, `-d` | Scan for UPX patterns without modifying files |
| `--verbose`, `-v` | Show detailed processing information |
| `--help`, `-h` | Show help message and exit |

---

## 🏗️ How It Works

### 1. **Detection Phase**
```python
# Scans for multiple UPX signatures:
- Version strings: "$Id: UPX 4.22", "UPX 0." through "UPX 9."
- Magic bytes: "UPX!", "UPX!u"
- Section names: "UPX0", "UPX1", "UPX2"
- URLs: "upx.sourceforge.net", "upx.sf.net", "github.com/upx/upx"
- Metadata: "the UPX Team", "executable packer"
- Copyright: "Markus Oberhumer", "Laszlo Molnar", "John F. Reiser"
```

### 2. **Backup Creation**
```python
# Creates organized backup structure:
backup_targetname_YYYYMMDD_HHMMSS/
├── filename.hash1.bak
├── filename.hash2.bak
└── operation.log
```

### 3. **Obfuscation Engine**
```python
# Generates intelligent padding:
- 30% valid x86 opcodes (NOP, XOR, MOV)
- 30% structured but meaningless patterns
- 40% truly random bytes (os.urandom-like)
# Result: High entropy, difficult to signature
```

### 4. **Safe Replacement**
```python
# Replaces UPX strings with padding:
- Each occurrence gets unique padding
- Maintains file integrity
- Preserves original functionality
```


---

## 📊 Output Example

<img width="1288" height="1227" alt="Screenshot 2026-01-10 205707" src="https://github.com/user-attachments/assets/5c122292-15c0-4ad9-b8f3-f8ab757c77b1" />


### Obfuscation Characteristics
- **Entropy**: High (mixed strategies)
- **Patterns**: Minimal detectable patterns
- **Plausibility**: Resembles valid code/data
- **Uniqueness**: Different padding per occurrence
- **Safety**: Preserves file structure

---

## ⚠️ Important Notes

### Safety First
```bash
# ALWAYS test first:
./noMoreUPX.py --dry-run ./target/

# Backups are created automatically, but:
1. Work on copies of critical files
2. Verify backups before proceeding
3. Test on non-production data first
```

### Best Practices
1. **Always use dry-run first** to see what will be changed
2. **Verify backups** are created successfully
3. **Check operation.log** for detailed results
4. **Test modified files** for functionality
5. **Keep the script updated** with new UPX signatures

---

## 🎯 Use Cases

### Malware Analysis
```bash
# Remove UPX signatures from packed malware
./noMoreUPX.py ./malware_collection/

# Preview UPX usage in samples
./noMoreUPX.py --dry-run ./suspicious_samples/
```

### CTF Challenges
```bash
# Create UPX-obfuscated challenges
# Obfuscate legitimate UPX-packed files
```

### Forensic Analysis
```bash
# Identify UPX-packed files in directories
# Remove UPX artifacts for cleaner analysis
```

### Security Research
```bash
# Study UPX evasion techniques
# Test detection capabilities
```

---

## 📝 Logging & Reporting

The tool creates detailed logs:
```bash
backup_directory/
├── operation.log          # Main operation summary
└── individual backups     # Original files

# Log includes:
- Processing timestamp
- Target specification
- File-by-file results
- Pattern detection details
- Statistics and summaries
```

---

## 🔄 Updating UPX Signatures

To add new UPX patterns:
```python
# Edit the UPX_STRINGS list:
UPX_STRINGS = [
    # Existing patterns...
    b"NEW_UPX_PATTERN",
    b"ANOTHER_PATTERN",
    bytes.fromhex('HEXVALUE'),  # Hex patterns
]
```

Common sources for new signatures:
- UPX changelogs and documentation
- Sample analysis of new UPX versions
- Security research papers
- Community contributions

---

## 🆘 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Permission denied" | Run with appropriate permissions |
| "Target does not exist" | Check path spelling and permissions |
| No modifications made | Use `--dry-run` to see if UPX is detected |
| Backup directory not created | Check write permissions in parent directory |
| Large files skipped | Increase size limit in code (line ~200) |

### Getting Help
1. Check `--dry-run` output first
2. Examine the operation.log file
3. Verify file permissions
4. Ensure Python 3.6+ is installed

---

## 📄 License & Disclaimer

**Educational Use Only**
```
This tool is provided for:
- Authorized security research
- Malware analysis in controlled environments
- Educational purposes
- CTF competitions

NOT for:
- Illegal activities
- Circumventing legitimate protections
- Unauthorized modification of software
```

**Author:** Syn
**Build Date:** 01/09/2026  
**Version:** 2.1 (Enhanced with backup system)

---

## 🙏 Acknowledgments

- The UPX Team for the original packer
- Security researchers for pattern identification
- Open source community for inspiration

---

**⚠️ WARNING:** Always use responsibly and ethically. The authors are not responsible for misuse or damage caused by this tool.
