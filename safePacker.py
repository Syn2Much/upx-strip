#!/usr/bin/env python3
import os
import sys
import shutil
import argparse
import hashlib
import logging
import random
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

#
#       .        :uuuuuuu
#       8F          M$   'WWWWWWWi
#      '$$$$$$"`    'E       #$$$$$
#      t$$$$$       'E       '$$$$$$L    '$"
#      $`````       'E       'E#$$$$$k   'E
#     J&.           'E       'E `$$$$$N  'E
#  '$$$$$$$$$$L     'E       'E   $$$$$$ 'E
#  9$#"`"#$$$$$k   'E       `@"    #$$$$$$E
#         '$$$$$   'E        $      `$$$$$&
#   ..     9$$$$L..JBu       $        R$$$$N
# d$$$R    9$$$F   'E        $         "$$$$$r
# $$$$    J$$$F     {E      .$.         '$$$$$
#  "$$$$$$$$$"   ..u$$u..  uz$$bu         #$$$
#                                          '$$k.
#                     noMoreUPX! V3 01/28/2026
#


# Configure logging
def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger("noMoreUPX")
    logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


logger = setup_logging()

# SAFE patterns - can be replaced without breaking functionality
# These are typically in data/string sections, not structural
UPX_STRINGS_SAFE = [
    b"$Id: UPX ",
    b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $",
    b"$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $",
    b"http://upx.sf.net",
    # URLs and references (safe - just strings)
    b"upx.sourceforge.net",
    b"upx.sf.net",
    b"github.com/upx/upx",
    b"the UPX Team",
    # Copyright notices (safe - just strings)
    b"Markus Oberhumer",
    b"Laszlo Molnar",
    b"John F. Reiser",
]

# UNSAFE patterns - these are structural or too generic
# Only used for DETECTION, not replacement
UPX_STRINGS_DETECT_ONLY = [
    b"UPX!",  # Magic bytes - structural
    b"UPX!u",  # Magic bytes variant
    b"\x55\x50\x58\x21",  # UPX! in hex - structural
    # Section names - NEVER replace these, breaks PE loader
    b"UPX0",
    b"UPX1",
    b"UPX2",
    b"UPX0\x00",
    b"UPX1\x00",
    # Too generic - only 3-4 bytes, high false positive risk
    b"UPX ",  # With space to be slightly safer
    b"UPX 0.",
    b"UPX 1.",
    b"UPX 2.",
    b"UPX 3.",
    b"UPX 4.",
]

# Legacy combined list for backward compatibility (detection only)
UPX_STRINGS = UPX_STRINGS_SAFE + UPX_STRINGS_DETECT_ONLY

# Binary file extensions to always process
BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".drv",
    ".ocx",
    ".cpl",
    ".scr",  # Windows
    ".so",
    ".dylib",
    ".bundle",  # Linux/macOS
    ".elf",
    ".bin",
    ".o",
    ".ko",  # Generic binary
    ".axf",
    ".prx",
    ".puff",
    ".out",  # Other
    ".mips",
    ".arm",
    ".x86",
    ".x86_64",
    ".aarch64",
    ".mipsel",
    ".armv7",
    ".armv6",
    ".powerpc",
    ".ppc",
    ".sparc",
    ".m68k",
    ".sh4",
    ".arc",  # Architecture-specific binaries
}


class PEValidator:
    """Validates and handles PE (Windows executable) file structures"""

    DOS_MAGIC = b"MZ"
    PE_MAGIC = b"PE\x00\x00"

    @staticmethod
    def is_pe_file(data: bytes) -> bool:
        """Check if data is a valid PE file"""
        if len(data) < 64:
            return False
        if data[:2] != PEValidator.DOS_MAGIC:
            return False
        try:
            pe_offset = struct.unpack("<I", data[60:64])[0]
            if pe_offset + 4 > len(data):
                return False
            return data[pe_offset : pe_offset + 4] == PEValidator.PE_MAGIC
        except:
            return False

    @staticmethod
    def get_pe_header_info(data: bytes) -> Optional[Dict]:
        """Extract PE header information for safe modification"""
        if not PEValidator.is_pe_file(data):
            return None

        try:
            pe_offset = struct.unpack("<I", data[60:64])[0]

            # COFF header starts at pe_offset + 4
            coff_offset = pe_offset + 4
            num_sections = struct.unpack("<H", data[coff_offset + 2 : coff_offset + 4])[
                0
            ]
            optional_header_size = struct.unpack(
                "<H", data[coff_offset + 16 : coff_offset + 18]
            )[0]

            # Optional header starts after COFF header (20 bytes)
            optional_header_offset = coff_offset + 20

            # Section table starts after optional header
            section_table_offset = optional_header_offset + optional_header_size

            # Each section header is 40 bytes
            section_table_end = section_table_offset + (num_sections * 40)

            # Determine header end (minimum of all section raw data pointers)
            headers_end = section_table_end
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                raw_data_ptr = struct.unpack(
                    "<I", data[section_offset + 20 : section_offset + 24]
                )[0]
                if raw_data_ptr > 0:
                    headers_end = max(headers_end, raw_data_ptr)
                    break

            # Get checksum offset for later update
            checksum_offset = optional_header_offset + 64  # Standard location

            return {
                "pe_offset": pe_offset,
                "section_table_offset": section_table_offset,
                "section_table_end": section_table_end,
                "num_sections": num_sections,
                "headers_end": headers_end,
                "checksum_offset": checksum_offset,
                "optional_header_offset": optional_header_offset,
            }
        except Exception as e:
            logger.debug(f"Failed to parse PE header: {e}")
            return None

    @staticmethod
    def get_safe_regions(data: bytes) -> List[Tuple[int, int]]:
        """Get regions that are safe to modify (not headers/import tables)"""
        pe_info = PEValidator.get_pe_header_info(data)
        if not pe_info:
            # Not a PE file, be conservative - skip first 4KB
            return [(4096, len(data))]

        # Safe to modify after headers
        # But avoid the first part of each section (could be code entry points)
        safe_start = pe_info["headers_end"]
        return [(safe_start, len(data))]

    @staticmethod
    def update_pe_checksum(data: bytearray, checksum_offset: int) -> bytearray:
        """Recalculate and update PE checksum"""
        try:
            # Zero out existing checksum
            data[checksum_offset : checksum_offset + 4] = b"\x00\x00\x00\x00"

            # Calculate new checksum (simplified PE checksum algorithm)
            checksum = 0
            # Process as 16-bit words
            for i in range(0, len(data) - 1, 2):
                word = struct.unpack("<H", data[i : i + 2])[0]
                checksum += word
                checksum = (checksum & 0xFFFF) + (checksum >> 16)

            # Add any remaining byte
            if len(data) % 2:
                checksum += data[-1]
                checksum = (checksum & 0xFFFF) + (checksum >> 16)

            # Final fold and add file length
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum += len(data)

            # Write new checksum
            data[checksum_offset : checksum_offset + 4] = struct.pack(
                "<I", checksum & 0xFFFFFFFF
            )

            return data
        except Exception as e:
            logger.warning(f"Failed to update PE checksum: {e}")
            return data

    @staticmethod
    def validate_pe_structure(data: bytes) -> Tuple[bool, str]:
        """Validate that PE structure is intact"""
        if not PEValidator.is_pe_file(data):
            return True, "Not a PE file"  # Non-PE files pass validation

        try:
            pe_info = PEValidator.get_pe_header_info(data)
            if not pe_info:
                return False, "Failed to parse PE headers"

            # Check section table integrity
            for i in range(pe_info["num_sections"]):
                section_offset = pe_info["section_table_offset"] + (i * 40)
                section_name = data[section_offset : section_offset + 8]

                # Section name should be null-padded ASCII
                try:
                    name_str = section_name.rstrip(b"\x00").decode("ascii")
                except:
                    return False, f"Invalid section name at index {i}"

            return True, "PE structure valid"
        except Exception as e:
            return False, f"Validation error: {e}"


class BackupManager:
    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create backup directory name
        if os.path.isfile(self.target_path):
            target_name = os.path.basename(self.target_path)
            backup_dir_name = f"backup_{target_name}_{self.timestamp}"
            self.backup_dir = os.path.join(
                os.path.dirname(self.target_path), backup_dir_name
            )
        else:
            backup_dir_name = (
                f"backup_{os.path.basename(self.target_path)}_{self.timestamp}"
            )
            self.backup_dir = os.path.join(self.target_path, "..", backup_dir_name)
            self.backup_dir = os.path.abspath(self.backup_dir)

        # Ensure backup directory exists
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            logger.debug(f"Backup directory created: {self.backup_dir}")
        except Exception as e:
            logger.error(f"Failed to create backup directory: {e}")
            raise

    def backup_file(self, filepath: str) -> Optional[str]:
        """Create a backup of a single file"""
        try:
            filename = os.path.basename(filepath)

            # Add hash to filename for uniqueness
            with open(filepath, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()[:8]

            backup_name = f"{filename}.{file_hash}.bak"
            backup_path = os.path.join(self.backup_dir, backup_name)

            shutil.copy2(filepath, backup_path)
            logger.debug(f"File backed up: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"Backup failed for {filepath}: {e}")
            return None

    def save_operation_log(self, results: Dict) -> str:
        """Save operation log to backup directory with detailed information"""
        log_file = os.path.join(self.backup_dir, "operation.log")

        try:
            with open(log_file, "w") as f:
                f.write(f"noMoreUPX! Operation Log\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_path}\n")
                f.write(f"Backup Directory: {self.backup_dir}\n")
                f.write(f"Total files processed: {results['processed']}\n")
                f.write(f"Files modified: {results['modified']}\n")
                f.write(f"UPX patterns found: {results['patterns_found']}\n")
                f.write(f"Total replacements: {results['total_replacements']}\n")
                f.write("\n" + "=" * 50 + "\n\n")

                for file_result in results["file_results"]:
                    f.write(f"File: {file_result['filename']}\n")
                    f.write(
                        f"  Modified: {'Yes' if file_result['modified'] else 'No'}\n"
                    )
                    if file_result["error"]:
                        f.write(f"  Error: {file_result['error']}\n")
                    if file_result["modified"]:
                        f.write(f"  Replacements: {file_result['replacements']}\n")
                        f.write(
                            f"  Patterns: {', '.join([p.decode('ascii', errors='ignore')[:20] for p in file_result['patterns']])}\n"
                        )
                    f.write("\n")

            logger.debug(f"Operation log saved: {log_file}")
            return log_file
        except Exception as e:
            logger.error(f"Failed to save operation log: {e}")
            return None


def generate_safe_padding(length: int) -> bytes:
    """Generate safe padding for replacing strings in data sections.

    Uses spaces and printable characters that won't cause issues
    if interpreted as strings, and null bytes that are safe in data.
    """
    padding = bytearray()

    for i in range(length):
        strategy = random.random()

        if strategy < 0.5:  # 50% - Null bytes (safest)
            padding.append(0x00)
        elif strategy < 0.8:  # 30% - Spaces (safe for strings)
            padding.append(0x20)
        else:  # 20% - Random printable ASCII (safe for display)
            # Use only safe printable characters
            safe_chars = b".-_=+[]{}|;:,<>?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            padding.append(random.choice(safe_chars))

    return bytes(padding)


def generate_obfuscation_padding(length: int) -> bytes:
    """Generate intelligent obfuscation padding with improved randomness.

    DEPRECATED: Use generate_safe_padding() instead for data sections.
    This function is kept for backward compatibility but should not be
    used on PE/DLL files as it can cause corruption.
    """
    # For safety, just use safe padding now
    return generate_safe_padding(length)


def scan_upx_patterns(data: bytes, safe_only: bool = False) -> List[bytes]:
    """Scan for UPX patterns in data with efficient search

    Args:
        data: Binary data to scan
        safe_only: If True, only return patterns safe to replace
    """
    found_patterns = []
    seen = set()

    # Always check safe patterns
    patterns_to_check = UPX_STRINGS_SAFE if safe_only else UPX_STRINGS

    for upx_str in patterns_to_check:
        if upx_str in data and upx_str not in seen:
            found_patterns.append(upx_str)
            seen.add(upx_str)

    return found_patterns


def scan_upx_patterns_with_locations(data: bytes) -> Dict[bytes, List[int]]:
    """Scan for UPX patterns and return their locations"""
    pattern_locations = {}

    for upx_str in UPX_STRINGS_SAFE:
        locations = []
        start = 0
        while True:
            pos = data.find(upx_str, start)
            if pos == -1:
                break
            locations.append(pos)
            start = pos + 1

        if locations:
            pattern_locations[upx_str] = locations

    return pattern_locations


def is_offset_in_safe_region(
    offset: int, pattern_len: int, safe_regions: List[Tuple[int, int]]
) -> bool:
    """Check if an offset falls within safe regions"""
    for start, end in safe_regions:
        if offset >= start and (offset + pattern_len) <= end:
            return True
    return False


def is_likely_binary(filepath: str) -> bool:
    """Check if file is likely binary by extension and content sampling"""
    try:
        # Check extension first - always process known binary types
        ext = Path(filepath).suffix.lower()
        if ext in BINARY_EXTENSIONS:
            logger.debug(f"Binary extension detected: {ext}")
            return True

        with open(filepath, "rb") as f:
            chunk = f.read(8192)

        if not chunk:
            return False

        # Check for PE header (MZ) - Windows executables/DLLs
        if chunk[:2] == b"MZ":
            return True

        # Check for ELF header - Linux binaries
        if chunk[:4] == b"\x7fELF":
            return True

        # Check for null bytes (binary indicator)
        if b"\x00" in chunk:
            return True

        # Check if mostly printable ASCII
        text_chars = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13))
        return (text_chars / len(chunk)) < 0.75

    except PermissionError:
        logger.warning(f"Permission denied checking: {filepath}")
        return True  # Try to process anyway
    except Exception as e:
        logger.debug(f"Error checking if binary {filepath}: {e}")
        return True  # Assume binary on error


def process_file(
    filepath: str, backup_manager: "BackupManager", dry_run: bool = False
) -> Dict:
    """Process a single file for UPX patterns with PE-aware safe modification"""
    results = {
        "filename": os.path.basename(filepath),
        "modified": False,
        "replacements": 0,
        "patterns": [],
        "skipped_unsafe": 0,
        "error": None,
    }

    try:
        # Skip if not binary
        if not is_likely_binary(filepath):
            logger.debug(f"Skipping non-binary file: {filepath}")
            return results

        with open(filepath, "rb") as f:
            data = f.read()

        # Check for all UPX patterns (for reporting)
        all_patterns = scan_upx_patterns(data, safe_only=False)
        # Get only safe patterns for modification
        safe_patterns = scan_upx_patterns(data, safe_only=True)

        results["patterns"] = all_patterns
        results["skipped_unsafe"] = len(all_patterns) - len(safe_patterns)

        if not all_patterns:
            return results

        # Determine safe regions based on file type
        is_pe = PEValidator.is_pe_file(data)
        pe_info = None
        safe_regions = [(0, len(data))]  # Default: entire file

        if is_pe:
            pe_info = PEValidator.get_pe_header_info(data)
            if pe_info:
                safe_regions = PEValidator.get_safe_regions(data)
                logger.debug(f"PE file detected, safe regions: {safe_regions}")

        if dry_run:
            logger.info(
                f"Found {len(all_patterns)} UPX patterns in {os.path.basename(filepath)} "
                f"({len(safe_patterns)} safe to replace, {results['skipped_unsafe']} structural/unsafe)"
            )
            if is_pe:
                logger.info(
                    f"  -> PE/DLL file: Will preserve headers and section table"
                )
            return results

        # Only proceed if we have safe patterns to replace
        if not safe_patterns:
            logger.info(
                f"Skipping {os.path.basename(filepath)}: Only structural UPX patterns found (unsafe to modify)"
            )
            return results

        # Create backup before modification
        backup_path = backup_manager.backup_file(filepath)
        if backup_path:
            logger.info(f"Backup created: {os.path.basename(backup_path)}")

        # Apply modifications safely
        new_data = bytearray(data)
        replacements = 0
        skipped_locations = 0

        # Get pattern locations for safe replacement
        pattern_locations = scan_upx_patterns_with_locations(data)

        for pattern, locations in pattern_locations.items():
            for loc in locations:
                # Check if location is in safe region
                if not is_offset_in_safe_region(loc, len(pattern), safe_regions):
                    skipped_locations += 1
                    logger.debug(
                        f"Skipping pattern at offset {loc} (in protected region)"
                    )
                    continue

                # Generate safe padding (null bytes for data sections are safer)
                padding = generate_safe_padding(len(pattern))
                new_data[loc : loc + len(pattern)] = padding
                replacements += 1

        if replacements > 0:
            # Update PE checksum if this is a PE file
            if is_pe and pe_info:
                logger.debug("Updating PE checksum...")
                new_data = PEValidator.update_pe_checksum(
                    new_data, pe_info["checksum_offset"]
                )

            # Validate the modified file structure before writing
            is_valid, validation_msg = PEValidator.validate_pe_structure(
                bytes(new_data)
            )
            if not is_valid:
                results["error"] = f"Modification would corrupt file: {validation_msg}"
                logger.error(f"Aborting modification of {filepath}: {validation_msg}")
                return results

            # Write modified file
            with open(filepath, "wb") as f:
                f.write(new_data)

            results["modified"] = True
            results["replacements"] = replacements

            logger.info(
                f"Modified: {os.path.basename(filepath)} ({replacements} patterns replaced, "
                f"{skipped_locations} skipped for safety)"
            )
        else:
            logger.info(
                f"No safe modifications possible for {os.path.basename(filepath)}"
            )

        return results

    except PermissionError as e:
        results["error"] = f"Permission denied (file may be in use): {e}"
        logger.warning(
            f"Permission denied: {filepath} - File may be locked/in use by system"
        )
        return results
    except OSError as e:
        if e.errno == 13:  # Permission denied
            results["error"] = "File is locked or in use"
            logger.warning(f"File locked/in use: {filepath}")
        elif e.errno == 32:  # Sharing violation (Windows)
            results["error"] = "File in use by another process"
            logger.warning(
                f"Sharing violation: {filepath} - Close applications using this DLL"
            )
        else:
            results["error"] = str(e)
            logger.error(f"OS error processing {filepath}: {e}")
        return results
    except MemoryError:
        results["error"] = "File too large to process"
        logger.error(f"File too large (memory error): {filepath}")
        return results
    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Error processing {filepath}: {e}", exc_info=True)
        return results


def print_banner():
    """Print the tool banner"""
    banner = r"""
 __    __            __       __   ______                       __    __  _______   __    __  __ 
|  \  |  \          |  \     /  \ /      \                     |  \  |  \|       \ |  \  |  \|  \
| $$\ | $$  ______  | $$\   /  $$|  $$$$$$\  ______    ______  | $$  | $$| $$$$$$$\| $$  | $$| $$
| $$$\| $$ /      \ | $$$\ /  $$$| $$  | $$ /      \  /      \ | $$  | $$| $$__/ $$ \$$\/  $$| $$
| $$$$\ $$|  $$$$$$\| $$$$\  $$$$| $$  | $$|  $$$$$$\|  $$$$$$\| $$  | $$| $$    $$  >$$  $$ | $$
| $$\$$ $$| $$  | $$| $$\$$ $$ $$| $$  | $$| $$   \$$| $$    $$| $$  | $$| $$$$$$$  /  $$$$\  \$$
| $$ \$$$$| $$__/ $$| $$ \$$$| $$| $$__/ $$| $$      | $$$$$$$$| $$__/ $$| $$      |  $$ \$$\ __ 
| $$  \$$$ \$$    $$| $$  \$ | $$ \$$    $$| $$       \$$     \ \$$    $$| $$      | $$  | $$|  \
 \$$   \$$  \$$$$$$  \$$      \$$  \$$$$$$  \$$        \$$$$$$$  \$$$$$$  \$$       \$$   \$$ \$$
                                                                                                 
    """
    print(banner)
    print(f"                 Build: 01/09/2026")
    print(f"               Author: sintax@exploit.im")
    print(f"              Version: 2.0 (Improved)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="noMoreUPX! - UPX pattern removal tool with backup system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious.exe           # Process single file
  %(prog)s ./malware_samples/       # Process directory
  %(prog)s target.bin --dry-run     # Scan without modifying
  %(prog)s -h                       # Show this help message
        """,
    )

    parser.add_argument("target", help="File or directory to process")
    parser.add_argument(
        "--dry-run",
        "-d",
        action="store_true",
        help="Scan for UPX patterns without modifying files",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed information"
    )
    parser.add_argument("--log", "-l", metavar="FILE", help="Write debug log to file")

    args = parser.parse_args()

    # Setup logging with optional file output
    global logger
    if args.log:
        logger = setup_logging(args.log)

    # Print banner
    print_banner()

    # Validate target
    if not os.path.exists(args.target):
        logger.error(f"Target '{args.target}' does not exist")
        sys.exit(1)

    # Initialize backup manager
    backup_manager = BackupManager(args.target)

    logger.info(f"Target: {args.target}")
    logger.info(
        f"Mode: {'Scan only (dry run)' if args.dry_run else 'Modify with backup'}"
    )
    logger.info(f"Backup directory: {backup_manager.backup_dir}")
    print()

    # Process files
    file_results = []
    total_processed = 0
    total_modified = 0
    total_patterns = 0
    total_replacements = 0

    if os.path.isfile(args.target):
        # Single file mode
        logger.info(f"Processing single file: {os.path.basename(args.target)}")
        result = process_file(args.target, backup_manager, args.dry_run)
        file_results.append(result)
        total_processed = 1
        if result["modified"]:
            total_modified = 1
            total_replacements = result["replacements"]
        total_patterns = len(result["patterns"])

    elif os.path.isdir(args.target):
        # Directory mode
        logger.info(f"Processing directory (recursive): {args.target}")
        files_found = 0

        for root, dirs, files in os.walk(args.target):
            # Skip backup directories
            if "backup_" in root and root.startswith(args.target):
                continue

            for file in files:
                filepath = os.path.join(root, file)

                # Skip very large files (> 100MB)
                try:
                    if os.path.getsize(filepath) > 100 * 1024 * 1024:
                        if args.verbose:
                            logger.debug(f"Skipping large file: {file} (>100MB)")
                        continue
                except OSError:
                    continue

                files_found += 1
                if args.verbose:
                    print(f"  Processing: {file}")

                result = process_file(filepath, backup_manager, args.dry_run)
                file_results.append(result)
                total_processed += 1

                if result["modified"]:
                    total_modified += 1
                    total_replacements += result["replacements"]

                total_patterns += len(result["patterns"])

        logger.debug(f"Total files found: {files_found}")

    # Summary
    print()
    print("=" * 60)
    print("                     PROCESSING SUMMARY")
    print("=" * 60)
    print(f"  Files processed:       {total_processed}")
    print(f"  Files modified:        {total_modified}")
    print(f"  UPX patterns found:    {total_patterns}")
    print(f"  Total replacements:    {total_replacements}")
    print(f"  Backup location:       {backup_manager.backup_dir}")

    if not args.dry_run and total_modified > 0:
        # Save operation log
        results_summary = {
            "processed": total_processed,
            "modified": total_modified,
            "patterns_found": total_patterns,
            "total_replacements": total_replacements,
            "file_results": file_results,
        }

        log_file = backup_manager.save_operation_log(results_summary)
        if log_file:
            print(f"  Operation log:         {log_file}")

        print("\n  [!] IMPORTANT: Original files have been modified!")
        print(f"      Backups saved in: {backup_manager.backup_dir}")

    print("=" * 60)

    if args.dry_run and total_patterns > 0:
        print("\n  [!] Use without --dry-run to apply modifications")
        print("      Backups will be created automatically")
    elif total_patterns == 0:
        print("\n  [✓] No UPX patterns found in target files")

    print("\n[+] Operation completed successfully!\n")

    # Return appropriate exit code
    sys.exit(0 if total_patterns >= 0 else 1)


if __name__ == "__main__":
    main()
