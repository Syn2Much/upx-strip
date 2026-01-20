#!/usr/bin/env python3
import os
import sys
import shutil
import argparse
import hashlib
from datetime import datetime
from pathlib import Path

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
#                     noMoreUPX! build date 01/09/2026
#                                sintax@exploit.im

UPX_STRINGS = [
    b"$Id: UPX ",
    b'UPX!',
    b'$Info: This file is packed with the UPX executable packer http://upx.sf.net $',
    b'$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $',
    b'UPX!u',
    b"http://upx.sf.net",
    b"UPX",
    b"UPX 0.",
    b"UPX 1.",
    b"UPX 2.",
    b"UPX 3.",
    b"UPX 4.",
    b"UPX 5.",
    b"UPX 6.",
    b"UPX 7.",
    b"UPX 8.",
    b"UPX 9.",
    # Section names
    b"UPX0",
    b"UPX1",
    b"UPX2",
    # URLs and references
    b"upx.sourceforge.net",
    b"upx.sf.net",
    b"github.com/upx/upx",
    b"the UPX Team",
    # Copyright notices
    b"Copyright (C) 1996-",
    b"Markus Oberhumer",
    b"Laszlo Molnar",
    b"John F. Reiser",
]


class BackupManager:
    def __init__(self, target_path):
        self.target_path = os.path.abspath(target_path)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create backup directory name
        if os.path.isfile(self.target_path):
            target_name = os.path.basename(self.target_path)
            backup_dir_name = f"backup_{target_name}_{self.timestamp}"
            self.backup_dir = os.path.join(os.path.dirname(self.target_path), backup_dir_name)
        else:
            backup_dir_name = f"backup_{os.path.basename(self.target_path)}_{self.timestamp}"
            self.backup_dir = os.path.join(self.target_path, "..", backup_dir_name)
            self.backup_dir = os.path.abspath(self.backup_dir)
        
        # Ensure backup directory exists
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def backup_file(self, filepath):
        """Create a backup of a single file"""
        try:
            filename = os.path.basename(filepath)
            backup_path = os.path.join(self.backup_dir, filename)
            
            # Add hash to filename for uniqueness
            with open(filepath, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()[:8]
            
            backup_name = f"{filename}.{file_hash}.bak"
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            shutil.copy2(filepath, backup_path)
            return backup_path
        except Exception as e:
            print(f"  [!] Backup failed for {filepath}: {e}")
            return None
    
    def save_operation_log(self, results):
        """Save operation log to backup directory"""
        log_file = os.path.join(self.backup_dir, "operation.log")
        
        with open(log_file, 'w') as f:
            f.write(f"noMoreUPX! Operation Log\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.target_path}\n")
            f.write(f"Backup Directory: {self.backup_dir}\n")
            f.write(f"Total files processed: {results['processed']}\n")
            f.write(f"Files modified: {results['modified']}\n")
            f.write(f"UPX patterns found: {results['patterns_found']}\n")
            f.write(f"Total replacements: {results['total_replacements']}\n")
            f.write("\n" + "="*50 + "\n\n")
            
            for file_result in results['file_results']:
                f.write(f"File: {file_result['filename']}\n")
                f.write(f"  Modified: {'Yes' if file_result['modified'] else 'No'}\n")
                if file_result['modified']:
                    f.write(f"  Replacements: {file_result['replacements']}\n")
                    f.write(f"  Patterns: {', '.join([p.decode('ascii', errors='ignore')[:20] for p in file_result['patterns']])}\n")
                f.write("\n")
        
        return log_file

def generate_obfuscation_padding(length):
    """Generate intelligent obfuscation padding"""
    import random
    
    # Mix different types of bytes for better obfuscation
    padding = bytearray()
    
    for i in range(length):
        # Random strategy selection
        strategy = random.random()
        
        if strategy < 0.3:  # 30% - Random valid x86 opcodes
            opcodes = [
                0x90, 0x90, 0x90, 0x90,  # NOP (common)
                0x31, 0xC0, 0x31, 0xC9,  # XOR reg, reg
                0x48, 0x89, 0xC7, 0x48,  # MOV instructions
                0x89, 0xF8, 0x8B, 0xFF,  # More MOV
                0xC3, 0xCC, 0xF4, 0xFB,  # RET, INT3, HLT, STI
            ]
            padding.append(random.choice(opcodes))
        
        elif strategy < 0.6:  # 30% - Structured but meaningless data
            patterns = [
                lambda x: (x % 256),                    # Incrementing pattern
                lambda x: 0x00 if random.random() < 0.1 else random.randint(1, 255),  # Sparse nulls
                lambda x: 0xFF if random.random() < 0.1 else random.randint(0, 254),  # Sparse 0xFF
                lambda x: random.choice([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]),  # Common hex words
            ]
            pattern = random.choice(patterns)
            padding.append(pattern(i))
        
        else:  # 40% - Truly random
            padding.append(random.randint(0, 255))
    
    return bytes(padding)

def scan_upx_patterns(data):
    """Scan for UPX patterns in data"""
    found_patterns = []
    for upx_str in UPX_STRINGS:
        if upx_str in data:
            found_patterns.append(upx_str)
    return found_patterns

def process_file(filepath, backup_manager, dry_run=False):
    """Process a single file for UPX patterns"""
    results = {
        'filename': os.path.basename(filepath),
        'modified': False,
        'replacements': 0,
        'patterns': []
    }
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Scan for UPX patterns
        found_patterns = scan_upx_patterns(data)
        results['patterns'] = found_patterns
        
        if not found_patterns:
            return results
        
        if dry_run:
            print(f"  [SCAN] Found {len(found_patterns)} UPX patterns")
            return results
        
        # Create backup before modification
        backup_path = backup_manager.backup_file(filepath)
        if backup_path:
            print(f"  [✓] Backup created: {os.path.basename(backup_path)}")
        
        # Apply modifications
        new_data = data
        replacements = 0
        
        for upx_str in found_patterns:
            # Replace each occurrence with obfuscated padding
            while upx_str in new_data:
                padding = generate_obfuscation_padding(len(upx_str))
                new_data = new_data.replace(upx_str, padding, 1)
                replacements += 1
        
        if new_data != data:
            # Write modified file
            with open(filepath, 'wb') as f:
                f.write(new_data)
            
            results['modified'] = True
            results['replacements'] = replacements
            
            print(f"  [✓] Modified: {replacements} UPX patterns replaced")
        
        return results
        
    except PermissionError:
        print(f"  [!] Permission denied: {filepath}")
        return results
    except Exception as e:
        print(f"  [!] Error processing {filepath}: {e}")
        return results

def print_banner():
    """Print the tool banner"""
    print(r"""
 __    __            __       __   ______                       __    __  _______   __    __  __ 
|  \  |  \          |  \     /  \ /      \                     |  \  |  \|       \ |  \  |  \|  \
| $$\ | $$  ______  | $$\   /  $$|  $$$$$$\  ______    ______  | $$  | $$| $$$$$$$\| $$  | $$| $$
| $$$\| $$ /      \ | $$$\ /  $$$| $$  | $$ /      \  /      \ | $$  | $$| $$__/ $$ \$$\/  $$| $$
| $$$$\ $$|  $$$$$$\| $$$$\  $$$$| $$  | $$|  $$$$$$\|  $$$$$$\| $$  | $$| $$    $$  >$$  $$ | $$
| $$\$$ $$| $$  | $$| $$\$$ $$ $$| $$  | $$| $$   \$$| $$    $$| $$  | $$| $$$$$$$  /  $$$$\  \$$
| $$ \$$$$| $$__/ $$| $$ \$$$| $$| $$__/ $$| $$      | $$$$$$$$| $$__/ $$| $$      |  $$ \$$\ __ 
| $$  \$$$ \$$    $$| $$  \$ | $$ \$$    $$| $$       \$$     \ \$$    $$| $$      | $$  | $$|  \
 \$$   \$$  \$$$$$$  \$$      \$$  \$$$$$$  \$$        \$$$$$$$  \$$$$$$  \$$       \$$   \$$ \$$
                                                                                                 
    """)    
    print(f"                 Build: 01/09/2026")
    print(f"               Author: sintax@exploit.im")
    print()

def main():
    parser = argparse.ArgumentParser(
        description='noMoreUPX! - UPX pattern removal tool with backup system',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious.exe           # Process single file
  %(prog)s ./malware_samples/       # Process directory
  %(prog)s target.bin --dry-run     # Scan without modifying
  %(prog)s -h                       # Show this help message
        """
    )
    
    parser.add_argument('target', help='File or directory to process')
    parser.add_argument('--dry-run', '-d', action='store_true', 
                       help='Scan for UPX patterns without modifying files')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed information')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate target
    if not os.path.exists(args.target):
        print(f"[!] Error: Target '{args.target}' does not exist")
        sys.exit(1)
    
    # Initialize backup manager
    backup_manager = BackupManager(args.target)
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Mode: {'Scan only (dry run)' if args.dry_run else 'Modify with backup'}")
    print(f"[*] Backup directory: {backup_manager.backup_dir}")
    print()
    
    # Process files
    file_results = []
    total_processed = 0
    total_modified = 0
    total_patterns = 0
    total_replacements = 0
    
    if os.path.isfile(args.target):
        # Single file mode
        print(f"[*] Processing single file:")
        result = process_file(args.target, backup_manager, args.dry_run)
        file_results.append(result)
        total_processed = 1
        if result['modified']:
            total_modified = 1
            total_replacements = result['replacements']
        total_patterns = len(result['patterns'])
        
    elif os.path.isdir(args.target):
        # Directory mode
        print(f"[*] Processing directory (recursive):")
        
        for root, dirs, files in os.walk(args.target):
            # Skip backup directories
            if 'backup_' in root and root.startswith(args.target):
                continue
                
            for file in files:
                filepath = os.path.join(root, file)
                
                # Skip very large files (> 100MB)
                if os.path.getsize(filepath) > 100 * 1024 * 1024:
                    if args.verbose:
                        print(f"  [.] Skipping large file: {file} (>100MB)")
                    continue
                
                print(f"  [.] Processing: {file}")
                
                result = process_file(filepath, backup_manager, args.dry_run)
                file_results.append(result)
                total_processed += 1
                
                if result['modified']:
                    total_modified += 1
                    total_replacements += result['replacements']
                
                total_patterns += len(result['patterns'])
    
    # Summary
    print()
    print("="*60)
    print("                     PROCESSING SUMMARY")
    print("="*60)
    print(f"  Files processed:       {total_processed}")
    print(f"  Files modified:        {total_modified}")
    print(f"  UPX patterns found:    {total_patterns}")
    print(f"  Total replacements:    {total_replacements}")
    print(f"  Backup location:       {backup_manager.backup_dir}")
    
    if not args.dry_run and total_modified > 0:
        # Save operation log
        results_summary = {
            'processed': total_processed,
            'modified': total_modified,
            'patterns_found': total_patterns,
            'total_replacements': total_replacements,
            'file_results': file_results
        }
        
        log_file = backup_manager.save_operation_log(results_summary)
        print(f"  Operation log:         {log_file}")
        
        print("\n  [!] IMPORTANT: Original files have been modified!")
        print(f"      Backups saved in: {backup_manager.backup_dir}")
    
    print("="*60)
    
    if args.dry_run and total_patterns > 0:
        print("\n  [!] Use without --dry-run to apply modifications")
        print("      Backups will be created automatically")
    
    print("\n[+] Operation completed successfully!\n")

if __name__ == "__main__":
    main()
