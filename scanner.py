#!/usr/bin/env python3
#----------------------------#
#  Suspicious File Scanner   #
#         by jaekid          #
#            v0.5            #
#----------------------------#

import os
import re
import sys
import math
import hashlib
import select
import threading
import queue
import datetime
import time
import stat

#----------------------------#
# Terminal color codes
#----------------------------#
RESET="\033[0m"
GREEN="\033[32m"
RED="\033[31m"
ORANGE="\033[38;5;208m"
YELLOW="\033[93m"
BLUE="\033[34m"

#----------------------------#
# Scan Profiles Configuration
#----------------------------#
SCAN_PROFILES = {
    'quick': {
        'max_file_size': 10 * 1024 * 1024,  # 10MB
        'entropy_threshold': 7.8,
        'skip_system_dirs': True,
        'system_dirs': ['/system', '/proc', '/dev', '/sys', 'Android/data', 'Android/obb'],
        'description': 'Quick scan - smaller files, higher threshold, skips system directories'
    },
    'thorough': {
        'max_file_size': 50 * 1024 * 1024,  # 50MB
        'entropy_threshold': 7.65,
        'skip_system_dirs': False,
        'system_dirs': [],
        'description': 'Thorough scan - larger files, lower threshold, scans all directories'
    }
}

# Current scan profile (will be set by user choice)
current_profile = None

#----------------------------#
# Global variables
#----------------------------#
files_scanned = 0
suspicious_files = []
deleted_files = 0
user_kept_files = []
skipped_files = []
estimated_total_files = 0  # Add this for progress tracking

file_queue = queue.Queue()
mod_requests = queue.Queue()  # Worker -> Moderator
spinner_lock = threading.Lock()
halt_flag = False
scan_halted_by_enter = False
in_prompt = False
spinner_active = False  # Start with spinner disabled
run_event = threading.Event()
run_event.set()
whitelisted_files = set()
whitelisted_folders = set()
cleared_files = {}  # {size: set(sha256_hash)}
cleared_files_lock = threading.Lock()
announced_folders = set()

#---------------------------#
# Whitelist
#---------------------------#
WHITELIST_FILE = "/storage/emulated/0/Download/Whitelist.txt"

# Ensure Whitelist.txt exists
os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
if not os.path.exists(WHITELIST_FILE):
    with open(WHITELIST_FILE, "w") as f:
        f.write("# Whitelisted paths\n")

#----------------------------#
# Load Whitelist
#----------------------------#
def load_whitelist():
    """Load whitelisted files and folders from WHITELIST_FILE."""
    whitelisted = {"files": set(), "folders": set()}

    if not os.path.exists(WHITELIST_FILE):
        # Ensure the file exists
        os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
        with open(WHITELIST_FILE, "w") as f:
            f.write("# Whitelisted paths\n")

    with open(WHITELIST_FILE, "r") as f:
        for line in f:
            path = line.strip()
            if not path or path.startswith("#"):
                continue
            if os.path.isdir(path):
                whitelisted["folders"].add(path)
            else:
                whitelisted["files"].add(path)

    return whitelisted

#----------------------------#
# Configuration
#----------------------------#
EXCLUDED_EXTENSIONS = ['.mp4', '.avi', '.jpg', '.jpeg', '.png', '.gif', '.txt', '.mp3', '.3gp', '.ogg', '.log', '.m4a', '.m4u', '.prof', '.0', '.so', '.a', '.dylib', '.chk', '.blk', '.sgv']
EXCLUDED_APKS = ['base.odex', 'base.dm', 'base.apk', 'split_config.arm64_v8a.apk', 'split_config.hdpi.apk', '0', '1', '2', '3', '4']
EXCLUDED_FOLDERS = ['cache']

CHUNK_SIZE = 8192

#----------------------------#
# Utility functions
#----------------------------#
def entropy(filepath):
    try:
        total_bytes = 0
        freq = [0]*256
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                for b in chunk:
                    freq[b] += 1
        if total_bytes == 0:
            return 0
        entropy_val = -sum((count/total_bytes) * math.log2(count/total_bytes) for count in freq if count)
        return entropy_val
    except Exception:
        return 0

def heuristic_check(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in EXCLUDED_EXTENSIONS:
        return False  # skip heuristic for excluded files
    suspicious_keywords = ["thumbnail", "thumbnails"]
    filename = os.path.basename(filepath).lower()
    return any(keyword in filename for keyword in suspicious_keywords)

def should_skip_system_dir(filepath):
    """Check if filepath is in a system directory that should be skipped"""
    if not current_profile['skip_system_dirs']:
        return False
    
    for sys_dir in current_profile['system_dirs']:
        if sys_dir in filepath:
            return True
    return False

def should_skip_extension(filepath):
    """Check if file extension should be skipped"""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in EXCLUDED_EXTENSIONS

def get_display_length(text):
    """Get the actual display length of text, ignoring ANSI color codes"""
    import re
    # Remove ANSI escape sequences
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return len(ansi_escape.sub('', text))

#----------------------------#
# Check if file is malware
#----------------------------#
MALWARE_SIGNATURES = {
    b'\x4d\x5a': 'PE executable',  # MZ header
    b'\x7f\x45\x4c\x46': 'ELF executable',  # ELF header
}

def check_file_signature(filepath):
    """Check file against known malware signatures"""
    try:
        # Skip legitimate library files
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ['.so', '.a', '.dylib']:  # Skip shared libraries
            return None
            
        with open(filepath, 'rb') as f:
            header = f.read(16)
            for sig, description in MALWARE_SIGNATURES.items():
                if header.startswith(sig):
                    return description
    except:
        pass
    return None

#----------------------------#
# Check if file is suspicious
#----------------------------#
def is_suspicious(filepath):
    # Skip excluded extensions
    ext = os.path.splitext(filepath)[1].lower()
    if ext in EXCLUDED_EXTENSIONS:
        return False

    # Skip whitelisted files
    if filepath in whitelisted_files:
        return False

    # Skip whitelisted folders
    folder = os.path.dirname(filepath)
    for wh_folder in whitelisted_folders:
        if folder.startswith(wh_folder):
            return False

    # Skip excluded folders (match actual folder names anywhere in path)
    parts = filepath.split(os.sep)
    if any(part in EXCLUDED_FOLDERS for part in parts):
        return False

    # Skip excluded APKs (match actual file names anywhere in path)
    if any(part in EXCLUDED_APKS for part in parts):
        return False

    # Skip system directories based on profile
    if should_skip_system_dir(filepath):
        return False

    # Skip large files based on profile (too big for entropy check)
    try:
        size = os.path.getsize(filepath)
        if size > current_profile['max_file_size']:
            return False
    except Exception:
        return False

    # Check for malware signatures first (fast check)
    if check_file_signature(filepath):
        return True

    # Entropy + heuristic check with profile-specific threshold
    try:
        ent = entropy(filepath)
        return ent > current_profile['entropy_threshold'] or heuristic_check(filepath)
    except Exception:
        return False

#----------------------------#
# SHA-256 filesize check
#----------------------------#
def sha256_file(filepath):
    try:
        sha = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return None

#----------------------------#
# File estimator
#----------------------------#
def estimate_total_files(root_path):
    """Estimate total files to scan for progress tracking"""
    global estimated_total_files
    print(f"\n{BLUE}Estimating files to scan...{RESET}")
    
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Apply the same filtering logic as the walker
            
            # Skip whitelisted folders  
            dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in whitelisted_folders]
            
            # Skip system directories based on profile
            if current_profile['skip_system_dirs']:
                dirnames[:] = [d for d in dirnames if not any(sys_dir in os.path.join(dirpath, d) for sys_dir in current_profile['system_dirs'])]
            
            # Count files that would actually be scanned
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                
                # Skip whitelisted files (don't count them)
                if filepath in whitelisted_files:
                    continue
                    
                # Skip excluded file types (same logic as walker)
                if should_skip_extension(filepath):
                    continue
                    
                # Skip system directories based on profile
                if should_skip_system_dir(filepath):
                    continue
                
                total += 1
                
                # Cap estimation for performance and show progress
                if total > 1000000:  # 1,000,000 file max estimation
                    print(f"\n{YELLOW}Large directory detected. Estimation capped at 1,000,000+ files.{RESET}")
                    estimated_total_files = total
                    return total
                    
                # Show progress every 20,000 files
                if total % 20000 == 0:
                    sys.stdout.write(f"\r{BLUE}Estimating... {total:,} files found{RESET}")
                    sys.stdout.flush()
                    
    except Exception as e:
        print(f"{RED}Error during estimation: {e}{RESET}")
        estimated_total_files = 1000  # Fallback estimate
        return 1000
    
    estimated_total_files = total
    # Clear any progress line and print final result on a clean line
    sys.stdout.write(f"\r{' ' * 80}\r{GREEN}Estimation complete: ~{total:,} files to scan{RESET}\n")
    sys.stdout.flush()
    return total

#----------------------------#
# Terminal width detection
#----------------------------#
def get_terminal_width():
    """Get terminal width, default to 80 if unable to detect"""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        return 80

#----------------------------#
# Spinner
#----------------------------#
def spinner():
    symbols = "|/-\\"
    idx = 0
    profile_name = "Quick" if current_profile == SCAN_PROFILES['quick'] else "Thorough"
    last_line_length = 0
    
    while not halt_flag:
        if not in_prompt and spinner_active:  # pause while moderator is prompting
            # Calculate progress percentage
            progress_percent = 0
            effective_total = estimated_total_files - len(skipped_files)
            if effective_total > 0:
                progress_percent = min(100, (files_scanned / effective_total) * 100)
            
            # Create smaller progress bar with 10% increments
            bar_width = 10
            filled_width = int(bar_width * (progress_percent // 10) / 10)  # Round to 10% increments
            bar = "█" * filled_width + "░" * (bar_width - filled_width)
            
            # Build the full line as designed
            line = (f"{GREEN}Scanning... {symbols[idx % len(symbols)]}{RESET} | "
                    f"{BLUE}[{bar}] {progress_percent:.0f}%{RESET} | "
                   #f"{GREEN}{files_scanned:,}/{estimated_total_files - len(skipped_files):,}{RESET} | "
                    f"{RED}Suss:{len(suspicious_files)}{RESET} | "
                    f"{ORANGE}Deleted:{deleted_files}{RESET}")
            
            # Get terminal width and check display length (not raw string length)
            term_width = get_terminal_width()
            display_length = get_display_length(line)
            
            if display_length > term_width:
                # Calculate how much to truncate from the actual display length
                truncate_at = term_width - 3  # Reserve 3 chars for "..."
                
                # Truncate while preserving color codes
                line = line[:len(line) - (display_length - truncate_at)] + "..."
            
            # Clear previous line completely before writing new one
            clear_chars = max(0, last_line_length - get_display_length(line))
            sys.stdout.write("\r" + line + " " * clear_chars)
            sys.stdout.flush()
            last_line_length = get_display_length(line)
            
            # Only increment when we actually display
            idx = (idx + 1) % len(symbols)
        
        time.sleep(0.1)

#----------------------------#
# Scan Worker 
#----------------------------#
def is_safe_file(path):
    try:
        mode = os.stat(path, follow_symlinks=False).st_mode
        # Only allow regular files
        return stat.S_ISREG(mode)
    except Exception:
        return False

def scan_worker():
    global files_scanned, suspicious_files, skipped_files, user_kept_files, deleted_files, halt_flag, scan_halted_by_enter, cleared_files

    while not halt_flag or not file_queue.empty():
        if not run_event.wait(timeout=0.1):
            continue

        try:
            filepath = file_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        if filepath is None:
            try:
                file_queue.task_done()
            except ValueError:
                pass
            break

        try:
            # Skip special files that could cause hangs (FIFOs, sockets, devices, etc.)
            if not is_safe_file(filepath):
                skipped_files.append(filepath)
                continue

            # Skip files already whitelisted - DON'T count them in files_scanned
            if filepath in whitelisted_files:
                skipped_files.append(filepath)
                continue

            size = os.path.getsize(filepath)

            # Check for duplicate by size and SHA
            file_sha = None
            if size in cleared_files:
                file_sha = sha256_file(filepath)
                if file_sha in cleared_files[size]:
                    # Duplicate found, skip
                    skipped_files.append(filepath)
                    continue

            # Only increment files_scanned for files that are actually processed
            files_scanned += 1

            if is_suspicious(filepath):
                resp_q = queue.Queue(maxsize=1)
                try:
                    mod_requests.put((filepath, resp_q), timeout=0.5)
                except queue.Full:
                    skipped_files.append(filepath)
                    continue

                try:
                    decision = resp_q.get(timeout=None)  # wait indefinitely
                except Exception:
                    decision = 'n'

                if decision == 'y':
                    user_kept_files.append(filepath)
                elif decision == 'stop':
                    halt_flag = True
                    scan_halted_by_enter = True
                else:
                    suspicious_files.append(filepath)

            # Add file to cleared_files
            if file_sha is None:
                file_sha = sha256_file(filepath)
            if size not in cleared_files:
                cleared_files[size] = set()
            cleared_files[size].add(file_sha)

        except PermissionError:
            skipped_files.append(filepath)
        except Exception:
            skipped_files.append(filepath)
        finally:
            try:
                file_queue.task_done()
            except ValueError:
                pass

#----------------------------#
# Moderator thread
#----------------------------#
def moderator():
    global in_prompt, deleted_files, halt_flag, scan_halted_by_enter, announced_folders, user_kept_files

    while not halt_flag:
        try:
            item = mod_requests.get(timeout=0.1)
        except queue.Empty:
            if halt_flag:
                break
            continue

        if item is None:
            mod_requests.task_done()
            break

        filepath, resp_q = item
        folder = os.path.dirname(filepath)

        # Skip if already whitelisted
        if filepath in whitelisted_files:
            try:
                resp_q.put('y')
            except Exception:
                pass
            mod_requests.task_done()
            continue

        # Pause workers
        run_event.clear()
        in_prompt = True

        # List all files in folder
        try:
            all_names = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
        except Exception:
            all_names = [os.path.basename(filepath)]

        # Show folder message once
        if folder not in announced_folders:
            print()
            print(f"\n{YELLOW}Folder with suspicious file(s) detected: {folder}{RESET}")
            print(f"\n{BLUE}Please be patient while the folder is scanned...{RESET}\n")
            announced_folders.add(folder)

        # Determine suspicious files
        eligible_names = []
        for name in all_names:
            path_f = os.path.join(folder, name)
            if path_f in whitelisted_files:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in EXCLUDED_EXTENSIONS:
                continue
            try:
                if is_suspicious(path_f):
                    eligible_names.append(name)
            except Exception:
                continue

        # Folder preview for >=5 suspicious files
        if len(eligible_names) >= 5:
            preview_text = "\n".join(eligible_names[:5])
            remaining = len(eligible_names) - 5
            choice = None
            print(f"[Whitelist] Suspicious folder preview:\n\n{preview_text}")
            if remaining > 0:
                print(f"...and {remaining} more.")
                print()

            while choice not in ('y', 'n', 'stop') and not halt_flag:
                choice = input("Whitelist all files in this folder? (y/n or stop): ").strip().lower()

            print()
            if choice == 'y':
                # Only add specifically kept files to user_kept_files
                for name in eligible_names:
                    path_f = os.path.join(folder, name)
                    if path_f not in whitelisted_files:
                        user_kept_files.append(path_f)
                        whitelisted_files.add(path_f)
                        try:
                            with open(WHITELIST_FILE, "a") as wf:
                                wf.write(path_f + "\n")
                        except Exception:
                            pass
                try:
                    resp_q.put('y')
                except Exception:
                    pass
                in_prompt = False
                run_event.set()
                mod_requests.task_done()
                continue

            elif choice == 'stop':
                try:
                    resp_q.put('stop')
                except Exception:
                    pass
                halt_flag = True
                scan_halted_by_enter = True
                in_prompt = False
                run_event.set()
                mod_requests.task_done()
                continue

            elif choice == 'n':
                # Ask individually for suspicious files
                original_resp_sent = False
                for name in eligible_names:
                    if halt_flag:
                        break
                    path_f = os.path.join(folder, name)
                    if path_f in whitelisted_files:
                        continue
                    
                    single_choice = None
                    while single_choice not in ('y', 'n', 'stop') and not halt_flag:
                        print()
                        single_choice = input(f"[Whitelist] Suspicious file: {name}\nWhitelist this file? (y/n or stop): ").strip().lower()

                    if single_choice == 'y':
                        user_kept_files.append(path_f)
                        whitelisted_files.add(path_f)
                        try:
                            with open(WHITELIST_FILE, "a") as wf:
                                wf.write(path_f + "\n")
                        except Exception:
                            pass
                    elif single_choice == 'stop':
                        if path_f == filepath:
                            try:
                                resp_q.put('stop')
                            except Exception:
                                pass
                            original_resp_sent = True
                        halt_flag = True
                        scan_halted_by_enter = True
                        break
                    else:
                        # delete handling remains, no append to user_kept
                        delete_choice = None
                        while delete_choice not in ('y', 'n') and not halt_flag:
                            delete_choice = input(f"Delete this file? {name} (y/n): ").strip().lower()
                        if delete_choice == 'y':
                            try:
                                os.remove(path_f)
                                deleted_files += 1
                                print(f"Deleted: {path_f}")
                            except Exception:
                                skipped_files.append(path_f)

                    if path_f == filepath and not original_resp_sent:
                        try:
                            resp_q.put(single_choice)
                        except Exception:
                            pass
                        original_resp_sent = True

                in_prompt = False
                run_event.set()
                mod_requests.task_done()
                continue

        # Fallback for <5 suspicious files
        choice = None
        while choice not in ('y', 'n', 'stop') and not halt_flag:
            print()
            choice = input(f"[Whitelist] Suspicious file: {os.path.basename(filepath)}\nWhitelist this file? (y/n or stop): ").strip().lower()

        if choice == 'y':
            user_kept_files.append(filepath)
            whitelisted_files.add(filepath)
            try:
                with open(WHITELIST_FILE, "a") as wf:
                    wf.write(filepath + "\n")
            except Exception:
                pass
        elif choice == 'stop':
            halt_flag = True
            scan_halted_by_enter = True
        else:
            delete_choice = None
            while delete_choice not in ('y', 'n') and not halt_flag:
                delete_choice = input(f"Delete this file? {os.path.basename(filepath)} (y/n): ").strip().lower()
            if delete_choice == 'y':
                try:
                    os.remove(filepath)
                    deleted_files += 1
                    print(f"Deleted: {filepath}")
                except Exception:
                    skipped_files.append(filepath)

        try:
            resp_q.put(choice)
        except Exception:
            pass

        in_prompt = False
        run_event.set()
        mod_requests.task_done()
        print()

#----------------------------#
# File Walker
#----------------------------#
def walker(root_path, whitelisted_files, whitelisted_folders):
    """Walks the filesystem and queues non-excluded files for scanning."""
    global halt_flag

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        if halt_flag:
            break

        # Skip whitelisted folders
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in whitelisted_folders]

        # Skip system directories based on profile
        if current_profile['skip_system_dirs']:
            dirnames[:] = [d for d in dirnames if not any(sys_dir in os.path.join(dirpath, d) for sys_dir in current_profile['system_dirs'])]

        for filename in filenames:
            if halt_flag:
                break

            filepath = os.path.join(dirpath, filename)

            # Skip whitelisted files (same as estimation logic)
            if filepath in whitelisted_files:
                continue

            # Skip excluded file types
            if should_skip_extension(filepath):
                continue

            # Skip system directories based on profile
            if should_skip_system_dir(filepath):
                continue

            # Queue the file for scanning
            file_queue.put(filepath)

#----------------------------#
# Report generation
#----------------------------#
def generate_report(last_scanned=None, error=None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    download_path = "/storage/emulated/0/Download"
    os.makedirs(download_path, exist_ok=True)
    profile_name = "Quick" if current_profile == SCAN_PROFILES['quick'] else "Thorough"
    report_path = os.path.join(download_path, f"Scan_Report_{profile_name}_{timestamp}.txt")
    try:
        with open(report_path, 'w') as f:
            f.write(f"Scan Profile: {profile_name}\n")
            f.write(f"Max file size: {current_profile['max_file_size'] / (1024*1024):.0f}MB\n")
            f.write(f"Entropy threshold: {current_profile['entropy_threshold']}\n")
            f.write(f"Skip system dirs: {current_profile['skip_system_dirs']}\n")
            f.write(f"Estimated total files: {estimated_total_files:,}\n")
            f.write(f"\nFiles scanned: {files_scanned:,}\n")
            f.write(f"Suss: {len(suspicious_files)}\n")
            f.write(f"Deleted: {deleted_files}\n")
            f.write(f"(user kept): {len(user_kept_files)}\n")
            f.write(f"Skipped files: {len(skipped_files):,}\n")

            if user_kept_files:
                f.write("\nUser-kept files:\n")
                for kept in user_kept_files:
                    f.write(f"{kept}\n")

            if error:
                f.write("\n--- ERROR DETECTED ---\n")
                f.write(f"{error}\n")
                if last_scanned:
                    f.write(f"Last scanned file before error: {last_scanned}\n")

        # Save whitelist back to file
        with open(WHITELIST_FILE, "a") as w:
            for path in whitelisted_files:
                w.write(path + "\n")
            for folder in whitelisted_folders:
                w.write(folder + "\n")

        return report_path
    except Exception as e:
        # Fallback if even writing report fails
        print(f"Report could not be saved: {e}")
        return None

#----------------------------#
# Enter key listener
#----------------------------#
def enter_listener():
    global halt_flag, scan_halted_by_enter, in_prompt, run_event, spinner_active
    if not hasattr(sys.stdin, "fileno") or not sys.stdin.isatty():
        return

    while not halt_flag:
        if spinner_active and not in_prompt:
            try:
                r, _, _ = select.select([sys.stdin], [], [], 0.1)
                if r:
                    line = sys.stdin.readline()
                    if line.strip() == "":
                        if not scan_halted_by_enter:
                            scan_halted_by_enter = True
                            halt_flag = True
                            sys.stdout.write("\nProcess halted. Please wait while report is generated...\n")
                            sys.stdout.flush()
                            run_event.set()
                            break
            except (OSError, ValueError):
                break
        else:
            time.sleep(0.05)

    # If scanning stopped from elsewhere, also print message
    if halt_flag and not scan_halted_by_enter:
        scan_halted_by_enter = True
        sys.stdout.write("\nScan halted. Please wait while report is generated...")
        sys.stdout.flush()
        run_event.set()

#----------------------------#
# Profile Selection
#----------------------------#
def select_scan_profile():
    """Prompt user to select scan profile and return the selected profile."""
    print(f"\n{BLUE}Available Scan Profiles:{RESET}\n")
    print(f"{GREEN}[q] Quick:{RESET} {SCAN_PROFILES['quick']['description']}")
    print(f"{YELLOW}[t] Thorough:{RESET} {SCAN_PROFILES['thorough']['description']}")
    print()
    
    while True:
        choice = input("Please enter 'q' for quick scan or 't' for thorough scan: ").strip().lower()
        
        if choice == 'q':
            print(f"{GREEN}Quick scan selected.{RESET}")
            return SCAN_PROFILES['quick']
        elif choice == 't':
            print(f"{YELLOW}Thorough scan selected.{RESET}")
            return SCAN_PROFILES['thorough']
        else:
            print(f"{RED}Invalid choice. Please enter 'q' for quick or 't' for thorough.{RESET}")

#----------------------------#
# Start Scan
#----------------------------#
def start_scan():
    """Kick off walker + worker threads and wait for completion or halt."""
    global halt_flag, spinner_active

    # Load whitelist
    whitelisted = load_whitelist()
    for f in whitelisted["files"]:
        whitelisted_files.add(f)
    for d in whitelisted["folders"]:
        whitelisted_folders.add(d)

    # Determine root scan path
    root_scan = "/storage/emulated/0"
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            root_scan = "/"
    except Exception:
        pass

    # DISABLE spinner during estimation
    spinner_active = False
    
    # Estimate total files BEFORE starting threads
    estimate_total_files(root_scan)
    print()  # Add spacing after estimation

    # NOW enable spinner and start the spinner and enter listener threads
    spinner_active = True
    spinner_thread = threading.Thread(target=spinner, daemon=True)
    spinner_thread.start()
    enter_thread = threading.Thread(target=enter_listener, daemon=True)
    enter_thread.start()

    # Start moderator thread
    mod_thread = threading.Thread(target=moderator, daemon=True)
    mod_thread.start()

    # Start worker threads
    num_workers = max(2, (os.cpu_count() or 4) // 2)
    worker_threads = []
    for _ in range(num_workers):
        t = threading.Thread(target=scan_worker, daemon=True)
        worker_threads.append(t)
        t.start()

    # Start walker (producer)
    w = threading.Thread(target=walker, args=(root_scan, whitelisted_files, whitelisted_folders), daemon=True)
    w.start()

    # Wait for queue to drain or halt
    while not halt_flag:
        try:
            if file_queue.unfinished_tasks == 0 and not w.is_alive():
                break
        except Exception:
            break
        time.sleep(0.1)

    # Ensure all sentinels present
    for _ in range(len(worker_threads)):
        file_queue.put(None)

    # Join workers
    for t in worker_threads:
        t.join(timeout=1.0)

    # Tell moderator no more prompts
    mod_requests.put(None)
    
    # Stop spinner
    spinner_active = False
    spinner_thread.join(timeout=1.0)

#----------------------------#
# Main execution
#----------------------------#
if __name__ == "__main__":

    print("\033[2J\033[H", end="") # Clear the screen
    print(f"""
{BLUE}╔═══════════════════════════════════════════════╗{RESET}
{BLUE}║{RESET}       {RED}███████╗██╗   ██╗███████╗███████╗{RESET}       {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}██╔════╝██║   ██║██╔════╝██╔════╝{RESET}       {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}███████╗██║   ██║███████╗███████╗{RESET}       {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}╚════██║██║   ██║╚════██║╚════██║{RESET}       {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}███████║╚██████╔╝███████║███████║{RESET}       {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}╚══════╝ ╚═════╝ ╚══════╝╚══════╝{RESET}       {BLUE}║{RESET}
{BLUE}║{RESET}                                               {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}███████╗ ██████╗ █████╗ ███╗   ██╗{RESET}      {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}██╔════╝██╔════╝██╔══██╗████╗  ██║{RESET}      {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}███████╗██║     ███████║██╔██╗ ██║{RESET}      {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}╚════██║██║     ██╔══██║██║╚██╗██║{RESET}      {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}███████║╚██████╗██║  ██║██║ ╚████║{RESET}      {BLUE}║{RESET}
{BLUE}║{RESET}       {RED}╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{RESET}      {BLUE}║{RESET}
{BLUE}║{RESET}                                               {BLUE}║{RESET}
{BLUE}║{RESET}        {YELLOW}SUSPICIOUS FILE SCANNER v0.5{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}                 {GREEN}by jaekid{RESET}                     {BLUE}║{RESET}
{BLUE}╚═══════════════════════════════════════════════╝{RESET}
""")
    
    # Profile selection
    current_profile = select_scan_profile()
    
    print("\nPress Enter or Ctrl + C at any time to halt scanning.\n")

    # Ensure spinner is disabled before starting
    spinner_active = False

    try:
        start_scan()
    except KeyboardInterrupt:
        scan_halted_by_enter = True
        halt_flag = True

    # Stop the spinner and ensure the line ends
    spinner_active = False
    print()  # end spinner line

    print()  # blank line before report message
    if not scan_halted_by_enter:
        print("Scan complete! Generating report...\n")

    # Generate report and show result
    report_file = generate_report()
    if report_file:
        print(f"Report saved to {report_file}\n")
    else:
        print("Report could not be saved.\n")

    # Final summary
    profile_name = "Quick" if current_profile == SCAN_PROFILES['quick'] else "Thorough"
    print(f"{BLUE}Scan Profile: {profile_name}{RESET}")
    print(f"{GREEN}Files scanned: {files_scanned}{RESET}, "
          f"{RED}Suss: {len(suspicious_files)}{RESET}, "
          f"{ORANGE}Deleted: {deleted_files}{RESET}, "
          f"{YELLOW}(user kept): {len(user_kept_files)}{RESET}\n")
