#!/usr/bin/env python3
#----------------------------#
#  Suspicious File Scanner   #
#         by jaekid          #
#            v0.3            #
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

#----------------------------#
# Terminal color codes
#----------------------------#
RESET="\033[0m"
GREEN="\033[32m"
RED="\033[31m"
ORANGE="\033[38;5;208m"
YELLOW="\033[93m"

#----------------------------#
# Global variables
#----------------------------#
files_scanned = 0
suspicious_files = []
deleted_files = 0
user_kept_files = []
skipped_files = []

file_queue = queue.Queue()
mod_requests = queue.Queue()  # Worker -> Moderator
spinner_lock = threading.Lock()
halt_flag = False
scan_halted_by_enter = False
in_prompt = False
spinner_active = True
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
EXCLUDED_EXTENSIONS = ['.mp4', '.avi', '.jpg', '.jpeg', '.png', '.gif', '.txt', '.mp3', '.3gp', '.ogg', '.log', '.m4a', '.m4u', '.prof', '.0']
EXCLUDED_APKS = []
EXCLUDED_FOLDERS = []

CHUNK_SIZE = 8192
MAX_ENTROPY_FILE_SIZE = 50 * 1024 * 1024  # 50 MB max for entropy check

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
    suspicious_keywords = ["temp", "cache", ".nomedia", "thumbnail", "thumbnails"]
    filename = os.path.basename(filepath).lower()
    return any(keyword in filename for keyword in suspicious_keywords)

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

    # Skip excluded APKs (check only the filename, not full path)
    filename = os.path.basename(filepath)
    if filename in EXCLUDED_APKS:
        return False

    # Skip large files (too big for entropy check)
    try:
        size = os.path.getsize(filepath)
        if size > MAX_ENTROPY_FILE_SIZE:
            return False
    except Exception:
        return False

    # Entropy + heuristic check
    try:
        ent = entropy(filepath)
        return ent > 7.65 or heuristic_check(filepath)
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
# Spinner
#----------------------------#
def spinner():
    symbols = "|/-\\"
    idx = 0
    while not halt_flag:
        if not in_prompt:  # pause while moderator is prompting
            line = (f"{GREEN}Scanning... {symbols[idx % len(symbols)]}{RESET} | "
                    f"{GREEN}Files:{files_scanned}{RESET} | "
                    f"{RED}Suspicious:{len(suspicious_files)}{RESET} | "
                    f"{ORANGE}Deleted:{deleted_files}{RESET}")
            sys.stdout.write("\r" + line + " " * 3)  # clear leftover chars
            sys.stdout.flush()
            idx += 1
        time.sleep(0.1)

#----------------------------#
# Scan Worker 
#----------------------------#
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
            # Skip files already whitelisted
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
            print(f"\n{YELLOW}Folder with suspicious file(s) detected: {folder}{RESET}")
            print(f"{YELLOW}Please be patient while the folder is scanned...{RESET}\n")
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
            print(f"[Whitelist] Suspicious folder preview:\n{preview_text}")
            if remaining > 0:
                print(f"...and {remaining} more.")

            while choice not in ('y', 'n', 'stop') and not halt_flag:
                choice = input("Whitelist all files in this folder? (y/n or stop): ").strip().lower()

            if choice == 'y':
                # Only add suspicious files to user_kept_files
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

        for filename in filenames:
            if halt_flag:
                break

            filepath = os.path.join(dirpath, filename)

            # Skip excluded file types
            ext = os.path.splitext(filename)[1].lower()
            if ext in EXCLUDED_EXTENSIONS:
                continue

            # Queue the file for scanning
            file_queue.put(filepath)

#----------------------------#
# Report generation
#----------------------------#
def generate_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    download_path = "/storage/emulated/0/Download"
    os.makedirs(download_path, exist_ok=True)
    report_path = os.path.join(download_path, f"Scan_Report_{timestamp}.txt")
    try:
        with open(report_path, 'w') as f:
            f.write(f"Files scanned: {files_scanned}\n")
            f.write(f"Suspicious: {len(suspicious_files)}\n")
            f.write(f"Deleted: {deleted_files}\n")
            f.write(f"(user kept): {len(user_kept_files)}\n")
            if skipped_files:
                f.write("Skipped files:\n")
                for s in skipped_files:
                    f.write(f"{s}\n")
        # Save whitelist back to file
        with open(WHITELIST_FILE, "a") as w:
            for path in whitelisted_files:
                w.write(path + "\n")
            for folder in whitelisted_folders:
                w.write(folder + "\n")
        return report_path
    except Exception:
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
        sys.stdout.write("\nProcess halted. Please wait while report is generated...\n")
        sys.stdout.flush()
        run_event.set()

#----------------------------#
# Start Scan
#----------------------------#
def start_scan():
    """Kick off walker + worker threads and wait for completion or halt."""
    global halt_flag

    # Load whitelist
    whitelisted = load_whitelist()
    for f in whitelisted["files"]:
        whitelisted_files.add(f)
    for d in whitelisted["folders"]:
        whitelisted_folders.add(d)

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
    root_scan = "/storage/emulated/0"
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            root_scan = "/"
    except Exception:
        pass

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

#----------------------------#
# Main execution
#----------------------------#
if __name__ == "__main__":
    print("#----------------------------#\n"
          "#  Suspicious File Scanner   #\n"
          "#         by jaekid          #\n"
          "#            v0.3            #\n"
          "#----------------------------#")
    print("Press Enter or Ctrl + C at any time to halt scanning.\n")

    spinner_thread = threading.Thread(target=spinner, daemon=True)
    spinner_thread.start()
    enter_thread = threading.Thread(target=enter_listener, daemon=True)
    enter_thread.start()

    try:
        start_scan()
    except KeyboardInterrupt:
        scan_halted_by_enter = True
        halt_flag = True

    # Stop the spinner and ensure the line ends
    spinner_active = False
    spinner_thread.join(timeout=1.0)
    print()  # end spinner line

    print()  # blank line before report message
    if not scan_halted_by_enter:
        print("Scan complete! Generating report...\n")

    # Generate report and show result
    report_file = generate_report()
    print()  # blank line before report file path
    if report_file:
        print(f"Report saved to {report_file}\n")
    else:
        print("Report could not be saved.\n")

    # Final summary
    print(f"{GREEN}Files scanned: {files_scanned}{RESET}, "
          f"{RED}Suspicious: {len(suspicious_files)}{RESET}, "
          f"{ORANGE}Deleted: {deleted_files}{RESET}, "
          f"{YELLOW}(user kept): {len(user_kept_files)}{RESET}\n")
