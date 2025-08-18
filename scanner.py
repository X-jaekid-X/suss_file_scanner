import os
import sys
import threading
import time
import math
import hashlib
import datetime
import queue
import select

#----------------------------#
#  Suspicious File Scanner   #
#         by jaekid   v0.2a  #
#----------------------------#

# GLOBALS
halt_flag = False                    # master stop flag checked by all threads
scan_halted_by_enter = False         # set only when Enter is pressed during scanning (not in prompt)
in_prompt = False                    # True only while waiting for y/n/stop
files_scanned = 0
suspicious_files = []
user_kept_files = []
scanned_hashes = set()               # (sha256, size) cross-reference

counter_lock = threading.Lock()
spinner_lock = threading.Lock()
whitelist_lock = threading.Lock()
hash_lock = threading.Lock()

spinner_chars = ['|', '/', '-', '\\']
spinner_active = True

file_queue = queue.Queue(maxsize=2048)    # work queue for workers
worker_threads = []

# NEW: moderator queue + run gate
mod_requests = queue.Queue()              # workers -> moderator (filepath, response_queue)
run_event = threading.Event()             # when set, workers may process; when cleared, they pause
run_event.set()                           # start in "running" mode

# EXCLUSIONS
EXCLUDED_EXTENSIONS = [
    '.mp3', '.m4a', '.mp4', '.ogg', '.3gp', '.mpeg', '.mpg', '.txt',
    '.jpg', '.jpeg', '.png', '.log', '.0', '.exo', '.lic', '.prof', '.pb', '.ldb'
]
EXCLUDED_APKS = [
    # keep empty unless you want hard-coded APK path skips
]
EXCLUDED_FOLDERS = [
    "cache",
    "Cache",
    "CACHE",
    "CacheStorage",
    "__pycache__",
    "location_based_model_table",
    "GrShaderCache",
    "app_commerce_acquire_cache",
    "app_image_scoped"
]

# MEMORY-SAFE CHUNK SIZE
CHUNK_SIZE = 8192                      # 8 KB
MAX_ENTROPY_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

def spinner():
    """Single-line spinner that runs while scanning (paused during prompts)."""
    idx = 0
    while not halt_flag:
        if spinner_active and not in_prompt:
            with spinner_lock:
                sys.stdout.write(
                    f"\rScanning... {spinner_chars[idx % len(spinner_chars)]} | "
                    f"Files: {files_scanned} | Suspicious: {len(suspicious_files)}"
                )
                sys.stdout.flush()
                idx += 1
        time.sleep(0.1)

def enter_listener():
    """
    Listens for a blank line (Enter key) ONLY while scanning (not in a prompt).
    Uses non-blocking select on stdin so it never interferes with the prompt.
    """
    global halt_flag, scan_halted_by_enter
    if not sys.stdin or not sys.stdin.isatty():
        return
    while not halt_flag:
        # Only react to Enter when spinner is active AND we are not in a prompt
        if spinner_active and not in_prompt:
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if r:
                line = sys.stdin.readline()
                if line.strip() == "":
                    scan_halted_by_enter = True
                    halt_flag = True
                    # NEW: print the halt message immediately
                    sys.stdout.write("\nProcess halted. Please wait while report is generated...\n")
                    sys.stdout.flush()
                    # also release any waiting workers promptly
                    run_event.set()
                    break
        else:
            time.sleep(0.05)

# ENTROPY CALCULATION (memory-safe)
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

# HEURISTIC CHECK
def heuristic_check(filepath):
    suspicious_keywords = ["temp", "cache", ".nomedia", "thumbnail", "thumbnails"]
    filename = os.path.basename(filepath).lower()
    return any(keyword in filename for keyword in suspicious_keywords)

# TWO-RULE CHECK
def is_suspicious(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in EXCLUDED_EXTENSIONS:
        return False
    if filepath in EXCLUDED_APKS:
        return False
    try:
        size = os.path.getsize(filepath)
        if size > MAX_ENTROPY_FILE_SIZE:
            return False  # skip huge files for entropy
    except Exception:
        pass
    ent = entropy(filepath)
    if ent > 7.65 or heuristic_check(filepath):
        return True
    return False

# SHA-256 HASH (memory-safe)
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

# LOAD WHITELIST
def load_whitelist():
    download_path = "/storage/emulated/0/Download"
    whitelist_path = os.path.join(download_path, "Whitelist.txt")
    whitelisted = set()
    try:
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                for line in f:
                    path = line.strip()
                    if path:
                        whitelisted.add(path)
    except Exception:
        pass
    return whitelisted

def walker(start_dir, whitelisted_files):
    """
    Producer: walks directories and enqueues file paths.
    Stops early if halt_flag is set.
    """
    try:
        for root, dirs, files in os.walk(start_dir, topdown=True):
            if halt_flag:
                break
            # Skip excluded folders (recursive strict name match)
            dirs[:] = [d for d in dirs if d not in EXCLUDED_FOLDERS]
            for name in files:
                if halt_flag:
                    break
                filepath = os.path.join(root, name)
                # Skip whitelisted files
                if filepath in whitelisted_files:
                    continue
                try:
                    file_queue.put(filepath, timeout=0.1)
                except queue.Full:
                    if halt_flag:
                        break
                    file_queue.put(filepath)
    except Exception:
        pass
    finally:
        # Signal workers to finish
        for _ in range(len(worker_threads)):
            file_queue.put(None)

def worker(whitelisted_files):
    """Consumer: processes paths from the queue."""
    global files_scanned, halt_flag
    while not halt_flag:
        # Obey global run gate (paused during moderator prompt)
        if not run_event.wait(timeout=0.1):
            continue
        try:
            item = file_queue.get(timeout=0.2)
        except queue.Empty:
            if halt_flag:
                break
            else:
                continue

        if item is None:
            file_queue.task_done()
            break

        filepath = item

        # SHA + size cross-reference (thread-safe)
        try:
            size = os.path.getsize(filepath)
            sha = sha256_file(filepath)
            if sha:
                with hash_lock:
                    if (sha, size) in scanned_hashes:
                        file_queue.task_done()
                        continue
                    scanned_hashes.add((sha, size))
        except Exception:
            file_queue.task_done()
            continue

        # Count file
        with counter_lock:
            files_scanned += 1

        # Decide suspicious
        try:
            if is_suspicious(filepath):
                # Hand off to moderator: don't prompt here
                resp_q = queue.Queue(maxsize=1)
                try:
                    mod_requests.put((filepath, resp_q), timeout=0.5)
                except queue.Full:
                    # If moderator queue unexpectedly full, treat as 'n' to avoid blocking workers forever
                    suspicious_files.append(filepath)
                    file_queue.task_done()
                    continue

                # Wait for moderator decision
                try:
                    decision = resp_q.get()  # block until moderator answers
                except Exception:
                    decision = 'n'

                if decision == 'y':  # whitelist
                    user_kept_files.append(filepath)
                    whitelisted_files.add(filepath)  # in-memory
                elif decision == 'stop':
                    halt_flag = True
                else:  # 'n' or anything else
                    suspicious_files.append(filepath)
        except Exception:
            pass
        finally:
            file_queue.task_done()

def spinner_pause(pause: bool):
    """Pause/resume spinner safely to not overwrite prompts."""
    global spinner_active
    if pause:
        spinner_active = False
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        spinner_active = True

def moderator():
    """
    Centralizes ALL prompts so only one question appears at a time.
    Pauses workers & spinner during prompt; resumes afterwards.
    """
    global in_prompt, halt_flag, scan_halted_by_enter
    while not halt_flag:
        try:
            item = mod_requests.get(timeout=0.1)
        except queue.Empty:
            # If scan ended and no pending prompts, exit
            if halt_flag:
                break
            continue

        if item is None:
            mod_requests.task_done()
            break

        filepath, resp_q = item

        # Pause scanning before prompting
        run_event.clear()           # pause workers
        spinner_pause(True)         # stop spinner
        in_prompt = True

        # Print question and get answer
        print(f"\n[Whitelist] Suspicious file: {filepath}")
        choice = None
        while choice not in ('y', 'n', 'stop'):
            try:
                choice = input("Whitelist this file? (y/n or type 'stop' to halt scan): ").strip().lower()
            except EOFError:
                choice = 'n'
            if choice not in ('y', 'n', 'stop'):
                print("Please enter y, n, or stop.")

        # Deliver decision back to the waiting worker
        try:
            resp_q.put_nowait(choice)
        except Exception:
            pass

        # Resume scanning unless user asked to stop
        if choice == 'stop':
            scan_halted_by_enter = True
            halt_flag = True

        in_prompt = False
        spinner_pause(False)  # resume spinner
        run_event.set()       # resume workers

        mod_requests.task_done()

# REPORT
def generate_report():
    try:
        download_path = "/storage/emulated/0/Download"
        if not os.path.exists(download_path):
            os.makedirs(download_path, exist_ok=True)
        # timestamped report filename
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"Scan_Report_{timestamp}.txt"
        report_path = os.path.join(download_path, report_filename)

        with open(report_path, 'w') as f:
            f.write(f"Files scanned: {files_scanned}\n")
            f.write(f"Suspicious found: {len(suspicious_files)}\n")
            f.write(f"User kept (whitelisted): {len(user_kept_files)}\n\n")
            f.write("Suspicious files:\n")
            for file in suspicious_files:
                f.write(file + "\n")
            f.write("\nUser kept files:\n")
            for file in user_kept_files:
                f.write(file + "\n")

        # Append new whitelist entries persistently
        whitelist_path = os.path.join(download_path, "Whitelist.txt")
        if user_kept_files:
            with open(whitelist_path, 'a') as f:
                for file in user_kept_files:
                    f.write(file + "\n")

        return report_path
    except Exception:
        return None

def start_scan():
    """Kick off walker + worker threads and wait for completion or halt."""
    whitelisted = load_whitelist()

    # Start moderator thread first
    mod_thread = threading.Thread(target=moderator, daemon=True)
    mod_thread.start()

    # Start worker threads
    num_workers = max(2, (os.cpu_count() or 4) // 2)
    for _ in range(num_workers):
        t = threading.Thread(target=worker, args=(whitelisted,), daemon=True)
        worker_threads.append(t)
        t.start()

    # Start walker (producer)
    root_scan = "/storage/emulated/0"
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            root_scan = "/"
    except Exception:
        pass

    w = threading.Thread(target=walker, args=(root_scan, whitelisted), daemon=True)
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

    # Tell moderator no more prompts (if any pending, they'll be handled)
    mod_requests.put(None)

if __name__ == "__main__":
    print("#----------------------------#\n"
          "#  Suspicious File Scanner   #\n"
          "#         by jaekid          #\n"
          "#            v0.2a           #\n"
          "#----------------------------#")
    print("Press Enter or Ctrl + C at any time to halt scanning.")

    # Spinner
    spinner_thread = threading.Thread(target=spinner, daemon=True)
    spinner_thread.start()

    # Enter key listener (does not interfere with prompts)
    enter_thread = threading.Thread(target=enter_listener, daemon=True)
    enter_thread.start()

    # Run scan
    try:
        start_scan()
    except KeyboardInterrupt:
        # Fallback halt via Ctrl+C
        scan_halted_by_enter = True
        halt_flag = True

    # Stop spinner and finish
    halt_flag = True
    spinner_active = False
    spinner_thread.join(timeout=1.0)

    # Final messaging + report
    if scan_halted_by_enter:
        # (Message already printed immediately on Enter; keep final status line behavior)
        pass
    else:
        print("\nScan complete! Generating report...")

    report_file = generate_report()
    if report_file:
        print(f"Report saved to {report_file}")
    else:
        print("Report could not be saved.")

    print(f"Files scanned: {files_scanned}, Suspicious found: {len(suspicious_files)}, (user kept): {len(user_kept_files)}")