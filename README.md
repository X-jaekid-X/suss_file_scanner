****Suspicious File Scanner****

This script will scan your device's files for any files that have high entropy or fail a heuristic check.  When a suspicious file is found, you will be prompted to either whitelist or delete it.  You will need to customize EXCLUDED_EXTENSIONS, EXCLUDED_APKS, and EXCLUDED_FOLDERS to leave out anything you do not want included in a scan.  The whitelist and report are saved into the Downloads folder.  This is developed for Android.

WARNING: This script allows you to delete potentially critical files. USE AT YOUR OWN RISK. I am NOT RESPONSIBLE for any bricked devices or devices rendered unusable by using this software.

1) Save scanner.py into Download folder.
2) Install Termux
3) Run:

~ $ termux-setup-storage

4) Install Python via Termux if not already installed by running the following command:

~ $ pkg install python-pip

5) Run the following commands in Termux:

~ $ cp ~/storage/shared/Download/scanner.py ~/

~ $ chmod +x ~/scanner.py

~ $ python3 scanner.py

6) One line to run as root:

su -c "/data/data/com.termux/files/usr/bin/python3 /data/data/com.termux/files/home/scanner.py"


****v 0.3 Changelog****

1. Added colors
2. Added ability to delete suspicious files.
3. Added queue to capture skipped files and scan at the end of the process when Moderator queue becomes full.
4. Added bulk whitelisting/deleting of files in folders with more than 5+ files including preview of suspicious files.
5. Can exclude files such as "com.android.maps" within file paths via EXCLUDED_APKS.


****v 0.4 Changelog****

1) Added scanning profiles (quick or thorough)
2) Adjusts output size based on terminal screen width
3) Added progress bar and percentage
4) Added ELF and MZ malware signature detection
5) Added file estimator
6) Fixed spacing

****v 0.5 Changelog****

1) Fixed spinner
2) Added clear screen on launch
3) Added logo
