****Suspicious File Scanner****

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
