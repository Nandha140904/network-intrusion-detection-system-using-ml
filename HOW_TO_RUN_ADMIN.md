# How to Run with Administrator Privileges

Real-time packet capture requires Administrator (root) privileges to access the network interface directly.

## Python Scripts (Real-time Analysis)

### 1. Open Administrator Command Prompt
1. Press `Windows Key`
2. Type `cmd` or `PowerShell`
3. Right-click on "Command Prompt" or "PowerShell"
4. Select **"Run as administrator"**
5. Click "Yes" on the UAC prompt

### 2. Navigate to Project Directory
```cmd
cd "c:\Users\nandh\New folder (2)"
```

### 3. Run the Script
```cmd
python run_realtime.py
```
OR
```cmd
python app.py
```
(app.py will try to capture packets when you click "Start Monitoring" in the dashboard)

---

## Offline Analysis (No Admin Required)

Analyzing saved datasets does NOT require admin privileges.

```cmd
python analyze_offline.py --dataset data/KDDTest+.txt
```
