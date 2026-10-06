"""Builds data/events.jsonl: labelled synthetic process-creation events.

Each event has a split. 'dev' events are visible to the agents while they write and
fix rules. 'holdout' events are only used for the final evaluation, so we can see
whether a rule generalises or was fitted to the dev examples.
"""
import json
import random
from pathlib import Path

random.seed(7)
OUT = Path(__file__).parent / "events.jsonl"
SYS = r"C:\Windows\System32"

# (technique, image, command line, parent, label, split)
E = []


def add(tech, image, cmd, label, split, parent=r"C:\Windows\explorer.exe"):
    E.append((tech, image, cmd, parent, label, split))


# T1059.001 PowerShell encoded commands (already covered by an existing rule)
P = SYS + r"\WindowsPowerShell\v1.0\powershell.exe"
add("T1059.001", P, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A", "malicious", "dev")
add("T1059.001", P, "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=", "malicious", "dev")
add("T1059.001", P, "powershell.exe -NoProfile -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=", "malicious", "holdout")

# T1003.001 LSASS credential dumping (existing rule only knows mimikatz)
add("T1003.001", r"C:\Tools\mimikatz.exe", 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', "malicious", "dev")
add("T1003.001", r"C:\Tools\mimikatz.exe", 'mimikatz.exe "sekurlsa::logonpasswords" exit', "malicious", "dev")
add("T1003.001", r"C:\Tools\procdump.exe", r"procdump.exe -accepteula -ma lsass.exe C:\Temp\l.dmp", "malicious", "dev")
add("T1003.001", r"C:\Tools\procdump64.exe", r"procdump64.exe -ma lsass.exe out.dmp", "malicious", "dev")
add("T1003.001", SYS + r"\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 612 C:\Temp\l.dmp full", "malicious", "dev")
add("T1003.001", SYS + r"\rundll32.exe", r"rundll32.exe comsvcs.dll MiniDump 704 C:\Users\Public\x.dmp full", "malicious", "dev")
add("T1003.001", r"C:\Tools\mimikatz.exe", "mimikatz.exe sekurlsa::logonpasswords full", "malicious", "holdout")
add("T1003.001", r"C:\Tools\procdump.exe", r"procdump.exe -ma lsass.exe d.dmp", "malicious", "holdout")
add("T1003.001", SYS + r"\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 888 C:\Windows\Temp\z.dmp full", "malicious", "holdout")
add("", SYS + r"\tasklist.exe", 'tasklist /fi "imagename eq lsass.exe"', "benign", "dev")
add("", r"C:\Tools\procdump.exe", r"procdump.exe -ma notepad.exe n.dmp", "benign", "dev")
add("", SYS + r"\tasklist.exe", r"tasklist /svc | findstr lsass", "benign", "holdout")
add("", SYS + r"\wbem\WMIC.exe", 'wmic process where name="lsass.exe" get processid', "benign", "holdout")

# T1053.005 Scheduled task persistence (no existing rule)
S = SYS + r"\schtasks.exe"
add("T1053.005", S, r'schtasks /create /sc onlogon /tn "Updater" /tr C:\Users\Public\x.exe', "malicious", "dev")
add("T1053.005", S, r'schtasks /create /sc minute /mo 1 /tn "Sync" /tr "powershell -w hidden -enc SQBFAFgA"', "malicious", "dev")
add("T1053.005", S, r'schtasks /create /tn "Cache" /tr C:\Windows\Temp\a.exe /sc hourly /ru system', "malicious", "dev")
add("T1053.005", S, r'schtasks /create /sc onstart /tn "WinUpd" /tr "C:\Users\bob\AppData\Roaming\u.exe"', "malicious", "dev")
add("T1053.005", S, r"schtasks /create /sc onlogon /tn Helper /tr C:\ProgramData\h.exe /ru system", "malicious", "holdout")
add("T1053.005", S, r"schtasks /create /tn X /tr C:\Users\Public\y.bat /sc minute", "malicious", "holdout")
add("", S, "schtasks /query /fo LIST", "benign", "dev")
add("", S, r'schtasks /create /tn "BackupNightly" /tr "C:\Program Files\Backup\run.exe" /sc daily /st 02:00', "benign", "dev")
add("", S, 'schtasks /run /tn "BackupNightly"', "benign", "dev")
add("", S, "schtasks /query /tn Backup", "benign", "holdout")
add("", S, r'schtasks /create /tn "PatchTuesday" /tr "C:\Program Files\Patch\p.exe" /sc weekly', "benign", "holdout")

# T1070.001 Clearing Windows event logs (no existing rule)
W = SYS + r"\wevtutil.exe"
add("T1070.001", W, "wevtutil.exe cl Security", "malicious", "dev")
add("T1070.001", W, "wevtutil cl System", "malicious", "dev")
add("T1070.001", W, "wevtutil.exe clear-log Application", "malicious", "dev")
add("T1070.001", W, "wevtutil cl Application", "malicious", "holdout")
add("T1070.001", W, "wevtutil.exe clear-log Security", "malicious", "holdout")
add("", W, "wevtutil qe System /c:5 /f:text", "benign", "dev")
add("", W, "wevtutil gl Security", "benign", "dev")
add("", W, r"wevtutil epl Security C:\Backup\sec.evtx", "benign", "holdout")

# T1218.011 Rundll32 proxy execution (no existing rule)
R = SYS + r"\rundll32.exe"
add("T1218.011", R, r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write()', "malicious", "dev")
add("T1218.011", R, r"rundll32.exe C:\Users\Public\evil.dll,Start", "malicious", "dev")
add("T1218.011", R, r"rundll32.exe C:\Windows\Temp\a.dll,DllMain", "malicious", "dev")
add("T1218.011", R, r"rundll32.exe C:\ProgramData\b.dll,Run", "malicious", "holdout")
add("T1218.011", R, r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)', "malicious", "holdout")
add("", R, r"rundll32.exe printui.dll,PrintUIEntry /il", "benign", "dev")
add("", R, "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", "benign", "dev")
add("", R, "rundll32.exe user32.dll,LockWorkStation", "benign", "dev")
add("", R, "rundll32.exe shell32.dll,Control_RunDLL main.cpl", "benign", "holdout")
add("", R, "rundll32.exe url.dll,FileProtocolHandler https://example.com", "benign", "holdout")

# Background noise
NOISE = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer --lang=en-US"),
    (SYS + r"\svchost.exe", "svchost.exe -k netsvcs -p"),
    (SYS + r"\notepad.exe", "notepad.exe C:\\Users\\{u}\\notes.txt"),
    (SYS + r"\cmd.exe", "cmd.exe /c dir C:\\Users\\{u}"),
    (P, "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1"),
    (P, "powershell.exe Get-Process | Sort-Object CPU"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE /n report.docx"),
]
for i in range(40):
    img, cmd = random.choice(NOISE)
    add("", img, cmd.format(u=random.choice(["alice", "bob", "carol"])), "benign", "dev" if i % 3 else "holdout")

events = []
for i, (t, img, cmd, parent, label, split) in enumerate(E):
    events.append({
        "id": i, "host": f"WS-{random.randint(1, 20):02d}", "User": random.choice(["alice", "bob", "carol", "SYSTEM"]),
        "Image": img, "CommandLine": cmd, "ParentImage": parent,
        "label": label, "technique": t, "split": split,
    })
random.shuffle(events)
OUT.write_text("\n".join(json.dumps(e) for e in events) + "\n")
print(f"wrote {len(events)} events to {OUT}")
