# HTB Sherlock: [Assistant] — Windows PCA Artifact Forensics Writeup

> **Category:** DFIR / Windows Forensics
> **Platform:** Hack The Box (Sherlocks)
> **Difficulty:** [fill in]
> **Author of challenge:** [fill in]
> **Evidence provided:** `PcaAppLaunchDic.txt`, `PcaGeneralDb0.txt`
> **Skills:** Program Compatibility Assistant (PCA) analysis, timeline reconstruction, temporal proximity analysis

---

## 1. Scenario

An attacker gained unauthorized RDP access to a Windows machine (user profile `cyberjunkie`). Using only two Program Compatibility Assistant (PCA) artifacts, the goal is to reconstruct what the attacker did: install an archive utility, stage a CLI exfiltration tool, collect data, and wipe traces.

---

## 2. Background: What is PCA and why does it matter?

The **Program Compatibility Assistant** is a Windows 11 (22H2+) component that monitors programs for compatibility problems. As a side effect, it keeps plain-text logs in:

```
C:\Windows\appcompat\pca\
```

| File | Content | Forensic value |
|---|---|---|
| `PcaAppLaunchDic.txt` | `full path \| last launch timestamp` | Evidence of execution (GUI launches), keyed by path |
| `PcaGeneralDb0.txt` | Pipe-delimited event records (below) | Install failures, abnormal exits, PCA resolutions |

### `PcaGeneralDb0.txt` record layout

```
Timestamp | RecordType | Path | ProductName | Company | Version | ProgramID | ExitMessage
```

| RecordType | Meaning |
|---|---|
| 0 | Installer failed |
| 1 | Driver blocked |
| 2 | Abnormal process exit |
| 3 | PCA resolve called |

Both files are plain text, so no special parser is needed. The timestamps carry millisecond precision, which is what makes the final task possible.

---

## 3. Analysis and answers

### Task 1: Full path of the downloaded archive utility setup

Search the logs for installers in the user's Downloads folder. `PcaGeneralDb0.txt` contains:

```
2026-04-08 11:30:26.117|2|%USERPROFILE%\Downloads\7z2600-x64.exe|7-zip|igor pavlov|26.00|...|Abnormal process exit with code 0x1
```

`PcaAppLaunchDic.txt` gives the expanded path:

```
C:\Users\cyberjunkie\Downloads\7z2600-x64.exe|2026-04-08 11:30:37.758
```

**Answer:** `C:\Users\cyberjunkie\Downloads\7z2600-x64.exe`

---

### Task 2: When was 7-Zip successfully installed?

The setup has three records at nearly the same moment:

| Time | Type | Message |
|---|---|---|
| 11:30:26.117 | 2 | Abnormal process exit with code 0x1 |
| 11:30:26.150 | 0 | Installer failed |
| 11:30:39.242 | 3 | PCA resolve is called, result: 0 |

The first two are the failure. The type-3 record 13 seconds later is the second, successful run.

**Answer:** `2026-04-08 11:30:39`

---

### Task 3: Command-line exfiltration tool and version

Immediately after 7-Zip, `rclone` appears:

```
...\Downloads\rclone-v1.73.3-windows-amd64\rclone.exe|rclone|https://rclone.org|1.73.3|...
```

rclone is a legitimate cloud-sync CLI, commonly abused for exfiltration to cloud storage.

**Answer:** `rclone v1.73.3`

---

### Task 4: When was the rclone process killed?

rclone is a CLI tool, so double-clicking it opens and closes a console immediately. PCA logs this as an abnormal exit:

```
2026-04-08 11:32:08.187|2|...\rclone.exe|rclone|...|Abnormal process exit with code 0x1
2026-04-08 11:32:08.517|3|...\rclone.exe|rclone|...|PCA resolve is called...
```

**Answer:** `2026-04-08 11:32:08`

---

### Task 5: When did data collection start?

The "limited evidence" is the 7-Zip **File Manager** (`7zFM.exe`), the GUI the attacker would use to build an archive. Its first appearance is in `PcaAppLaunchDic.txt`:

```
C:\Program Files\7-Zip\7zFM.exe|2026-04-08 11:37:07.600
```

This comes about 6 minutes after the install (11:30:39), so the attacker spent that time on other things (rclone attempt, preparation) before collecting.

**Answer:** `2026-04-08 11:37:07`

---

### Task 6: Temporal proximity analysis: how long did data collection take?

Two records exist for `7zFM.exe`:

| Source | Timestamp | Role |
|---|---|---|
| `PcaAppLaunchDic.txt` | `2026-04-08 11:37:07.600` | Start of collection |
| `PcaGeneralDb0.txt` | `2026-04-08 11:40:03.043` | Last recorded 7zFM activity: end of collection |

The answer is the difference between the two, with milliseconds included. The platform format is `***.***`.

```
  11:40:03.043
- 11:37:07.600
= 00:02:55.443  →  120 + 55.443 = 175.443 s
```

Alternative calculation:

```
Start: 37*60 + 7.600  = 2227.600
End:   40*60 + 3.043  = 2403.043
Diff:  2403.043 - 2227.600 = 175.443
```

PowerShell:

```powershell
([datetime]"2026-04-08 11:40:03.043" - [datetime]"2026-04-08 11:37:07.600").TotalSeconds
```

Python:

```python
from datetime import datetime
f = "%Y-%m-%d %H:%M:%S.%f"
d = datetime.strptime("2026-04-08 11:40:03.043", f) - datetime.strptime("2026-04-08 11:37:07.600", f)
print(d.total_seconds())  # 175.443
```

**Answer:** `175.443`

> **Note on reasoning:** This is a *proxy* measurement. PCA does not log "archive finished"; it logs when it evaluated the process. The first `7zFM.exe` record and the last one therefore bracket the collection window as tightly as the available evidence allows. Other readings of the question were tested and rejected by the platform, including 13.785 (gap from the last 7zFM record to the terminal launch) and 189.228 (gap from collection start to the terminal launch).

---

### Task 7: Utility used to permanently delete traces

Right after the collection window, Windows Terminal launches:

```
C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.23.20211.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe|2026-04-08 11:40:16.828
```

This is most likely where rclone was run from the command line. The Eraser installer and application follow:

```
C:\Users\cyberjunkie\Downloads\Eraser 6.2.0.2996.exe|2026-04-08 11:42:11.726
C:\Program Files\Eraser\Eraser.exe|2026-04-08 11:43:38.671
```

Eraser is a secure file-deletion tool that overwrites data to defeat recovery, which is consistent with anti-forensics.

**Answer:** `C:\Program Files\Eraser\Eraser.exe`

---

## 4. Reconstructed timeline (2026-04-08)

| Time | Event | Source |
|---|---|---|
| 11:30:26 | `7z2600-x64.exe` fails (exit 0x1, installer failed) | GeneralDb |
| 11:30:37 | Setup launched again | AppLaunchDic |
| 11:30:39 | 7-Zip installed successfully | GeneralDb |
| 11:32:00 | `rclone.exe` launched via GUI | AppLaunchDic |
| 11:32:08 | rclone exits abnormally (0x1), killed | GeneralDb |
| 11:37:07 | `7zFM.exe` launched: **collection starts** | AppLaunchDic |
| 11:40:03 | Last `7zFM.exe` record: **collection ends** | GeneralDb |
| 11:40:16 | Windows Terminal launched: likely rclone exfiltration | AppLaunchDic |
| 11:42:11 | Eraser installer run | AppLaunchDic |
| 11:43:38 | `Eraser.exe` launched: trace destruction | AppLaunchDic |

**Attack chain:** RDP access → tooling (7-Zip, rclone) → data staging → exfiltration → anti-forensics.

---

## 5. Other observations and caveats

- `PcaAppLaunchDic.txt` is keyed by path, so it generally keeps only the **latest** launch time per executable. Earlier launches can be overwritten, which is why timestamps from both files are cross-referenced.
- `WindowsTerminal.exe` (1.23.20211.0) appears twice in `PcaAppLaunchDic.txt` (10:12:30 and 11:40:16). The 10:12 entry predates the 7-Zip install, so it is not part of the exfiltration window.
- `gkape.exe` (KAPE) appears on 2026-03-04 and again at 12:00:25 on 2026-04-08 from the Desktop. This is probably the investigator's triage collection rather than attacker activity, but the logs alone cannot confirm that.
- PCA proves that a program was **launched** or **evaluated**. It does not prove what was archived, where it was sent, or what rclone commands were run. Corroborate with PowerShell/console history, Prefetch, ShimCache/Amcache, firewall and proxy logs, and RDP event logs (4624 type 10, 1149).

## 6. Indicators of compromise

| Type | Value |
|---|---|
| Account | `cyberjunkie` |
| File | `C:\Users\cyberjunkie\Downloads\7z2600-x64.exe` |
| File | `C:\Users\cyberjunkie\Downloads\rclone-v1.73.3-windows-amd64\rclone.exe` |
| File | `C:\Users\cyberjunkie\Downloads\Eraser 6.2.0.2996.exe` |
| File | `C:\Program Files\Eraser\Eraser.exe` |

## 7. MITRE ATT&CK mapping

| Technique | ID |
|---|---|
| Remote Services: RDP | T1021.001 |
| Ingress Tool Transfer | T1105 |
| Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration to Cloud Storage | T1567.002 |
| Indicator Removal: File Deletion | T1070.004 |

## 8. Takeaways

1. PCA artifacts are small, easy to parse, and often overlooked.
2. Failed installers and abnormal exits are useful evidence in themselves.
3. Combining two artifact sources in a temporal proximity analysis recovers behaviour that neither source shows alone.
4. Anti-forensic tooling such as Eraser leaves its own execution trail.

---

*References: Windows 11 PCA artifact research (Andrea Fortuna, Aleksandar Milenkoski), HTB Sherlocks documentation.*

Medium reference: https://medium.com/@navanath/assistant-htb-write-up-ad5392dd23c6
