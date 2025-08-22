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

## NOTE

Before I begin, the queries used and the answers are for the original logs, so there might be some differences in answers, especially when it comes to time. I had to find the new logs as well to create screenshots, because I only focused on completing the hunt when it came out that first day.


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

<img width="800" src="https://github.com/user-attachments/assets/626eb342-4e88-4a56-a848-5a65a189910d"/>

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

🧠 **Thought process:** The query is still the same, because it gives all the information needed to provide the answer for the 1st, 2nd, and 3rd flag.


**Answer: "powershell.exe" net localgroup Administrators**

---

## 🟩 Flag 4 – Active Session Discovery

**Objective:**

Reveal which sessions are currently active for potential masking.

**What to Hunt:**

Might be session-enumeration commands.

**Thought:**

By riding along existing sessions, attackers can blend in and avoid spawning suspicious user contexts.


 🕵️ **Provide the value of the program tied to this activity**

Query used:
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ProcessCommandLine, FileName, SHA256,InitiatingProcessFileName, AccountName, ProcessCreationTime
```


🧠 **Thought process:** The query stays the same. This time around, I was getting a little lost, but then I googled what qwinsta means from the previous results, and I found the answer to flag 4.

**Answer: qwinsta.exe**

---

## 🟩 Flag 5 – Defender Configuration Recon

**Objective:**

Expose tampering or inspection of AV defenses, disguised under HR activity.

**What to Hunt:**

Can be PowerShell related activity.

**Thought:**

Disabling protection under the guise of internal tooling is a hallmark of insider abuse.

**Side Note: 1/6**

union

 🕵️ **What was the command value used to execute?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ProcessCommandLine, FileName, SHA256,InitiatingProcessFileName, AccountName, ProcessCreationTime
```

🧠 **Thought process:** Query will stay the same. I spotted this command upon reviewing the logs in flag 1 already.

**Answer: ""powershell.exe" -Command "Set-MpPreference -DisableRealtimeMonitoring $true"**

---

## 🟩 Flag 6 – Defender Policy Modification

**Objective:**

Validate if core system protection settings were modified.

**What to Hunt:**

Policy or configuration changes that affect baseline defensive posture.

**Thought:**

Turning down the shield is always a red flag.

 🕵️ **Provide the name of the registry value**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "nathan-iel-vm"
| where ActionType == "RegistryValueSet"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
```

🧠 **Thought process:** The question itself asked for the registry value, so I immediately went looking into modified registry values and ordering them by registry value name. I then came across the answer.

<img width="800" src="https://github.com/user-attachments/assets/1d759b75-6108-46cc-8890-d87aa87b09f2"/>

**Answer: DisableAntiSpyware**

---

## 🟩 Flag 7 – Access to Credential-Rich Memory Space

**Objective:**

Identify if the attacker dumped memory content from a sensitive process.

**What to Hunt:**

Uncommon use of system utilities interacting with protected memory.

**Thought:**

The path to credentials often runs through memory — if you can reach it, you own it.

**Side Note: 2/6**
(DeviceFileEvents | where FileName =~ "ConsoleHost_history.txt" and ActionType == "FileDeleted")


 🕵️ **What was the HR related file name associated with this tactic?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName in~ ("rundll32.exe","procdump.exe","procdump64.exe","werfault.exe")
| where ProcessCommandLine has_any ("lsass","comsvcs.dll","MiniDump")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

🧠 **Thought process:** The query was made with the help of chat gpt, because I wasn't sure which processes create dumps, but after seeing the results, I could have just as well used the query from the first 5 flags, because the answer was also there.

<img width="900" src="https://github.com/user-attachments/assets/e5dd2028-8251-4fac-ad9b-1b67e5052518"/>

**Answer: HRConfig.json**

---

## 🟩 Flag 8 – File Inspection of Dumped Artifacts

**Objective:**

Detect whether memory dump contents were reviewed post-collection.

**What to Hunt:**

Signs of local tools accessing sensitive or unusually named files.

**Thought:**

Dumping isn’t the end — verification is essential.

**Hint:**

1. Utilize previous findings

 🕵️ **Provide the value of the associated command**

Query used:

```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine has "HRConfig.json"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

🧠 **Thought process:** I looked for the file that was dumped with the above query, but it could also have been seen with the same query as the first 5 flags, which is where I actually took the screenshot.

<img width="900" src="https://github.com/user-attachments/assets/34d36a4a-ea80-4483-9c1e-159369581b29"/>

**Answer: "notepad.exe" C:\HRTools\HRConfig.json**

---

## 🟩 Flag 9 – Outbound Communication Test

**Objective:**

Catch network activity establishing contact outside the environment.

**What to Hunt:**

Lightweight outbound requests to uncommon destinations.

**Thought:**

Before exfiltration, there’s always a ping — even if it’s disguised as routine.

**Side Note: 3/6**

(DeviceFileEvents | where FileName =~ "EmptySysmonConfig.xml")

 🕵️ **What was the TLD of the unusual outbound connection?**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "nathan-iel-vm"
| distinct RemoteUrl
```

🧠 **Thought process:** I looked for unique remote URLs and found the pipedream.net, which is known for data exfil.

<img width="600" src="https://github.com/user-attachments/assets/5e96688d-33d4-456c-88e0-b79b938bd0c5"/>

**Answer: .net**

---

## 🟩 Flag 10 – Covert Data Transfer

**Objective:**

Uncover evidence of internal data leaving the environment.

**What to Hunt:**

Activity that hints at transformation or movement of local HR data.

**Thought:**

Staging the data is quiet. Sending it out makes noise — if you know where to listen.

 🕵️ **Identify the ping of the last unusual outbound connection attempt**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "nathan-iel-vm"
| where RemoteUrl endswith ".net" or RemoteUrl contains ".net"
| order by Timestamp desc
```

🧠 **Thought process:** I wasn't sure what I was looking for. Am I looking for the time of the last ping that was made to an external URL? Was it the last connection? But in the end, it was the IP address of the pipedream website which is now different due to new logs. I'm assuming it might be 3.234.58.20.

**Answer: 52.54.13.125**

---

## 🟩 Flag 11 – Persistence via Local Scripting

**Objective:**

Verify if unauthorized persistence was established via legacy tooling.

**What to Hunt:**

Use of startup configurations tied to non-standard executables.

**Thought:**

A quiet script in the right location can make a backdoor look like a business tool.

**Side Note: 4/6**

(DeviceProcessEvents | where FileName =~ "Sysmon64.exe" and ProcessCommandLine has "-c")

 🕵️ **Provide the file name tied to the registry value**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "nathan-iel-vm"
| where ActionType == "RegistryValueSet"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
```

🧠 **Thought process:** I used the same query as for flag 6 and ordered the logs by registry value name again. That is where I saw the HRToolTracker and the registry value data which has the name of the file.

<img width="900" src="https://github.com/user-attachments/assets/dceb3328-7555-435f-9528-c3b9a4876a2b"/>

**Answer: OnboardTracker.ps1**

---

## 🟩 Flag 12 – Targeted File Reuse / Access

**Objective:**

Surface the document that stood out in the attack sequence.

**What to Hunt:**

Repeated or anomalous access to personnel files.

**Thought:**

The file that draws the most interest often holds the motive.

**Format:**

Abcd Efgh

 🕵️ **What is the name of the personnel file that was repeatedly accessed?**

Query used:

```
DeviceEvents
| where DeviceName == "nathan-iel-vm"
| where FileName != ""
```

🧠 **Thought process:** The query doesn't seem like much but the empty fields in the FileName column helped a lot, so when I order by File name I could see that the file of Carlos Tanaka was accessed the most.

<img width="800" src="https://github.com/user-attachments/assets/e1efafef-83ea-4315-a2f7-ca036d7b9bcc"/>

**Answer: Carlos Tanaka**

---

## 🟩 Flag 13 – Candidate List Manipulation

**Objective:**

Trace tampering with promotion-related data.

**What to Hunt:**

Unexpected modifications to structured HR records.

**Thought:**

Whether tampering or staging — file changes precede extraction.

**Hint:**

1. Utilize previous findings
2. File is duplicated in other folder(s)

**Side Note: 5/6**

(DeviceRegistryEvents | where RegistryKey has @"SOFTWARE\CorpHRChaos")

 🕵️ **Identify the first instance where the file in question is modified and drop the corresponding SHA1 value of it**

Query used:

```
DeviceFileEvents
| where DeviceName == "nathan-iel-vm"
| where FileName =~ "PromotionCandidates.csv"
| where ActionType == "FileModified"
```

🧠 **Thought process:** According to the previous findings and the promotion-related data I immediately assumed it was the Hash of the promotionCandidates.csv, which ended up being the correct assumption

**Answer: SHA1 = 65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34**

---

## 🟩 Flag 14 – D Audit Trail Disruption

**Objective:**

Detect attempts to impair system forensics.

**What to Hunt:**

Operations aimed at removing historical system activity.

**Thought:**

The first thing to go when a crime’s committed? The cameras.

**Hint:**

1. "ab"

 🕵️ **Identify when the first attempt at clearing the trail was done**

Query used:

```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName in~ ("wevtutil.exe","powershell.exe")
| where ProcessCommandLine has_any ("wevtutil", "wevtutil.exe cl", "Clear-EventLog", "Remove-EventLog")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

🧠 **Thought process:** I saw all the logs from my previous findings, so I narrowed it down to wevutil.exe cl and some others that AI helped with just in case I missed some. The right answer was indeed the command "wevtutil.exe" cl Security, well the specific time, depending on the new or old logs.

<img width="600" src="https://github.com/user-attachments/assets/c8faa800-1b77-4600-af6d-c292b95d846e"/>

**Answer: 2025-07-19T05:38:55.6800388Z**

---

## 🟩 Flag 15 – Final Cleanup and Exit Prep

**Objective:**

Capture the combination of anti-forensics actions signaling attacker exit.

**What to Hunt:**

Artifact deletions, security tool misconfigurations, and trace removals.

**Thought:**

Every digital intruder knows — clean up before you leave or you’re already caught.

**Side Note: 6/6**

| sort by Timestamp desc


 🕵️ **Identify when the last associated attempt occurred**

Query used:

```
let device = "nathan-iel-vm";

// Processes that clear traces
let ProcAF =
DeviceProcessEvents
| where DeviceName == device
| where
  (FileName =~ "wevtutil.exe" and ProcessCommandLine has " cl ") or
  (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
      "Remove-Item",
      "Clear-EventLog",
      "ConsoleHost_history.txt",
      @"\Recent", @"\Prefetch",
      @"Windows Defender\\Scans\\History",
      @"HKLM:\\SOFTWARE\\CorpHRChaos"
  )) or
  (FileName =~ "Sysmon64.exe" and ProcessCommandLine has " -c")
| project Timestamp, Source="Proc", FileName, ProcessCommandLine;

// File artifacts (PS history, Defender history, empty Sysmon cfg)
let FileAF =
DeviceFileEvents
| where DeviceName == device
| where (FileName =~ "ConsoleHost_history.txt" and ActionType == "FileDeleted")
   or (tostring(FolderPath) has @"\Windows Defender\Scans\History" and ActionType == "FileDeleted")
   or (FileName =~ "EmptySysmonConfig.xml" and ActionType in ("FileCreated","FileModified"))
| project Timestamp, Source="File", FileName, FolderPath, ActionType;

// Registry artifacts (range-specific cleanup key)
let RegAF =
DeviceRegistryEvents
| where DeviceName == device
| where RegistryKey has @"SOFTWARE\CorpHRChaos"
| project Timestamp, Source="Reg", RegistryKey, RegistryValueName, RegistryValueData;

union ProcAF, FileAF, RegAF
```

🧠 **Thought process:** ChatGPT wrote the query as I wasn't sure what I was looking for, BUT it gave me the correct answer immediately. According to the new logs the answer is different, the time obviouslly, but the file as well. In previous logs it was EmptySysmonConfig.xml but in the new logs i'm seeing ConsoleHost_history.txt.

**Answer: 2025-07-19T06:18:38.6841044Z**

---

## ✅ Conclusion

The endpoint nathan-iel-vm shows a clear, HR-themed intrusion that relied almost entirely on built-in tooling (LOLBAS).

The attacker:

	•	Recon & account scoping: whoami /all, net localgroup Administrators, and qwinsta to learn privileges and sessions.
	•	AV weakening: multiple Set-MpPreference -DisableRealtimeMonitoring $true runs and policy change (DisableAntiSpyware) to lower defenses.
	•	Credential access: LSASS mini-dump via rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump … saved as C:\HRTools\HRConfig.json, then opened with notepad.exe.
	•	WData staging & tampering: Created many HR artifacts and modified PromotionCandidates.csv (also duplicated under LegacyAutomation).
	•	Egress testing & exfil: Outbound beacons to pipedream.net and scripted POST of staged data.
	•	Persistence: Run-key autostart (HRToolTracker) pointing to OnboardTracker.ps1.
 	•	Anti-forensics: Deletion of traces (PS history, Defender history), log clearing via wevtutil cl Security, and final Sysmon neutering by dropping EmptySysmonConfig.xml



