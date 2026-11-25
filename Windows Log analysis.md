# Windows Event & Sysmon Log Analysis 

---

## Key Event IDs Investigated

| Log Source | Event ID | Meaning | SOC Triage Value |
| :--- | :---: | :--- | :--- |
| Security | `4624` | Successful Logon | Identify access vector via `LogonType` (`10` = RemoteInteractive/RDP, `3` = Network) |
| Security | `4720` | User Account Created | Detect backdoor or unauthorized local accounts |
| Security | `4732` | Member Added to Security-Enabled Local Group | Catch privilege escalation (e.g., `Administrators`, `Backup Operators`) |
| Sysmon | `15` | FileCreateStreamHash (ADS / MOTW) | Recover exact download URL (`HostUrl`), `ZoneId`, and file hashes via `:Zone.Identifier` |
| Sysmon | `11` | FileCreate | Detect payloads dropped into Startup folders or staging paths |
| Sysmon | `22` | DNSEvent (DNS Query) | Map suspicious outbound domain lookups directly to the originating process |
| Sysmon | `3` | NetworkConnect | Confirm active outbound C2 connections tied to a specific `ProcessGuid` / PID |

---

## Investigation 1: Unauthorized RDP Access & Backdoor Persistence

### 1. Filtering for Remote Access (Event ID `4624`)
Filtered the saved Security event log for Event ID `4624` and pivoted on source IP `10.10.53.248` to locate remote interactive logins.

<img width="1016" height="867" alt="1" src="https://github.com/user-attachments/assets/ce46f472-cbe8-4c13-a854-12bc4227c3a5" />)

* **Timestamp:** `2025-05-17 22:53:41`
* **Target Host / Account:** `THM-PC\Administrator` (`TargetUserSid`: `S-1-5-21-1966530601-3185510710604624-500`)
* **Logon Type:** `10` (RemoteInteractive / RDP via `User32`)
* **Target Logon ID:** `0x183c36d`

<img width="1012" height="757" alt="3" src="https://github.com/user-attachments/assets/f5ddadd1-fed0-4e12-99e5-bfa404018ac3" />
### 2. Backdoor Account Creation (Event ID `4720`)
77 seconds after the RDP login, a new local user account was created to maintain access:

* **Timestamp:** `2025-05-17 22:54:58`
* **Created Account (`TargetUserName`):** `svc_sysrestore`
* **MITRE ATT&CK:** `T1136.001` (Create Account: Local Account)

<img width="1025" height="517" alt="4" src="https://github.com/user-attachments/assets/adb21783-a79d-47bd-b0f7-01f60dbbda5a" />
### 3. Privilege Escalation via Local Group Membership (Event ID `4732`)
Immediately after creation, three `4732` events fired (`22:54:59`, `22:55:12`, `22:55:24`), adding the newly created account into privileged local groups including **`BUILTIN\Backup Operators`** (which permits reading sensitive files such as SAM/SYSTEM hives and bypassing standard ACLs).

* **MITRE ATT&CK:** `T1098` (Account Manipulation)

<img width="1025" height="531" alt="5" src="https://github.com/user-attachments/assets/7ff2ddb6-712d-48a5-858a-24225557057b" />
---

## Investigation 2: Malware Delivery, Startup Persistence & C2 Beaconing 

By pivoting on **`ProcessGuid: {c5d2b969-060b-682a-490c-000000001701}`** (`PID 1460`), the full execution chain was reconstructed across four Sysmon event types.

### 1. Initial Delivery via Browser (Sysmon Event ID `15` — FileCreateStreamHash)
Even without proxy logs, Sysmon Event ID `15` captured the NTFS Alternate Data Stream (`:Zone.Identifier`) written by Chrome when the payload hit disk:

* **Timestamp:** `2025-05-18 16:07:23.848 UTC` (Logged `4:07:38 PM`)
* **User:** `THM-PC\sarah.miller`
* **Parent Browser:** `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe` (`PID 4600`)
* **Downloaded File:** `C:\Users\sarah.miller\Downloads\ckjg.exe`
* **Zone Transfer Details:** `ZoneId=3` (Internet) | `HostUrl=hxxp://gettsveriff[.]com/bgj3/ckjg.exe`
* **MD5:** `B721ACDDF7B64B7D1ABEF3CB4F6A34A9`
* **SHA256:** `B23ECDF759CD1488EBB798F0A6D6F5E70D1B518D4A46731C7681E4961923415A`

<img width="585" height="557" alt="7" src="https://github.com/user-attachments/assets/c1a2dcef-63b7-47df-8caa-3065d73dcd3e" />
### 2. Startup Folder Persistence (Sysmon Event ID `11` — FileCreate)
Roughly 83 seconds after download, `ckjg.exe` (`PID 1460`) executed and wrote a persistence file directly into the user's Windows Startup directory:

* **Timestamp:** `2025-05-18 16:08:46.604 UTC`
* **Originating Process:** `C:\Users\sarah.miller\Downloads\ckjg.exe` (`PID 1460`)
* **Dropped Path:** `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp...`
* **MITRE ATT&CK:** `T1547.001` (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder; logged under legacy Sysmon rule `T1023`)

<img width="576" height="610" alt="8" src="https://github.com/user-attachments/assets/ca7c8979-b72f-47ee-a21a-3072d4d73ef3" />
### 3. Command & Control DNS Lookup (Sysmon Event ID `22` — DNS Query)
11 seconds after establishing persistence, the same process resolved an external DGA-style domain:

* **Timestamp:** `2025-05-18 16:08:57.208 UTC`
* **Process:** `C:\Users\sarah.miller\Downloads\ckjg.exe` (`PID 1460`)
* **Queried Domain:** `hkfasfsafg[.]click`
* **Resolved IP:** `193[.]46[.]217[.]4` (`::ffff:193.46.217.4`)

<img width="772" height="362" alt="9" src="https://github.com/user-attachments/assets/302fab7c-4b93-4b8e-bc7d-51bb7e53109e" />
### 4. Outbound Network Connection (Sysmon Event ID `3` — NetworkConnect)
Confirmed active outbound network telemetry from the exact same `ProcessGuid` (`{c5d2b969-060b-682a-490c-000000001701}`) immediately following DNS resolution.

<img width="772" height="387" alt="6" src="https://github.com/user-attachments/assets/c95bb732-b63e-43b6-bbbb-237a1291d54d" />
---

## Extracted IOCs (Defanged)

* **Malicious Payload Path:** `C:\Users\sarah.miller\Downloads\ckjg.exe`
* **SHA256:** `B23ECDF759CD1488EBB798F0A6D6F5E70D1B518D4A46731C7681E4961923415A`
* **MD5:** `B721ACDDF7B64B7D1ABEF3CB4F6A34A9`
* **Download URL:** `hxxp://gettsveriff[.]com/bgj3/ckjg.exe`
* **C2 Domain:** `hkfasfsafg[.]click`
* **C2 IP:** `193[.]46[.]217[.]4`
* **Unauthorized Local Account:** `svc_sysrestore`
* **Suspicious Source IP (Lab RDP):** `10.10.53.248`
