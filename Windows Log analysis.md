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

![Filtering Security.evtx for Event ID 4624](images/01-evtx-filter-4624.png)

* **Timestamp:** `2025-05-17 22:53:41`
* **Target Host / Account:** `THM-PC\Administrator` (`TargetUserSid`: `S-1-5-21-1966530601-3185510710604624-500`)
* **Logon Type:** `10` (RemoteInteractive / RDP via `User32`)
* **Target Logon ID:** `0x183c36d`

![Event ID 4624 showing RDP LogonType 10 as Administrator](images/02-rdp-logon-4624.jpg)

### 2. Backdoor Account Creation (Event ID `4720`)
77 seconds after the RDP login, a new local user account was created to maintain access:

* **Timestamp:** `2025-05-17 22:54:58`
* **Created Account (`TargetUserName`):** `svc_sysrestore`
* **MITRE ATT&CK:** `T1136.001` (Create Account: Local Account)

![Event ID 4720 showing svc_sysrestore account creation](images/03-user-created-4720.png)

### 3. Privilege Escalation via Local Group Membership (Event ID `4732`)
Immediately after creation, three `4732` events fired (`22:54:59`, `22:55:12`, `22:55:24`), adding the newly created account into privileged local groups including **`BUILTIN\Backup Operators`** (which permits reading sensitive files such as SAM/SYSTEM hives and bypassing standard ACLs).

* **MITRE ATT&CK:** `T1098` (Account Manipulation)

![Event ID 4732 adding account to Backup Operators](images/04-group-added-4732.png)

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

![Sysmon Event 15 showing Chrome Zone.Identifier and HostUrl](images/05-sysmon-15-motw-download.jpg)

### 2. Startup Folder Persistence (Sysmon Event ID `11` — FileCreate)
Roughly 83 seconds after download, `ckjg.exe` (`PID 1460`) executed and wrote a persistence file directly into the user's Windows Startup directory:

* **Timestamp:** `2025-05-18 16:08:46.604 UTC`
* **Originating Process:** `C:\Users\sarah.miller\Downloads\ckjg.exe` (`PID 1460`)
* **Dropped Path:** `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp...`
* **MITRE ATT&CK:** `T1547.001` (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder; logged under legacy Sysmon rule `T1023`)

![Sysmon Event 11 showing Startup folder persistence drop](images/06-sysmon-11-startup-persistence.png)

### 3. Command & Control DNS Lookup (Sysmon Event ID `22` — DNS Query)
11 seconds after establishing persistence, the same process resolved an external DGA-style domain:

* **Timestamp:** `2025-05-18 16:08:57.208 UTC`
* **Process:** `C:\Users\sarah.miller\Downloads\ckjg.exe` (`PID 1460`)
* **Queried Domain:** `hkfasfsafg[.]click`
* **Resolved IP:** `193[.]46[.]217[.]4` (`::ffff:193.46.217.4`)

![Sysmon Event 22 showing DNS query to C2 domain](images/07-sysmon-22-c2-dns.png)

### 4. Outbound Network Connection (Sysmon Event ID `3` — NetworkConnect)
Confirmed active outbound network telemetry from the exact same `ProcessGuid` (`{c5d2b969-060b-682a-490c-000000001701}`) immediately following DNS resolution.

![Sysmon Event 3 confirming outbound connection from ckjg.exe](images/08-sysmon-03-network-conn.png)

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
