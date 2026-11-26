# Linux Log Analysis & Process Tree Investigation: SOC L1 

---

## Core Linux Log Sources & Commands

| Log Source / Tool | Default Path | What It Captures | Key Triage Commands |
| :--- | :--- | :--- | :--- |
| Authentication Logs | `/var/log/auth.log` | SSH logins (`Accepted` / `Failed password`), `sudo`, `passwd` changes | `grep -i "failed password" /var/log/auth.log` |
| Nginx Access Logs | `/var/log/nginx/access.log` | HTTP requests, query parameters, status codes, User-Agents | `grep -E ";|\|" /var/log/nginx/access.log` |
| Apache Access Logs | `/var/log/apache2/access.log` | HTTP requests on Apache-hosted web apps | `grep "<attacker_ip>" /var/log/apache2/access.log` |
| Linux Audit Daemon | `/var/log/audit/audit.log` | Syscalls (`EXECVE`), command arguments (`PROCTITLE`), `PID`/`PPID` trees | `ausearch -i -x <cmd>` & `ausearch -i --ppid <PID>` |

---

## 1. SSH Authentication & Brute-Force Analysis (`/var/log/auth.log`)

### Separating Normal Sessions from Failed Attempts
OpenSSH logs successful logins as `Accepted password` or `Accepted publickey` rather than the word `login`, and logs failed attempts with a lowercase `p` (`Failed password`). Using `grep -i` prevents case-sensitivity blind spots during triage.

<img width="1072" height="147" alt="1" src="https://github.com/user-attachments/assets/f61a34da-a821-40c2-ba56-39ccd51b703f" />

### Filtering Failed Logins & Validating Alerts
Filtering "/var/log/auth.log" for "Failed" exposed automated brute-force attempts targeting "root" and non-existent usernames (`sol`) from external source IPs ("197.39.195.136" and "193.32.162.145").

<img width="1076" height="195" alt="2" src="https://github.com/user-attachments/assets/b0765da9-4f55-4683-bd68-c4ff03df03f6" />

To distinguish a true brute-force alert from a legitimate user mistyping a password, check:

* **Attempt frequency:** Rapid bursts within seconds indicate automated tooling.
  
* **Source IP reputation:** Check external IPs against AbuseIPDB, VirusTotal, Cisco Talos Intelligence, and GreyNoise.
  
* **Username validity & login timing:** Flag attempts against "root", invalid usernames, or off-hours activity.

### Confirming Breach Impact (`Accepted` vs. `passwd`)
Pivoting on `Accepted` confirmed a successful password login for `root` from external IP "91.224.92.97" ("sshd[16876]"). Note that `Accepted password` confirms authentication via password rather than a password reset—checking for post-compromise password modifications requires searching for "passwd".

<img width="1072" height="62" alt="3" src="https://github.com/user-attachments/assets/ad0755e9-59ea-462c-a62b-f238fc274302" />


## 2. Web Server Access Log Analysis (`/var/log/nginx/access.log`)

Reviewing `/var/log/nginx/access.log` revealed normal `ping` health-check requests transitioning into OS command injection from "10.14.14.255":

1. **Probe & Command Separator Discovery:** `GET /ping?host=whoami` returned HTTP `500`, whereas `GET /ping?host=;whoami` returned HTTP `200`, confirming shell command execution via `;`.
2. **Host Discovery & Source Code Read:** The attacker enumerated the working directory and read the application source via `;ls`, `;pwd`, and `;cat+/opt/trypingme/main.py` (all returning HTTP `200`).
3. **Reverse Shell Delivery:** Sent a URL-encoded Python socket reverse shell targeting port `1337` (`GET /ping?host=;python3%20-c%20'import%20socket,subprocess,os...'`).

<img width="1067" height="742" alt="4" src="https://github.com/user-attachments/assets/edcf36f8-cc45-4f2f-b87d-fde8e043b3e1" />


## 3. Service Breach & Process Tree Reconstruction (`auditd`)

Application logs alone rarely capture full post-exploitation activity. Using `ausearch`, we reconstructed the execution chain directly from kernel audit logs:

### Tracing Upward (`PID` → `PPID`) & Downward (`--ppid`)
1. Queried `ausearch -i -x whoami` to locate the execution event (`pid=1020`, `cwd=/opt/trypingme`) and identified its parent process ID (`ppid=1018`).
2. Pivoted downward using `ausearch -i --ppid 1018` to list all sibling commands spawned by the vulnerable web app process (`ping -c 2` followed by `whoami`).

<img width="1077" height="687" alt="5" src="https://github.com/user-attachments/assets/83a22146-9a2e-4ecc-8f0e-82d7feb03d4b" />

### Confirming Full Command Arguments (`PROCTITLE` & `EXECVE`)
Running `ausearch -i -x ping` confirmed how user input was passed unsanitized into `ping -c 2 hello` and `ping -c 2 whoami` from `/opt/trypingme` across `ppid=1014`, `1016`, and `1018`.

<img width="1080" height="766" alt="6" src="https://github.com/user-attachments/assets/0a8fb35e-ea1e-4148-a67d-86e33fba003b" />

Finally, inspecting the `EXECVE` record at `20:11:16` confirmed `/bin/sh -c` spawning the Python reverse shell payload (`python3 -c 'import socket,subprocess,os;...'`) out of `/opt/trypingme`.

<img width="1070" height="152" alt="7" src="https://github.com/user-attachments/assets/c400f567-bc04-43ea-a549-ee94b2dc5fc5" />


## Extracted IOCs (Defanged)

* **Compromised Application Directory:** `/opt/trypingme/main.py`
* **External SSH Brute-Force IPs:** `197.39.195.136, 193.32.162.145`
* **Confirmed Root SSH Login IP:** `91.224.92.79`
* **Web Command Injection / Reverse Shell IP:** `10.14.105.255` (Port `1337`)
