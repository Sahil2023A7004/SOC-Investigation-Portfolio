# SOC L1 Portfolio 01: Network Traffic Forensics and Attack Signature Analysis

**Focus:** Multi stage malware PCAP triage, C2 beaconing, port scans, DNS and ICMP tunneling
**Tools:** Wireshark, Nmap, VirusTotal
**Verdict (Carnage scenario):** True Positive, escalated to SOC L2

## Part A: Multi Stage Malware and Cobalt Strike C2 Investigation

**Capture analyzed:** `carnage.pcap`

### 1. Executive Summary

Packet analysis of the internal host `10.9.23.102` shows a multi stage compromise:

1. **Delivery:** HTTP download of a malicious archive, `documents.zip`, from `attirenepal[.]com`. The archive contains an Excel payload.
2. **Command and control:** Outbound TLS handshakes and periodic HTTP beaconing roughly every 5 seconds to confirmed Cobalt Strike infrastructure (`185[.]106[.]96[.]158` and `185[.]125[.]204[.]174`). The requests carry a spoofed `Host: ocsp[.]verisign[.]com` header.
3. **Post infection activity:** HTTP POST check ins to `maldivehost[.]net` and a high volume outbound SMTP burst of 1,439 packets.

### 2. Evidence and Analysis Walkthrough

#### 2.1 Initial Payload Delivery and Safe Inspection

Isolated `documents.zip` (198 kB, packet 2173) using File, Export Objects, HTTP. Reviewed `tcp.stream eq 73` in ASCII and confirmed the embedded Excel payload from the ZIP `PK` magic bytes. The malware was never extracted to disk.

![HTTP Export Object](images/01_http_export_zip.jpg)
![Safe ZIP Stream Inspection](images/02_zip_stream_xls.jpg)

#### 2.2 Encrypted Traffic Pivot (TLS SNI)

Filtered TLSv1.2 Client Hello packets to read the plaintext Server Name Indication (`finejewels[.]com[.]au`) from otherwise encrypted sessions.

![TLS SNI Extraction](images/03_tls_sni.png)

#### 2.3 Cobalt Strike C2 Beaconing and Threat Intel Enrichment

Identified automated GET requests to `/gscp.R/...` from `10.9.23.102` to `185[.]106[.]96[.]158` at a steady interval of about 5 seconds. Following `tcp.stream eq 327` exposed a spoofed `Host: ocsp[.]verisign[.]com` header. VirusTotal confirmed Cobalt Strike C2 attribution for `survmeter[.]live` and `securitybusinpuff[.]com`.

![C2 Beaconing](images/04_c2_beaconing.jpg)
![Spoofed Host Header](images/05_c2_domain_fronting.jpg)
![VirusTotal C2 Attribution](images/06_vt_cobalt_strike.png)

#### 2.4 Post Infection Activity

Isolated outbound HTTP POST traffic (`tcp.stream eq 104`) to `maldivehost[.]net` (Apache 2.4.49 with cPanel, PHP 5.6.40). The same host also generated 1,439 outbound `smtp` packets, consistent with post exploitation abuse.

![Post Infection HTTP POST](images/07_post_exfil.jpg)

### 3. Defanged Indicators of Compromise

<table>
  <tr><th>Type</th><th>Indicator</th><th>Context</th></tr>
  <tr><td>Victim host</td><td><code>10.9.23.102</code></td><td>Compromised internal workstation</td></tr>
  <tr><td>Delivery domain and file</td><td><code>attirenepal[.]com</code> and <code>documents.zip</code></td><td>Initial HTTP dropper containing an Excel payload</td></tr>
  <tr><td>C2 server 1</td><td><code>185[.]106[.]96[.]158</code> and <code>survmeter[.]live</code></td><td>Confirmed Cobalt Strike C2, spoofed Host header <code>ocsp[.]verisign[.]com</code></td></tr>
  <tr><td>C2 server 2</td><td><code>185[.]125[.]204[.]174</code> and <code>securitybusinpuff[.]com</code></td><td>Secondary Cobalt Strike C2</td></tr>
  <tr><td>Post infection host</td><td><code>maldivehost[.]net</code></td><td>Outbound HTTP POST check in</td></tr>
</table>

### 4. Containment and L2 Escalation

**Immediate containment:** Isolate `10.9.23.102` through EDR to cut active and fallback C2 channels. Block all listed C2 IPs and domains at the perimeter firewall and proxy.

**Host pivot for L2 handoff:** Review Windows Security Event ID 4688 and Sysmon Event ID 1 (process creation) and Event ID 3 (network connection) on `10.9.23.102`. Confirm macro execution from `excel.exe` and check for persistence.

## Part B: Reconnaissance and Covert Tunneling Signatures (Lab Validation)

To build network triage baselines, I captured and analyzed three core attack patterns in Wireshark.

### 1. TCP SYN Port Scan (MITRE T1046)

**Filter:** `tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024`
**Finding:** Conversations show 50 distinct destination ports probed rapidly from a single source port (`42296`), matching an Nmap SYN scan.

![Nmap SYN Scan](images/08_nmap_syn_scan.png)

### 2. DNS Tunneling with iodine (MITRE T1071.004)

**Filter:** `dns and dns.qry.name.len > 30` and `dns.qry.type == 10 || dns.qry.type == 16`
**Finding:** Encoded subdomains of 47 to 61 characters and a flood of NULL (type 10) records, all targeting a single base domain.

![DNS Tunneling](images/09_dns_tunneling.png)

### 3. ICMP Tunneling (MITRE T1095)

**Filter:** `icmp and data.len > 64`
**Finding:** Oversized 170 byte Echo Request and Reply frames carrying an embedded hex payload (`73 65 63 72 65 74`, which decodes to `secret`) instead of the standard 32 to 56 bytes of OS padding.

![ICMP Tunneling](images/10_icmp_tunneling.png)
