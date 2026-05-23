# soc-homelab-wazuh
> Built a SOC homelab using Wazuh, Sysmon, Kali Linux, and Windows 10 to simulate brute-force attacks, monitor endpoint telemetry, investigate PowerShell activity, and analyze MITRE ATT&CK mapped alerts.

---

## Lab Architecture

```text
Kali Linux (Attacker) — 192.168.56.109
        ↓
Windows 10 + Sysmon (Victim) — 192.168.56.108
        ↓
Ubuntu Server + Wazuh SIEM
```

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Wazuh v4.7.5 | SIEM and security monitoring |
| Sysmon | Endpoint telemetry (Windows) |
| Kali Linux | Attack simulation machine |
| Windows 10 | Monitored victim endpoint (DESKTOP-MOSHGPL) |
| Ubuntu Server | Wazuh SIEM server |
| VirtualBox | Virtual lab environment |
| Hydra / xfreerdp | Brute-force simulation |
| PowerShell | Attack simulation and telemetry |

---

## Simulated Attacks

### 1. Reconnaissance

```powershell
whoami
systeminfo
ipconfig /all
net user
```

### 2. Encoded PowerShell Execution

```powershell
powershell -enc SQBFAFgA
```

### 3. RDP Brute-Force

```bash
xfreerdp /u:testuser /p:WrongPassword /v:192.168.56.108
```

Detected via Windows Event ID 4625 (failed login), Wazuh Rule 60122, and Rule 60204 (multiple failures alert).

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Repeated failed RDP authentication |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Logon failure and successful authentication detected |
| Account Manipulation | [T1531](https://attack.mitre.org/techniques/T1531/) | Account-related impact observed during brute-force |
| PowerShell | [T1059](https://attack.mitre.org/techniques/T1059/) | Encoded PowerShell execution |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | PowerShell created executable file in Windows root |
| Account Discovery | [T1087](https://attack.mitre.org/techniques/T1087/) | whoami, net user, systeminfo |

---

## Detections

Wazuh successfully detected:

- Failed login attempts — Windows Event ID 4625, Wazuh Rule 60122 (level 5)
- Multiple login failures threshold — Wazuh Rule 60204 (level 10)
- PowerShell file creation in Windows root — Wazuh Rule 92205 (level 9)
- Encoded PowerShell execution — Sysmon Event ID 1
- Discovery commands — process creation telemetry
- Registry modifications — Sysmon Event ID 13
- DNS queries — Sysmon Event ID 22

### Key Wazuh Rule IDs

| Rule ID | Description | Level |
|---------|-------------|-------|
| 60122 | Logon failure - Unknown user or bad password | 5 |
| 60204 | Multiple Windows logon failures | 10 |
| 92205 | PowerShell process created executable in Windows root | 9 |

### Key Wazuh Queries

```
rule.id: 60122
rule.id: 60204
rule.id: 92205
event.code: 1 AND data.win.eventdata.image: *powershell.exe*
data.win.eventdata.commandLine: *-enc*
agent.name: winlab-001
```

---

## Screenshots

| Description | File |
|---|---|
| Wazuh agent overview (MITRE tactics, compliance) | screenshots/wazuh-dashboard.png |
| Failed login alerts — Rule 60122 | screenshots/failed-login-alerts.png |
| PowerShell detection — Rule 92205 | screenshots/powershell-detection.png |
| Sysmon Event ID 1 — process creation | screenshots/sysmon-event-id-1.png |
| MITRE ATT&CK mapping — T1078 detail | screenshots/mitre-attack-mapping.png |

---

## Indicators of Compromise (IOCs)

**Attacker IP:** `192.168.56.109`
**Victim IP:** `192.168.56.108`
**Hostname:** `DESKTOP-MOSHGPL`

**Suspicious Processes:**
- `powershell.exe` — C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
- `SecEdit.exe` — C:\Windows\SysWOW64\SecEdit.exe
- `net.exe`
- `whoami.exe`

**Suspicious Files Created:**
- `C:\Windows\SystemTemp\__PSScriptPolicyTest_tbxthy5y.kib.ps1`

---

## Incident Timeline

| Time | Activity |
|---|---|
| 03:50 | Reconnaissance initiated |
| 03:57 | Multiple failed RDP logins detected |
| 03:59 | Successful authentication observed |
| 04:01 | PowerShell execution detected |
| 04:02 | Discovery commands executed |

---

## Future Improvements

- Splunk integration
- Suricata IDS integration
- Sigma rule development
- Atomic Red Team simulations
- Custom Wazuh detection rules

---

## Skills Demonstrated

- SIEM deployment and management (Wazuh v4.7.5)
- Windows endpoint monitoring with Sysmon
- Brute-force attack detection and investigation
- PowerShell telemetry analysis
- Wazuh rule ID analysis and correlation
- MITRE ATT&CK mapping
- Incident response workflow
- Threat hunting basics

---

> ⚠️ This lab was built strictly for educational and defensive cybersecurity purposes in an isolated virtual environment.
