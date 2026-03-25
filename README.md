# Multi-Stage Linux Host Compromise Investigation – Microsoft Sentinel

## 🎯 Lab Objective

This project simulates and investigates a realistic multi-stage compromise of a cloud-hosted Linux virtual machine monitored using Microsoft Sentinel.

The objective was to replicate attacker behaviour across multiple phases of the intrusion lifecycle and develop behavioural detection logic aligned with real Tier-2 SOC investigation workflows.

---

## 🧠 Investigation Focus

This lab emphasises advanced host-based threat hunting and incident investigation techniques aligned with real SOC Tier-2 response activities.

The investigation focused on identifying indicators of a **multi-stage intrusion**, including:

- Correlation of authentication events with post-login behavioural anomalies  
- Detection of privilege escalation patterns involving sudo and root session activity  
- Identification of persistence mechanisms such as new privileged account creation and SSH key modification  
- Recognition of defence evasion activity including log tampering and command history removal  
- Analysis of network activity and system interaction consistent with attacker reconnaissance  
- Monitoring for potential credential access behaviour targeting sensitive Linux system files  

By analysing these signals within a structured timeline, the investigation aimed to determine attacker intent, persistence level, and potential risk to the broader environment.

This approach mirrors real-world SOC investigative methodology where contextual behavioural analysis is prioritised over isolated alert-driven response.

---

## 🧪 Simulated Attack Scenario

Following successful remote SSH authentication from an external IP address, an attacker performed a sequence of post-compromise actions designed to establish persistence, escalate privileges, and prepare for potential credential theft and data exfiltration.

Simulated attacker behaviours included:

- Valid account abuse via remote SSH login  
- Privilege escalation using sudo / root session activity  
- Creation of covert administrative persistence account  
- SSH authorised key modification to enable password-less access  
- Scheduled task persistence via cron execution  
- System discovery and process enumeration  
- Credential access attempts targeting sensitive files  
- Network reconnaissance and connection awareness  
- Data staging through system archive creation  
- Defence evasion behaviour including log removal indicators  

---

## 🛰️ Detection Engineering Approach

Behaviour-based hunting queries were developed in Microsoft Sentinel to correlate authentication telemetry with host activity indicators.

Detection logic focused on identifying suspicious behavioural sequences such as:

- Successful external authentication followed by rapid privilege escalation  
- Creation of new privileged accounts after initial access  
- Persistence establishment through cron scheduling or SSH key modification  
- Sensitive file interaction suggesting credential harvesting intent  
- Archive creation and cleanup actions indicating data staging  

This correlation-driven approach improves detection fidelity compared to isolated alerting.

---

## 🔎 Investigation Methodology

A structured SOC investigation workflow was followed:

1. Validate authentication source and login frequency  
2. Expand timeline to identify post-authentication behavioural patterns  
3. Analyse privilege escalation sessions and account manipulation events  
4. Detect persistence mechanisms including cron execution and SSH key changes  
5. Review discovery and reconnaissance commands executed on host  
6. Identify potential credential access or data staging behaviour  
7. Assess defence evasion indicators and potential attacker intent  

This methodology reflects real incident triage practices used to confirm host compromise.

---

## 🛡️ Incident Response Actions

Following confirmation of suspicious activity, simulated containment actions included:

- Removal of persistence mechanisms  
- Locking of suspicious service accounts  
- Validation of scheduled task removal  
- Review of authentication telemetry for further compromise indicators  
- Host shutdown to simulate isolation and incident containment  

---

## 📊 Skills Demonstrated

- Behaviour-based threat hunting in Microsoft Sentinel  
- KQL detection engineering and log correlation  
- Linux host security telemetry analysis  
- Privilege escalation and persistence investigation  
- SOC incident severity classification  
- Timeline reconstruction of attacker activity  
- Practical incident containment workflow  

---

## 📌 MITRE ATT&CK Techniques Observed

- T1078 – Valid Accounts  
- T1548 – Abuse Elevation Control Mechanism  
- T1098 – Account Manipulation  
- T1053 – Scheduled Task / Cron  
- T1003 – OS Credential Dumping  
- T1087 – Account Discovery  
- T1070 – Indicator Removal  

---

## 📈 Detection Improvement Opportunities

Future detection enhancements could include:

- Correlation of failed authentication bursts prior to successful access  
- Geo-anomaly detection for external SSH sessions  
- Behaviour baselining for privileged command execution  
- Automated alert enrichment using Sentinel playbooks  
- Integration with endpoint telemetry for deeper visibility  

---

## 🧠 SOC Analyst Reflection

This investigation highlighted the importance of analysing attacker behaviour progression rather than focusing solely on isolated alerts.

The lab strengthened practical skills in behavioural hunting, incident prioritisation, and detection engineering — key competencies for modern SOC analysts.

---

## 🔬 Example Behavioural Detection Logic (KQL)

The following hunting logic demonstrates correlation of remote authentication activity with subsequent privilege escalation behaviour — a common indicator of potential host compromise.

```kql
let timeframe = 6h;

let ssh_logins =
Syslog
| where TimeGenerated > ago(timeframe)
| where ProcessName == "sshd"
| where SyslogMessage contains "Accepted password"
| extend Account = extract(@"for (\w+)", 1, SyslogMessage),
         SourceIP = extract(@"from ([0-9.]+)", 1, SyslogMessage)
| project LoginTime = TimeGenerated, Computer, Account, SourceIP;

let privilege_activity =
Syslog
| where TimeGenerated > ago(timeframe)
| where SyslogMessage has_any ("sudo", "session opened for user root", "su:")
| project PrivTime = TimeGenerated, Computer, SyslogMessage;

ssh_logins
| join kind=inner privilege_activity on Computer
| where PrivTime between (LoginTime .. LoginTime + 30m)
| project LoginTime, PrivTime, Account, SourceIP, Computer, SyslogMessage
| order by PrivTime desc
```

This detection approach highlights suspicious behavioural chaining rather than isolated system events, improving alert confidence and reducing false positives.
