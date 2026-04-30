# Multi-Stage Linux Host Compromise Investigation – Microsoft Sentinel

## Lab Objective

This project simulates and investigates a realistic multi-stage compromise of a cloud-hosted Linux virtual machine monitored using Microsoft Sentinel.

The objective was to replicate attacker behaviour across multiple phases of the intrusion lifecycle and develop behavioural detection logic aligned with real Tier-2 SOC investigation workflows.

---

## Investigation Focus

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

## Simulated Attack Scenario

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

## Detection Engineering Approach

Behaviour-based hunting queries were developed in Microsoft Sentinel to correlate authentication telemetry with host activity indicators.

Detection logic focused on identifying suspicious behavioural sequences such as:

- Successful external authentication followed by rapid privilege escalation  
- Creation of new privileged accounts after initial access  
- Persistence establishment through cron scheduling or SSH key modification  
- Sensitive file interaction suggesting credential harvesting intent  
- Archive creation and cleanup actions indicating data staging  

This correlation-driven approach improves detection fidelity compared to isolated alerting.

---

## Detection Strategy & Behavioural Correlation Logic

Rather than alerting on isolated system events, detection logic for this scenario focused on identifying a **sequence of attacker behaviours occurring within a defined timeframe.**

This strategy aligns with modern SOC detection engineering practices where behavioural correlation improves signal confidence and reduces false positives.

### Key Correlated Indicators

The detection approach prioritised identifying patterns such as:

- Successful external SSH authentication followed by rapid privilege escalation  
- Creation or modification of privileged accounts shortly after login  
- Persistence establishment through scheduled task execution or SSH key manipulation  
- Interaction with sensitive credential storage indicating potential credential harvesting  
- Archive creation or data staging activity suggesting collection objectives  
- Attempts at defence evasion such as log manipulation or history clearing  

### Detection Confidence Logic

Individually, these events may represent legitimate administrative activity.  
However, when observed as a **behavioural chain**, they provide high-confidence evidence of host compromise.

Detection prioritisation therefore considered:

- Event sequencing  
- Temporal proximity between authentication and elevated actions  
- Presence of persistence indicators  
- Signs of attacker reconnaissance or credential access  

This correlation-driven methodology reflects real Tier-2 SOC detection engineering workflows designed to balance visibility with alert fidelity.

---

The investigation followed a structured behavioural analysis workflow aligned with real SOC incident response practices.

### Timeline Correlation

Authentication telemetry was first reviewed to identify the initial point of access.  
Subsequent system activity was then correlated to determine attacker actions performed after login.

### Privilege Escalation Analysis

Logs were examined for indicators of elevated privilege usage including:

• sudo and root session activity  
• administrative command execution  
• account group membership modification  

This helped determine whether the intrusion progressed beyond initial access.

### Persistence Mechanism Identification

The investigation focused on detecting techniques used to maintain long-term access:

• Creation of new privileged service accounts  
• Modification of SSH authorised_keys files  
• Scheduled task (cron) configuration  

These behaviours indicated deliberate attempts to establish sustained control.

### Defence Evasion Indicators

Evidence of attacker attempts to reduce visibility was analysed, including:

• Command history clearing  
• log artefact removal  
• covert execution patterns  

### Impact & Risk Evaluation

By analysing correlated host telemetry, the investigation assessed:

• attacker intent  
• persistence level  
• potential credential exposure  
• likelihood of lateral movement risk  

This structured methodology reflects real Tier-2 SOC investigative decision-making where contextual behavioural analysis is prioritised over isolated alert review.

---

## Incident Response Actions

Following confirmation of suspicious activity, simulated containment actions included:

- Removal of persistence mechanisms  
- Locking of suspicious service accounts  
- Validation of scheduled task removal  
- Review of authentication telemetry for further compromise indicators  
- Host shutdown to simulate isolation and incident containment  

---

## Skills Demonstrated

- Behaviour-based threat hunting in Microsoft Sentinel  
- KQL detection engineering and log correlation  
- Linux host security telemetry analysis  
- Privilege escalation and persistence investigation  
- SOC incident severity classification  
- Timeline reconstruction of attacker activity  
- Practical incident containment workflow  

---

## MITRE ATT&CK Techniques Observed

- T1078 – Valid Accounts  
- T1548 – Abuse Elevation Control Mechanism  
- T1098 – Account Manipulation  
- T1053 – Scheduled Task / Cron  
- T1003 – OS Credential Dumping  
- T1087 – Account Discovery  
- T1070 – Indicator Removal  

---

## Detection Improvement Opportunities

Future detection enhancements could include:

- Correlation of failed authentication bursts prior to successful access  
- Geo-anomaly detection for external SSH sessions  
- Behaviour baselining for privileged command execution  
- Automated alert enrichment using Sentinel playbooks  
- Integration with endpoint telemetry for deeper visibility  

---

## SOC Analyst Reflection

This investigation highlighted the importance of analysing attacker behaviour progression rather than focusing solely on isolated alerts.

The lab strengthened practical skills in behavioural hunting, incident prioritisation, and detection engineering — key competencies for modern SOC analysts.

---

## Example Behavioural Detection Logic (KQL)

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

---

## Incident Severity Assessment

Based on correlated behavioural evidence observed during the investigation, the activity was assessed as a **high-severity host compromise scenario.**

Several factors contributed to this classification:

- Successful external authentication followed by rapid privilege escalation  
- Creation of additional privileged accounts indicating persistence intent  
- Modification of authentication mechanisms enabling covert re-entry  
- Interaction with sensitive system credential storage locations  
- Evidence of system discovery and reconnaissance activity  
- Archive creation suggesting potential data collection objectives  
- Indicators of defence evasion behaviour aimed at reducing detection visibility  

When evaluated collectively, these behaviours demonstrated attacker capability to maintain access, elevate privileges, and potentially impact system confidentiality and integrity.

This severity assessment reflects real SOC prioritisation practices where behavioural correlation and attacker intent drive incident classification and response urgency.

