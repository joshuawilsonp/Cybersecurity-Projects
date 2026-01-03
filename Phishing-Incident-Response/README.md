# Phishing Incident Response

## Project Overview
This project simulates the investigation of a phishing email incident. It covers the process of analyzing email headers, extracting Indicators of Compromise (IOCs), and documenting the incident timeline and remediation steps.

## Tools and Resources Used
- VirusTotal (for file and URL analysis)  
- Email Header Analyzer (online tools)  
- MITRE ATT&CK Framework  
- Public phishing email samples  

## Incident Description
A simulated phishing email was received by an employee, containing a malicious link designed to steal credentials. The goal was to investigate the email, identify the threat, and recommend mitigation.

## Investigation Steps
1. Analyzed the email headers to identify the sender and routing path.  
2. Extracted URLs and attachments for further analysis.  
3. Submitted URLs and attachments to VirusTotal for reputation and behavior analysis.  
4. Mapped discovered tactics to the MITRE ATT&CK framework.  
5. Documented indicators such as IP addresses, domains, and email addresses involved.

## Findings
- The phishing email originated from a suspicious domain with low reputation.  
- The attachment was identified as a malicious macro-enabled document.  
- URLs led to credential phishing websites designed to harvest user login information.

## MITRE ATT&CK Mapping
- Initial Access: Phishing (T1566)  
- Execution: Malicious Macro (T1204.002)  
- Credential Access: Phishing for Credentials (T1566.001)

## Remediation and Recommendations
- Blocked sender domain and IP addresses at the firewall.  
- Informed employees about the phishing attempt through awareness training.  
- Implemented email filtering rules to flag similar phishing emails.  
- Enabled multi-factor authentication (MFA) to protect user accounts.

## Lessons Learned
This exercise highlighted the importance of proactive email filtering, employee awareness, and rapid incident response procedures in mitigating phishing attacks.
