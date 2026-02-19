# Risk-Register-Spooky
Hospital Patient Record System – Risk Register Project
1. Project Overview
The Hospital Patient Record System (HPRS) stores sensitive patient data and is critical to hospital operations. This project documents a comprehensive risk registers to identify, assess, and mitigate cybersecurity and operational risks. The risk register helps the organization manage threats such as data breaches, ransomware, insider threats, and system misconfigurations, ensuring confidentiality, integrity, and availability (CIA) of patient records.
Objectives:
•	Identify potential threats and vulnerabilities affecting hospital systems.
•	Assign risk levels and categorize them by impact and likelihood.
•	Map risks to security domains and mitigation strategies.
•	Support compliance with healthcare cybersecurity frameworks (e.g., NIST CSF, CIS Controls, HIPAA).
2. Risk Assessment Methodology
Impact × Likelihood Model:
•	Impact Level (Severity of Effect): Negligible → Critical (1–5)
•	Likelihood Level (Probability of Occurrence): Rare → Almost Certain (1–5)
•	Risk Rating = Impact × Likelihood
Risk Level Classification:
Risk Rating	Risk Level
1 – 5	Low
6 – 10	Medium
11 – 20	High
16 – 25	Extreme


Risk Response Strategies:
•	Mitigate: Reduce the likelihood or impact of risk.
•	Transfer: Share risk with a third party (insurance, cloud vendor).
•	Accept: Acknowledge risk without immediate action.
•	Escalate: Raise to higher management for action.
•	Monitor: Track the risk periodically.

3. Security Domain Mapping
The risks are mapped to standard frameworks to align with industry best practices:
Security Domain	Framework Mapping
Identity and Access Control	NIST PR.AC
Network	NIST PR.PT / DE.CM
Cloud / SaaS	NIST PR.IP / PR.DS
Endpoint	NIST PR.MA / PR.IP
Physical Security	NIST PE.FS
Policy / Governance	NIST ID.GV / PR.IP

4. Risk Categories
Risk Category	Description
Phishing / Social Engineering	Risks targeting staff to obtain credentials or sensitive info.
Malware / Ransomware	Malicious software attacks leading to data encryption or system disruption.
System Misconfiguration	Errors in configuration of systems, networks, or apps that can be exploited.
Third-Party Risk	Vendor or partner-related risks, including stolen credentials or insecure APIs.
Data Breach	Exposure of sensitive patient or hospital data.
Denial of Service	Attacks disrupting access to critical hospital systems.
Insider Threat	Malicious or accidental actions by staff that compromise systems or data.
Access Control Failure	Weak identity management, orphaned accounts, or weak passwords.
Policy / Governance	Risks from insufficient policies, controls, or training.
________________________________________
5. Risk Register Sample
Below is a truncated example from the full register for clarity. Full register includes 25+ risks.
Ref ID	Risk Title	Impact	Likelihood	Risk Rating	Risk Level	Category	Security Domain	Owner	Response	Mitigation Notes	Status	Date Identified	Next Review
CR001	Phishing Email to Staff	4	4	16	Extreme	Phishing / Social Engineering	Identity & Access Control	Rendle Bent	Mitigate	Add phishing simulation program	Mitigation In Progress	08-01-25	11-01-25
CR002	Ransomware on Shared Drive	5	3	15	High	Malware / Ransomware	Endpoint	Shane Jayne	Transfer	Evaluate cyber insurance policy	Open	08-05-25	11-05-25
CR006	Rogue Wi-Fi on Job Site	3	3	9	Medium	Insider Threat	Network	Lisa Perez	Accept	Monitor with wireless IDS	In Review	08-19-25	11-19-25
Note: The full register includes all 25 risks with dates, owners, categories, mitigation notes, and next review dates.

6. Mitigation & Controls Mapping
Risk	Mitigation	Security Domain	Framework Control
Phishing Email to Staff	Phishing simulations, staff training	Identity & Access Control	NIST PR.AC-5
Ransomware	Endpoint protection, backups, cyber insurance	Endpoint	NIST PR.MA-1 / PR.IP-4
Stolen Contractor Credentials	Hardware MFA tokens	Identity & Access Control	NIST PR.AC-1
Open S3 Bucket Exposed	Enable encryption & bucket policies	Cloud / SaaS	NIST PR.DS-1 / PR.IP-3
DDoS Threat	WAF, rate limiting, cloud mitigation	Network	NIST DE.CM-7

7. Policies & Procedures
•	Access Control Policy: Strong password policies, MFA, least privilege.
•	Incident Response Policy: Documented steps for malware, phishing, or breach.
•	Vendor Management Policy: Assess third-party security before integration.
•	Data Protection Policy: Encryption at rest and in transit, audit logging.
•	Backup & Recovery Policy: Regular backups with tested restore procedures.
•	Staff Training Policy: Annual cybersecurity awareness and phishing simulations.

8. Review & Maintenance
•	Review Frequency: Quarterly for high/extreme risks, semi-annually for medium, annually for low.
•	Ownership: Each risk has an assigned owner responsible for tracking and mitigation.
•	Escalation: Critical and extreme risks reported to hospital IT leadership and compliance officers.

9. Visual Aids (Optional Images for PDF)
Mitigation Mapping Diagram: Linking risk categories to NIST CSF controls.
Phishing / Social Engineering
     ↓
Mitigation: Training, Simulation, DMARC
     ↓
Security Domain: Identity & Access Control
     ↓
NIST CSF: PR.AC-5

Malware / Ransomware
     ↓
Mitigation: Endpoint protection, backups, cyber insurance
     ↓
Security Domain: Endpoint / Network
     ↓
NIST CSF: PR.MA-1 / PR.IP-4

System Misconfiguration
     ↓
Mitigation: Patch, firewall review, TLS upgrade
     ↓
Security Domain: Network / App / Endpoint
     ↓
NIST CSF: PR.PT-1 / PR.IP-3

Third-Party Risk
     ↓
Mitigation: MFA, API Gateway, Vendor assessment
     ↓
Security Domain: Identity & Access / Cloud
     ↓
NIST CSF: PR.AC-1 / PR.DS-1


Risk Category	Mitigation Measures	Security Domain	NIST CSF Controls	Suggested Risk Level
Phishing / Social Engineering	Staff Training, Phishing Simulations	Identity & Access Control	PR.AC-1, PR.AC-4, PR.AC-5	High (Red)
Malware / Ransomware	Endpoint Protection, Backups, Anti-virus	Endpoint	PR.MA-1, PR.IP-3	High (Red)
System Misconfiguration	Patch Management, Configuration Reviews	Network / Application / Endpoint	PR.IP-4, PR.PT-1	High (Red)
Third-Party Risk	MFA for Vendors, Contractual SLAs, API Gateway	Identity & Access Control / Cloud	PR.AC-5, PR.DS-1	High (Red)
Data Breach	Encryption, Access Controls, Data Loss Prevention	Cloud / SaaS / Application	PR.DS-1, PR.IP-4	High (Red)
Denial of Service	DDoS Protection, Rate Limiting	Network / Application	DE.CM-7, PR.PT-1	Medium (Yellow)
Insider Threat	Password Policies, Access Reviews, MFA	Identity & Access Control / Policy	PR.AC-1, PR.AC-4	Medium (Yellow)
Access Control Failure	Role-Based Access, Account Deprovisioning	Identity & Access Control	PR.AC-1, PR.AC-4, PR.AC-5	Medium (Yellow)

Use Miro.ai



Workflow Diagram: Risk Management Process
Flow (left → right):
1.	Risk Identification
o	Activities:
	Identify assets (patient records, servers, endpoints)
	Detect threats (phishing, ransomware, insider threats)
	Document vulnerabilities
o	Output: Risk Register Draft
2.	Risk Assessment
o	Activities:
	Determine Impact Level (Negligible → Critical)
	Determine Likelihood Level (Rare → Almost Certain)
	Calculate Risk Rating (Impact × Likelihood)
	Assign Risk Category (Data Breach, Malware, Insider, etc.)
o	Output: Prioritized Risk List
3.	Risk Mitigation
o	Activities:
	Define Risk Response Strategy (Mitigate, Transfer, Accept, Escalate, Monitor)
	Implement technical, policy, or procedural controls
	Map mitigations to Security Domain & NIST CSF
o	Output: Mitigated Risk Register
4.	Risk Review & Monitoring
o	Activities:
	Track Status (Open, In Review, Mitigated, Closed, Transferred)
	Schedule Next Review Dates
	Update Risk Register with residual risk and lessons learned
o	Output: Updated Risk Register, Reports to Management


 
Phishing Attack Incident Response Playbook
Organization: Hospital Patient Record System (HPRS)
Document Owner: Security Operations Center (SOC)
Version: 1.0
Last Updated: 11/18/2024
Classification: Internal Use Only

1. Purpose
This playbook provides standardized procedures for detecting, analyzing, containing, eradicating, and recovering from phishing-related incidents. It ensures a consistent, timely, and effective response to protect patient data, user credentials, and critical hospital systems.

2. Scope
This playbook applies to:
•	All hospital employees and contractors
•	Email systems and collaboration platforms
•	Endpoints (workstations, laptops, mobile devices)
•	Identity and Access Management systems
•	Cloud-based applications and SaaS platforms
3. Definition of a Phishing Incident
A phishing incident occurs when:
•	A user receives a malicious email attempting to steal credentials or sensitive data
•	A user clicks a malicious link or opens a malicious attachment
•	Unauthorized account access is detected due to credential compromise
•	Business Email Compromise (BEC) is suspected

4. Roles and Responsibilities
SOC Analyst (Tier 1)
•	Monitor alerts
•	Triage reported phishing emails
•	Initiate containment steps
SOC Analyst (Tier 2)
•	Conduct forensic analysis
•	Identify Indicators of Compromise (IOCs)
•	Escalate if data exposure suspected
IT Operations
•	Reset passwords
•	Isolate affected endpoints
•	Remove malicious emails from mailboxes
Risk & Compliance Team
•	Assess regulatory impact
•	Notify management and legal if required
CISO / Security Manager
•	Approve escalation
•	Communicate with executive leadership

5. Incident Severity Classification
Severity	Description
Low	Phishing email received but not clicked
Medium	User clicked link but no credential entry
High	Credentials submitted or malware executed
Critical	Confirmed account takeover or data exfiltration

6. Incident Response Phases
Phase 1: Detection & Identification
Triggers
•	Email security gateway alert
•	User report to SOC
•	SIEM alert for suspicious login
•	Abnormal authentication activity
Actions
•	Collect email headers
•	Analyze sender domain
•	Check URL reputation
•	Identify impacted users
•	Document incident in ticketing system
Deliverable: Incident Ticket Created

Phase 2: Containment
Immediate Containment Actions
If link clicked but no credentials entered:
•	Block sender domain
•	Delete malicious email from all inboxes
If credentials entered:
•	Force password reset immediately
•	Invalidate active sessions
•	Enable/verify MFA
•	Check for suspicious login activity
If malware executed:
•	Isolate affected endpoint
•	Disable network access
•	Initiate malware scan
Deliverable: Threat Contained

Phase 3: Eradication
•	Remove malicious email from mail server
•	Block malicious URLs and domains at firewall/DNS
•	Remove persistence mechanisms
•	Patch exploited vulnerabilities
•	Verify endpoint clean state
Deliverable: Malicious items removed

Phase 4: Recovery
•	Restore affected accounts
•	Reinstate device network access (if safe)
•	Monitor account for abnormal behavior (7–14 days)
•	Confirm no unauthorized access to patient records
Deliverable: System returned to operational state

Phase 5: Post-Incident Activities
Root Cause Analysis
•	How was email delivered?
•	Why was it not blocked?
•	Was training ineffective?
Documentation
•	Timeline of events
•	Impact assessment
•	Mitigation steps
•	Lessons learned
Reporting
•	Notify compliance team if PHI involved
•	Determine regulatory reporting obligations
•	Provide executive summary to leadership
Deliverable: Final Incident Report

7. Indicators of Compromise (IOCs)
•	Suspicious sender domain
•	Lookalike domains
•	Failed login attempts followed by successful login
•	Unusual login geography
•	Unexpected MFA prompts
•	Mass email forwarding rules created

8. Required Tools
•	Email Security Gateway
•	SIEM platform
•	Endpoint Detection & Response (EDR)
•	Threat Intelligence feeds
•	Identity & Access Management system

9. Communication Plan
 
Internal
•	SOC → IT Operations
•	SOC → Security Manager
•	Security Manager → Executive Team (if High/Critical)
External (if required)
•	Legal counsel
•	Regulatory bodies
•	Cyber insurance provider
 
10. Metrics & KPIs
Track for continuous improvement:
•	Mean Time to Detect (MTTD)
•	Mean Time to Respond (MTTR)
•	Percentage of users reporting phishing
•	Click rate during phishing simulations
•	Recurring targeted users
11. Preventive Controls
•	Mandatory annual phishing awareness training
•	Quarterly phishing simulations
•	Enforced Multi-Factor Authentication (MFA)
•	Email authentication (SPF, DKIM, DMARC)
•	Least privilege access model
•	Conditional access policies

12. Playbook Review Cycle
•	Reviewed quarterly
•	Updated after every major phishing incident
•	Approved by Security Governance Committee
13. Appendix
Timeline 
Time	Action	Owner
09:05	Phishing email reported	User
09:10	Ticket created	SOC Tier 1
09:20	Domain blocked	SOC Tier 2
09:35	Password reset	IT Ops
11:00	Incident closed	SOC Lead

