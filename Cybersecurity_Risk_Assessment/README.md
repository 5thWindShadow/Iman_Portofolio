# Practical Study Case Example
### Disclaimer : This is a dummy project, the situations (Scenario) are generated by AI for Training Purposes.

## Scenario: DigDeep Mining Corp.
Company Profile
* Name: DigDeep Mining Corp.
* Industry: Mining (Copper & Zinc exploration and extraction).
* Size: Small-to-Medium Business (SMB) - approx. 80 employees.

Locations:
* Head Office (HQ): Located in a regional city. Houses management, finance, geology data analysis, HR, and basic IT support (2 people).
* Mine Site: A remote site approx. 200km from HQ. Includes extraction operations, basic on-site management, and equipment maintenance crew.

**Business Goal**: Efficiently extract minerals and manage geological survey data, which is highly valuable intellectual property.

**Security Goal**: The CEO recently heard about ransomware attacks on similar companies and wants a basic understanding of DigDeep's information security risks. They aren't certified for anything yet but might consider ISO 27001 in the future if it makes sense.

Technology & Operations:
* Network: Standard office network at HQ (wired & WiFi). The Mine Site has limited connectivity back to HQ via a microwave link, which can be unreliable in bad weather. Internet access at HQ is standard broadband; Mine Site internet is slow satellite backup.
* Servers:
  * One main file server at HQ storing geological data, financial reports, and operational documents.
  * One email server (hosted internally at HQ).
  * Basic web server hosting the company website (hosted externally).
* User Devices: Mix of Windows desktops (HQ finance/admin) and laptops (geologists, management, some site staff).
* Data:
  * Highly Sensitive: Detailed Geological Survey Maps and Analysis Data (critical IP).
  * Sensitive: Employee Records (HR), Financial Data, Contracts.
  * Operational: Daily production logs (sent from Mine Site to HQ), maintenance schedules.
  
* Current Security Measures (Known Issues/Hints):
  * A basic firewall is installed at the HQ internet gateway.
  * Standard antivirus software is installed on most company machines, but updates are sometimes missed.
  * Password policy exists (8 characters, mix of types) but isn't strictly enforced, and users complain it's inconvenient.
  * Data backups for the main file server are performed weekly to external hard drives stored in the server room closet at HQ. No regular offsite backups.
  * There is no formal security awareness training for employees.
  * Physical access to the HQ server room is a standard locked door; the key is held by IT and office manager. Access logs are not kept. Physical security at the Mine Site is more focused on safety than information security.
  * Geologists sometimes need remote access to the file server from exploration sites; they use a VPN set up by the IT team, but documentation on its configuration is sparse.
  * The small IT team is overwhelmed with daily tasks and struggles to keep up with patching and security configurations.

## Risk Assessment
### 1. Scope and Objectives
Assets Scope : The scope include IT infrastructure in HQ(Main Server, Email Server, Users Endpoints) and its network components(Wifi), Web server that hosted externally, Mine site network component like Sattelite for internet(exclude Microwave Link).
Objective : Conduct an Security Risk Assessment to identify vulnerabilities, prioritize risks, and develop mitigation strategies to imrpove security postures.

### 2. Identify Assets
Assets Inventory
* Network : HQ Wifi, Sattelite for Internet (Mine Site)
* Servers : HQ Main Data Server, HQ Email Server, Web Server (External)
* User Devices : Users Desktops (Mix Windows Version), Laptops (geologists, management, some site staff)
* Data : Sensitive Data (Geological Survey Maps, Analysis Data, Employee Records, Financial Data, Contracts) and Operational Data (Daily production logs, Maintenance Schedules)

### 3. Identify Vulnerabilities and Threats
| Asset | Threat | Vulnerability |
| ----- | -------- | ------------- |
| Web Server | System Compromise, Web Defacement | Security Misconfiguration |
| User Endpoints | Unathourized Access | Weak Password |
| Employee | Phishing | no formal security awareness training |
| Main Server | Unathourized Access, Malicious Employee | Weak physical access control (standard lock, uncontrolled key access) |
| Main Server | Malware | Poor Patch Management |
| Main Server | Data Loss, System Failure, Disaster, Ransomware | Weak Backups Regulation |

### 4. Assess Risk
Tools : OWASP Risk Rating Calculator

Likelihood Factors
* Threat Agent Factors (TAF) : Skill Level (SL), Motive (M), Opportunity (O), Size (S)
* Vulnerability Factors (VF) : Ease of Discovery (ED), Ease of Exploit (EE), Awareness (A), Intrusion Detection (ID)

Impact Factors
* Technical Impact Factors (TIF) : Loss of confidentiality (LC), Loss of Integrity (LI), Loss of Availability (LAV), Loss of accountability (LAC)
* Business Impact Factors (BIF) : Financial Damage (FD), Reputation Damage (RD), Non-Compliance (NC), Privacy Violation (PV)

| Threat | Vulnerability | Likelihood Factor (LF) | Impact Factor (IF) | Overall Risk Severity | Score Vector |
| -------- | ------------- | -------------------- | ------------------- | --------------------| ------------------|
| System Compromise, Web Defacement | Security Misconfiguration | 6.125 | 2.75 | Medium | SL:6/M:3/O:9/S:9/ED:7/EE:5/A:7/ID:3/LC:1/LI:3/LAV:7/LAC:3/FD:1/RD:7/NC:2/PV:1 |
| Unathourized Access | Weak Password | 5.375 | 6.75 | High |SL:6/M:6/O:7/S:7/ED:1/EE:3/A:4/ID:9/LC:9/LI:5/LAV:5/LAC:5/FD:6/RD:9/NC:7/PV:5 |
| Phishing | No formal security awareness training | 7.25 | 6.5 | Critical | SL:6/M:9/O:9/S:9/ED:7/EE:3/A:6/ID:9/LC:7/LI:7/LAV:9/LAC:7/FD:7/RD:5/NC:9/PV:5 |
| Unathourized Access, Malicious Employee | Weak physical access control (standard lock, uncontrolled key access) | 5 | 6.75 | High | SL:3/M:9/O:4/S:5/ED:3/EE:3/A:4/ID:9/LC:9/LI:9/LAV:9/LAC:5/FD:7/RD:9/NC:7/PV:4 |
| Malware | Poor Patch Management | 5.25 | 5 | Medium | SL:1/M:9/O:7/S:9/ED:3/EE:4/A:6/ID:3/LC:7/LI:7/LAV:5/LAC:7/FD:5/RD:5/NC:5/PV:5 |
| Data Loss, System Failure, Disaster, Ransomware | Weak Backups Regulation | 6.25 | 7 | Critical | SL:1/M:9/O:9/S:9/ED:3/EE:5/A:6/ID:8/LC:9/LI:9/LAV:9/LAC:7/FD:7/RD:9/NC:7/PV:5 |

### 5. Evaluate and Prioritize Risks



