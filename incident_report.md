### **Incident Summary**



On a controlled lab network (10.10.10.0/24), a simulated brute-force attack was conducted from a Kali Linux host against a Windows 11 Enterprise system. The attack generated multiple failed authentication attempts which were detected successfully using Splunk.



The objective was to validate detection logic for brute-force activity using Windows Security Event Logs.



#### **Event Timeline**



|Time(Lab)|Event|
|-|-|
|02/23/2026 06:14:54.421 PM|Hydra initiated from 10.10.10.5|
|02/23/2026 06:14:54.432 PM|First Failed Authentication Observed|
|02/23/2026 06:14:54.481 PM|Fifth Failed Authentication Attempt Observed|
|02/23/2026 06:14:54.748 PM|Detection Threshold Triggered|

#### 

**Affected Systems**



|System|Role|IP Address|
|-|-|-|
|Kali Linux VM|Attacker|10.10.10.5|
|Windows 11 Enterprise VM|Target|10.10.10.10|

 

Network: Lab Network 10.10.10.0/24 (VirtualBox Internal Network, fully isolated)



#### **Detection Details**



###### Log Source



Windows Security Event Log



###### Relevant Event ID



* 4625 (An account failed to log on)



###### Notable Fields Observed



|**Field**|**Value**|
|-|-|
|Logon Type|3 (Network)|
|Authentication Package|NTLM|
|Source Network Address|10.10.10.5|
|Target Account|testuser|
|Failure Status|0xC000006D|
|Sub status|0xC000006A (Bad password)|

#### 

**Detection Logic**



###### Threshold-Based Detection Query



index=wineventlog EventCode=4625

| stats count by Source\_Network\_Address, Account\_Name

| where count > 5

| sort -count



This query finds instances where there are more than five failed authentication attempts for an account from a single IP address.



###### Time-Window Detection Query (1 Minute)



index=wineventlog EventCode=4625

| bin \_time span=1m

| stats count by \_time, Source\_Network\_Address, Account\_Name

| where count > 5



This query finds instances where there are more than five failed authentication attempts within one minute by a single IP address.



#### **Analysis**



* Multiple failed login attempts from a single IP address (10.10.10.5)
* Authentication Attempts used NTLM over a network logon (Type 3)
* No successful logon events were observed (ID 4624)
* Pattern is consistent with brute-force credential attack behavior.



#### **MITRE ATT\&CK Mapping**



* Tactic: Credential Access
* Technique - T1110 brute-force



This detection aligns with identifying repeated authentication failures, suggesting password guessing activity.



#### **Impact Assessment**



Since this attack was conducted in a controlled lab environment, no production systems were affected, no account compromise occurred, and no lateral movement was observed. If detected in a real-world network environment, brute-force attack telemetry by itself would be classified as a medium-severity threat, whereas if it were followed by a successful authentication, then it would elevate to high-severity.



#### **Recommended Response (In Real SOC Environment)**



1. Identify and validate source IP reputation
2. Determine whether account lockout policy was triggered
3. Check if any successful logins events were detected (ID 4624)
4. Reset credentials for any compromised accounts
5. Review exposure of RDP/network services
6. Consider adding source IP to firewall block list



#### **Lessons Learned**



* Correctly managing audit policy configuration is crucial for detection visibility.
* Detection based on unique attack indicators reduces false positives.
* Network segmentation isolates lab activity and prevents interfering with production systems.
* Effective detection engineering requires a combination of telemetry validation and contextual analysis.
