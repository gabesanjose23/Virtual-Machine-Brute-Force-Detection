# Virtual Machine Brute Force Detection


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Sentinel

##  Scenario

When entities (local or remote users, usually) attempt to log into a virtual machine, a log will be created on the local machine and then forwarded to Microsoft Defender for Endpoint under the DeviceLogonEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when the same entity fails to log into the same VM a given number of times within a certain time period. (i.e. 10 failed logons or more per 5 hours). 

---

## Steps Taken

### Part 1: Create Alert Rule Brute Force Attempt Detection

Here I am setting up the rules to detect if there were a excessive amount of login failed attempt.


<img width="1212" alt="image" src="Screenshot 2025-03-22 161239.png">

<img width="1212" alt="image" src="Screenshot 2025-03-22 161602.png">

---

### 2. Investigate and find out if anyone has attempted to login into the machine

Next the rules that I put in place are alerted.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName, ActionType
| where EventCount >= 10
| order by EventCount
```
<img width="1212" alt="image" src="Screenshot 2025-03-22 162815.png">

<img width="1212" alt="image" src="Screenshot 2025-03-22 160732.png">

<img width="1212" alt="image" src="Screenshot 2025-03-22 163912.png">

---

### 3. Check if any of the bad actor where able to login

The top 10 most failed login attempts IP addresses have not been able to successfully break into the VM

**Query used to locate events:**

```kql
let RemoteIPsInQuestion = dynamic(["128.1.44.9", "178.20.129.235", "83.118.125.238", "106.246.239.179", "85.215.149.156", "146.196.63.17", "89.232.41.74", "190.5.100.193", "178.176.229.228"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 143007.png">

---

### 4. Check who dose have access to the account

The only successful remote/network logons in the last 7 days was for the ‘labuser’ account (6 total)

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType =="Network"
| where ActionType == "LogonSuccess"
|where DeviceName =="windows-target-1"
|where AccountName == ”labuser”
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 145153.png">

---
### 5. Check if labuser has any suspicious failed login attemps 

There were (0) failed logons for the ‘labuser’ account,indicating that a brute force attempts for this account didn’t take place,and a 1-time password guess is unlikely.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType =="Network"
| where ActionType == "LogonFailed"
|where DeviceName =="windows-target-1"
|where AccountName == "labuser"
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 145659.png">

---

### 6. Check if the location from which is being logon from is normal

We checked all of the successful login IP addresses for the “labuser” account to see if any of them were unusual or from an unexpected location,All were normal.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType =="Network"
| where ActionType == "LogonSuccess" 
|where DeviceName =="windows-target-1"
|where AccountName == "labuser"
| summarize loginCount = count() by DeviceName,ActionType,AccountName,RemoteIP
```
<img width="1212" alt="image" src="Screenshot 2025-03-10 150405.png">

---

## Summary

Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account “labuser”.


MITRE ATT&CK - T1087: Account Discovery 

MITRE ATT&CK - T1110: Brute Force

---

## Response Action

--Hardened the NSG attached to “windows-target-1” to allow only RDP traffic from specific end-points(no public internet access)

--Implemented account lockout policy

--Implement MFA


---
