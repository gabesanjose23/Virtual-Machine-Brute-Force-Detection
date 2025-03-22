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

### 3. Investigate the Machines 

Three different virtual machines were potentially impacted by brute force attempts from 4 different public IP:

## Details of Failed Logon Attempts

| **IP Address**       | **Hostname**                                              | **Status**      | **Failed Attempts** |
|----------------------|----------------------------------------------------------|----------------|--------------------|
| 170.64.155.135       | linux-programmatic-fix-tau.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net | LogonFailed    | 63                 |
| 112.135.212.148      | sa-mde-test-2                                             | LogonFailed    | 58                 |
| 158.101.242.63       | sa-mde-test-2                                             | LogonFailed    | 40                 |
| 185.151.86.130       | ir-sentinel-moa                                           | LogonFailed    | 40                 |


---

### 4. Containment:Isolated Devices
I isolated the Devices using MDE then I Ran anti-malware scan on all four devices within MDE.I check to see if any of the IP addresses attempting to brute force successfully logged in with the following query,but none were successful:

**Query used to locate events:**

```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP in ("170.64.155.135", "112.135.212.148", "185.151.86.130", "158.101.242.63")
```
<img width="1212" alt="image" src="Screenshot 2025-03-22 164528.png">

---

## Summary

<img width="1212" alt="image" src="Screenshot 2025-03-22 165905.png">


MITRE ATT&CK - T1087: Account Discovery 

MITRE ATT&CK - T1110: Brute Force

---

## Response Action

NSG was locked down to prevent RDP attempts from the public internet. Policy was proposed to require this for all VMs going forward.Additionally I set a rule only allowing my home IP address.(Alternatively we can use bastion host) 

<img width="1212" alt="image" src="Screenshot 2025-03-22 165025.png">

---
