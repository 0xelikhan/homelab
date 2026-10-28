# SOC and honeypot in Microsoft Azure

![SOC architecture](https://github.com/user-attachments/assets/aadd2f1a-4ab0-4cac-8c85-c942e5c91702)

A Windows 10 VM in Azure run as a honeypot, exposed to the internet, with Microsoft Sentinel, a Log Analytics workspace and KQL collecting and investigating the login attempts it attracted. The steps below are the build, then what the data showed after an hour, a day and a week.

## Tech used

- Microsoft Azure — hosts the VM and the SOC tooling.
- Windows 10 VM — the honeypot.
- Network Security Group — set to allow all inbound, so the VM is fully exposed.
- Log Analytics workspace — collects events from the VM and Sentinel.
- Microsoft Sentinel — SIEM for detection, investigation and alerting.
- KQL — detection rules and attacker-activity queries.

## Contents

1. [Set up an Azure subscription](#1-set-up-an-azure-subscription)
2. [Create a resource group](#2-create-a-resource-group)
3. [Create a virtual network](#3-create-a-virtual-network)
4. [Create a virtual machine](#4-create-a-virtual-machine)
5. [Create the honeypot](#5-create-the-honeypot)
6. [Validate honeypot exposure](#6-validate-honeypot-exposure)
7. [Create a Log Analytics workspace](#7-create-a-log-analytics-workspace)
8. [Enable Microsoft Sentinel](#8-enable-microsoft-sentinel)
9. [Results after 1 hour](#9-results-after-1-hour)
10. [Log enrichment in Sentinel](#10-log-enrichment-in-sentinel)
11. [Build a map workbook](#11-build-a-map-workbook)
12. [Results after 24 hours](#12-results-after-24-hours)
13. [Top 5 countries](#13-top-5-countries)
14. [Top 10 attacker IPs](#14-top-10-attacker-ips)
15. [Failed-logon timeline](#15-failed-logon-timeline)
16. [Create a detection rule](#16-create-a-detection-rule)
17. [Incident response](#17-incident-response)
18. [Results after 1 week](#18-results-after-1-week)

---

## 1. Set up an Azure subscription

Create a free Azure subscription at [azure.microsoft.com](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account).

<img width="1594" height="677" alt="Lab 1" src="https://github.com/user-attachments/assets/943202f4-4ee4-4bdc-817c-5071ae21f0e5" />

<img width="1314" height="488" alt="Lab 2" src="https://github.com/user-attachments/assets/e2857ac0-8dcd-4699-b139-2181c4e4859d" />

You have to provide valid payment information at sign-up, but you will not be charged. Once the subscription exists, log in at [portal.azure.com](https://portal.azure.com).

---

## 2. Create a resource group

In the portal, search for Resource Groups and create one:

```
Subscription: Azure Subscription 1
Resource Group Name: RG-lab
Region: (US) East US 2
```

<img width="626" height="279" alt="Resource group" src="https://github.com/user-attachments/assets/e879227c-64d5-4437-8d15-4df415684957" />

---

## 3. Create a virtual network

Search for Virtual Network and create one in the same resource group:

```
Subscription: Azure Subscription 1
Resource Group: RG-lab
Virtual Network Name: vnet-lab
Region: (US) East US 2
```

<img width="626" height="279" alt="Virtual network" src="https://github.com/user-attachments/assets/3ad66e12-4e04-4654-b7cf-7f832f85da22" />

---

## 4. Create a virtual machine

Search for Virtual Machines and create a new one.

<img width="433" height="599" alt="Create VM" src="https://github.com/user-attachments/assets/f3e8dc4d-470a-4d60-9012-ee34b574ed68" />

Settings I used:

```
Project
  Subscription: Azure Subscription 1
  Resource Group: RG-lab
Instance
  Name: CORP-NET-EAST
  Region: (US) East US 2
  Image: Windows 10 Pro, 22H2 - x64 Gen2
  Size: Standard_B1s (1 vCPU, 1 GiB RAM)
Administrator account: your own username and password
Licensing: confirm an eligible Windows 10/11 license

Disks
  OS Disk Type: Standard HDD

Networking
  Virtual Network: Create new
  Subnet: Default
  Public IP: new
  NIC NSG: Basic
  Delete public IP and NIC when VM is deleted: yes

Monitoring
  Boot Diagnostics: disable
```

---

## 5. Create the honeypot

Open the VM's Network Settings (Networking > Network Settings).

Delete the default RDP inbound rule:

<img width="2196" height="402" alt="Delete RDP rule" src="https://github.com/user-attachments/assets/7dd7b6d6-ca5d-487c-a7c0-4608d753a10a" />

Add an inbound rule that allows everything:

```
Source: Any
Source Port Ranges: *
Destination: *
Service: Custom
Destination Port Ranges: *
Protocol: Any
Action: Allow
Priority: 300
Name: DANGER_AllowAnyCustomAnyInbound
```

Log into the VM with Remote Desktop using its public IP (Overview > Public IP Address) and the username and password from step 4.

<img width="405" height="248" alt="Public IP" src="https://github.com/user-attachments/assets/747f1402-0f15-4f73-ace8-cfc2f558e4d7" />

Turn off Windows Defender Firewall (`Win + R` > `wf.msc`):

<img width="1041" height="779" alt="Firewall off" src="https://github.com/user-attachments/assets/0562dc50-79da-4c5e-b018-1fff70469493" />

---

## 6. Validate honeypot exposure

Ping the VM's public IP from your local machine, then simulate brute-force attempts: log out and back in with a wrong username and password.

<img width="451" height="414" alt="Failed login" src="https://github.com/user-attachments/assets/810de6dd-94ff-41ce-9b70-9f0623a5486e" />

Back on the VM, check Event Viewer (`Win + R` > `eventvwr.msc` > Windows Logs > Security):

<img width="907" height="381" alt="Event Viewer" src="https://github.com/user-attachments/assets/c7d293e9-db4b-4623-8bb1-454948581740" />

Event ID `4625` is a failed logon. Here a user named `employee` tried to log in — the honeypot is live.

---

## 7. Create a Log Analytics workspace

Search for Log Analytics Workspaces and create one:

```
Subscription: Azure Subscription 1
Resource Group: RG-lab
Name: LAW-lab
Region: (US) East US 2
```

<img width="626" height="279" alt="Log Analytics workspace" src="https://github.com/user-attachments/assets/90014f16-a3ad-4234-b7d7-5ebcca19d05a" />

---

## 8. Enable Microsoft Sentinel

Search for Microsoft Sentinel, select the Log Analytics workspace, and add it.

<img width="1173" height="124" alt="Add workspace to Sentinel" src="https://github.com/user-attachments/assets/e41d901e-57a8-4bfa-8406-a226fb2f9faa" />

Install Windows Security Events from the Content Hub (search "Security Event"):

<img width="1634" height="984" alt="Windows Security Events" src="https://github.com/user-attachments/assets/763c4d83-7054-4995-9816-1663209543b5" />

Open the connector (Windows Security Events via AMA > Open Connector Page) and create a Data Collection Rule:

```
Rule Name: DC-lab
Subscription: Azure Subscription 1
Resource Group: RG-lab
Resources: Azure Subscription 1 > RG-lab > the VM
Collect: All Security Events
```

Check that the `AzureMonitorWindowsAgent` extension is installed on the VM (VM > Settings > Extensions + Applications). Logs from the honeypot now flow into the Log Analytics workspace.

---

## 9. Results after 1 hour

Failed logons (`Event ID 4625`) in the hour from 07:46 to 08:46 UTC on 2025-07-21:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T07:46:00Z) .. datetime(2025-07-21T08:46:00Z))
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| sort by TimeGenerated asc
```

In the first hour, 94 failed logins came from three IPs: `x.x.x.x`, `91.238.181.94` and `80.94.95.75`.

---

## 10. Log enrichment in Sentinel

In Sentinel, select the Log Analytics workspace and create a watchlist (Configuration > Watchlist > + New):

```
Name / Alias: geoip
Source: geoip-summarized (Excel)
SearchKey: Network
```

<img width="784" height="364" alt="Watchlist" src="https://github.com/user-attachments/assets/45e08b88-0185-4323-a390-fe52dd31dc62" />

Failed logons from one IP, enriched with GeoIP (city, country, coordinates):

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "x.x.x.x"
    | where EventID == 4625
    | order by TimeGenerated desc;
WindowsEvents
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude
```

---

## 11. Build a map workbook

In Sentinel, add a workbook (Threat Management > Workbooks > + Add Workbook), edit it, remove the prepopulated content, and add a query. On the Advanced Editor tab, paste this and click Done Editing:

```json
{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}
```

The query it runs:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

Saved as `Windows VM Attack Map` in the resource group.

---

## 12. Results after 24 hours

Failed logons over the 24 hours from 2025-07-21 07:46 UTC — 107,836:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T07:46:00Z) .. datetime(2025-07-22T07:46:00Z))
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| count
```

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

<img width="1936" height="837" alt="24-hour map" src="https://github.com/user-attachments/assets/412ec00c-824c-4a4f-8d10-ae2ad22e8469" />

---

## 13. Top 5 countries

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| where isnotempty(countryname);
let Top5Countries = 
    WindowsEvents
    | summarize FailureCount = count() by countryname
    | top 5 by FailureCount desc
    | project countryname;
WindowsEvents
| where countryname in (Top5Countries)
| summarize FailureCount = count(),
          latitude = any(latitude),
          longitude = any(longitude),
          city = any(cityname)
    by countryname
| extend friendly_location = strcat(city, " (", countryname, ")")
| project countryname, FailureCount, latitude, longitude, friendly_location
```

<img width="1571" height="829" alt="Top 5 countries" src="https://github.com/user-attachments/assets/44226dea-0a42-4563-926e-5b7fbf632376" />

---

## 14. Top 10 attacker IPs

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by AttackerIp = IpAddress
| sort by FailedAttempts desc
```

<img width="364" height="424" alt="Top 10 IPs" src="https://github.com/user-attachments/assets/321bb612-079a-46da-90d3-887b46d48414" />

---

## 15. Failed-logon timeline

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| render columnchart
```

<img width="1951" height="739" alt="Timeline" src="https://github.com/user-attachments/assets/195ef539-1f7e-4bb9-8289-170fd21db8ec" />

<img width="1951" height="735" alt="Timeline detail" src="https://github.com/user-attachments/assets/50138024-90df-48dc-82f5-e0c515d97f28" />

117,000 failed logins over the window, with spikes of 17,000 at 8 AM, 8,930 at 9 AM, and 70,400 at 8 PM.

---

## 16. Create a detection rule

In Sentinel, add a scheduled analytics rule (Configuration > Analytics > + Create):

```
Name: Failed Logon Attempts
Description: Detects Windows logon failures on CORP-NET-EAST
Severity: Medium
MITRE ATT&CK
  Credential Access  — T1110 Brute Force
  Initial Access     — T1078 Valid Accounts
  Reconnaissance     — T1589 Gather Identity Information / T1589.001 Credentials
Status: Enabled
```

```kql
SecurityEvent
| where EventID == 4625
| where computer == "CORP-NET-EAST"
| summarize AttemptCount = count() by IpAddress, Account, Computer, bin(TimeGenerated, 5m)
| where AttemptCount > 3
```

```
Alert enhancement (entity mapping)
  Account: Name -> Account
  Host:    HostName -> Computer
  IP:      Address -> IpAddress

Query scheduling: run every 5 min, lookup last 5 min, start automatically
Alert threshold: generate when results > 0
Event grouping: all events into a single alert
Suppression: stop running for 24 h after an alert fires
```

---

## 17. Incident response

Investigate incidents the rule raises (Threat Management > Incident).

An account named `\EAST` from `80.94.95.43` tried to log into `CORP-NET-EAST` 10,470 times — a brute-force attempt.

The IP geolocates to Maarn, Netherlands (latitude 52.0672, longitude 5.3781):

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "80.94.95.43"
    | where EventID == 4625
    | order by TimeGenerated desc;
WindowsEvents
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude
```

<img width="972" height="188" alt="IP geolocation" src="https://github.com/user-attachments/assets/5cd10d8a-6eb9-4358-877b-c044ed60acfa" />

It has been reported 43 times and flagged malicious by several vendors, including AlphaMountain.ai, CyRadar and Fortinet.

<img width="1308" height="523" alt="IP reputation" src="https://github.com/user-attachments/assets/604a4cd9-c7d6-4d7e-9986-ac1c91e2f517" />

<img width="502" height="494" alt="IP reputation detail" src="https://github.com/user-attachments/assets/0fe2b512-1039-47bd-b3f2-361d204d2734" />

No successful logins (`Event ID 4624`) from that IP, so `CORP-NET-EAST` was not compromised:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "80.94.95.43"
    | where EventID == 4624
    | order by TimeGenerated desc;
WindowsEvents
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude
```

<img width="363" height="97" alt="No successful logins" src="https://github.com/user-attachments/assets/c1f5eb42-6884-4756-95b1-360588270cf3" />

Block the IP range with an inbound NSG deny rule (VM > Networking > Network Settings):

```
Source: IP Addresses
Source IP/CIDR: 80.94.95.0/24
Source Port Ranges: *
Destination: Any
Service: Custom
Destination Port Ranges: *
Protocol: Any
Action: Deny
Priority: 100
Name: Deny--80.94.95.0-24
```

<img width="2124" height="520" alt="Deny rule" src="https://github.com/user-attachments/assets/0325f06d-2753-4c5f-a6f4-940de9e06bf2" />

`80.94.95.0/24` covers `80.94.95.0`–`80.94.95.255`, so this blocks `80.94.95.43` and the rest of that range from reaching the honeypot.

---

## 18. Results after 1 week

Failed logons from 2025-07-21 to 2025-07-28 — 315,565:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T00:00:00Z) .. datetime(2025-07-28T23:59:59Z))
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| count
```

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

<img width="1875" height="837" alt="1-week map" src="https://github.com/user-attachments/assets/0b7965af-4212-4f22-966a-13d1730f5ad8" />

Top 5 countries over the week:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| where isnotempty(countryname);
let Top5Countries = 
    WindowsEvents
    | summarize FailureCount = count() by countryname
    | top 5 by FailureCount desc
    | project countryname;
WindowsEvents
| where countryname in (Top5Countries)
| summarize FailureCount = count(),
          latitude = any(latitude),
          longitude = any(longitude),
          city = any(cityname)
    by countryname
| extend friendly_location = strcat(city, " (", countryname, ")")
| project countryname, FailureCount, latitude, longitude, friendly_location
```

<img width="1578" height="834" alt="Top 5 countries, 1 week" src="https://github.com/user-attachments/assets/1a3f27f7-abbf-42b9-8750-385563254c9f" />

Top 10 attacker IPs over the week:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T00:00:00Z) .. datetime(2025-07-28T23:59:59Z))
| summarize FailedAttempts = count() by AttackerIp = IpAddress
| sort by FailedAttempts desc
```

<img width="323" height="388" alt="Top 10 IPs, 1 week" src="https://github.com/user-attachments/assets/ef56f187-d3a3-4fbb-861a-1442952140a7" />

Timeline over the week — 315K total, highest on July 21 around 8 PM at 70,400:

<img width="2156" height="985" alt="Timeline, 1 week" src="https://github.com/user-attachments/assets/061e5a1d-4407-498a-b7c7-bfd535873790" />
