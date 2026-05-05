<h1 = align=center>IMPLEMENTING A <code>SECURITY OPERATION CENTER</code>
  
  AND `HONEYPOT` IN `MICROSOFT AZURE`</h1>

<p = align=center>
<img width="1548" height="748" alt="SOC Final drawio (1)" src="https://github.com/user-attachments/assets/aadd2f1a-4ab0-4cac-8c85-c942e5c91702" />
</p>

## 🛠️ `TECHNOLOGY & PLATFORMS` UTILIZED

- *`Microsoft Azure:`*</br>
  Core cloud platform used to build and host the SOC and honeypot infrastructure.

- *`Windows 10 VM:`*</br>
  Deployed as a honeypot to attract and monitor unauthorized access attempts.

- *`Network Security Group (NSG) / Firewall:`*</br>
  Intentionally configured to allow all inbound traffic to maximize visibility and expose the honeypot VM to real-world attack attempts.

- *`Log Analytics Workspace:`*</br>
  Centralized log collection hub for ingesting and analyzing event data from the VM and Sentinel.

- *`Microsoft Sentinel:`*</br>
  Cloud-native SIEM solution used to detect, investigate, and respond to threats in real time.

- *`Kusto Query Language (KQL):`*</br>
  Used to write custom detection rules, analyze login attempts, and visualize attacker behavior in Sentinel dashboards.

  ---

## 🎯 `OBJECTIVE`

The objective of this project was to design and implement a simulated `Security Operations Center` (SOC) environment in `Microsoft Azure`, centered around a `Windows 10` virtual machine acting as a `honeypot`. The goal was to attract and analyze real-world unauthorized access attempts by exposing the VM to public traffic. Using tools such as `Microsoft Sentinel`, `Log Analytics Workspace`, and `Kusto Query Language` (KQL), I monitored, detected, and investigated threat activity. This project demonstrates core SOC capabilities, including threat detection, alerting, incident response, and visualization through workbooks.

## `TABLE OF CONTENTS`

[`1. SETUP AZURE SUBSCRIPTION`](#1-setup-azure-subscription)</br>
[`2. CREATE A RESOURCE GROUP`](#2-create-a-resource-group)</br>
[`3. CREATE A VIRTUAL NETWORK`](#3-create-a-virtual-network)</br>
[`4. CREATE A VIRTUAL MACHINE`](#4-create-a-virtual-machine)</br>
[`5. CREATE A HONEYPOT`](#5-create-a-honeypot)</br>
[`6. VALIDATE HONEYPOT EXPOSURE`](#6-validate-honeypot-exposure)</br>
[`7. CREATE A LOG ANALYTICS WORKSPACE`](#7-create-a-log-analytics-workspace)</br>
[`8. ACTIVATE MICROSOFT SENTINEL`](#8-activate-microsoft-sentinel)</br>
[`9. 1-HOUR RESULTS`](#9-1-hour-results)</br>
[`10. LOG ENRICHMENT IN MICROSOFT SENTINEL`](#10-log-enrichment-in-microsoft-sentinel)</br>
[`11. CREATING A MAP WORKBOOK`](#11-creating-a-map-workbook)</br>
[`12. 24-HOUR RESULTS`](#12-24-hour-results)</br>
[`13. TOP 5 COUNTRIES`](#13-top-5-countries)</br>
[`14. TOP 10 ATTACKER IP ADDRESSES`](#14-top-10-attacker-ip-addresses)</br>
[`15. FAILED LOGON ATTEMPTS TIMELINE`](#15-failed-logon-attempts-timeline)</br>
[`16. CREATING A CUSTOM DETECTION RULE`](#16-creating-a-custom-detection-rule)</br>
[`17. INCIDENT RESPONSE IN MICROSOFT SENTINEL`](#17-incident-response-in-microsoft-sentinel)</br>



---

# 1. SETUP `AZURE SUBSCRIPTION`

### Step 1: Create a free Azure subscription: [`https://azure.microsoft.com`](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)

<img width="1594" height="677" alt="Lab 1" src="https://github.com/user-attachments/assets/943202f4-4ee4-4bdc-817c-5071ae21f0e5" /></br>

<img width="1314" height="488" alt="Lab 2" src="https://github.com/user-attachments/assets/e2857ac0-8dcd-4699-b139-2181c4e4859d" /></br>

*Note: You will have to sign up and provide valid payment information, but you will **NOT** be charged.*

### Step 2: After your subscription is created, you can log in at: [`https://portal.azure.com`](https://portal.azure.com)

---

# 2. CREATE A `RESOURCE GROUP`

### Step 1: Go to `portal.azure.com` and search for `Resource Groups`

<img width="626" height="279" alt="Extra 1" src="https://github.com/user-attachments/assets/e879227c-64d5-4437-8d15-4df415684957" />

### Step 2: `+ Create` a Resource Group

```
Basics

Resource Group
  └─ Subscription: Azure Subscription 1  
  └─ Resource Group Name: RG-khan
  └─ Region: (US) East US 2
Review + Create
  └─ Create (When Prompted)
```

---

# 3. CREATE A `VIRTUAL NETWORK`

### Step 1: In Azure Portal, search for `Virtual Network` 

<img width="626" height="279" alt="Extra 1" src="https://github.com/user-attachments/assets/3ad66e12-4e04-4654-b7cf-7f832f85da22" />

### Step 2: `+ Create` Virtual Network

```
Basics

Project Details
  └─ Subscription: Azure Subscription 1  
  └─ Resource Group Name: RG-khan
Instance Details
  └─ Virtual Network Name: vnet-khan
  └─ Region: (US) East US 2
Review + Create
  └─ Create (When Prompted)
```

---

# 4. CREATE A `VIRTUAL MACHINE`

### Step 1: In Azure Portal, search for `Virtual Machines`

<img width="626" height="279" alt="Extra 1" src="https://github.com/user-attachments/assets/1b5184f5-0b63-47e0-bb00-bad092289d57" />

### Step 2: `+ Create` a new `Virtual Machine`

<img width="433" height="599" alt="Extra 2" src="https://github.com/user-attachments/assets/f3e8dc4d-470a-4d60-9012-ee34b574ed68" />

### Step 3: My `Virtual Machine` settings

```
Basics

Project Details
  └─ Subscription: Azure Subscription 1  
  └─ Resource Group: RG-khan
Instance Details 
  └─ Virtual Machine Name: CORP-NET-EAST  
  └─ Region: (US) East US 2
  └─ Image: Windows 10 Pro, Version 22H2 - x64 Gen2  
Size
  └─ Standard_B1s 1 vCPU, 1 GiB RAM  
Administrator Account
  └─ Username: YourUsername
  └─ Password: YourPassword
  └─ Confirm Password: YourPassword  
Licensing  
  └─ ☑ I confirm I have an eligible Windows 10/11 license
```

```
Disks

OS Disk
  └─ OS Disk Type: Standard HDD 
```

```
Networking

Network Interface
  └─ Virtual Network: Create New 
  └─ Subnet: Default 
  └─ Public IP: (new)  
  └─ NIC Network Security Group: Basic
  └─ ☑ Delete public IP and NIC when VM is deleted 
```

```
Monitoring

Diagnostics
  └─ Boot Diagnostics: Disable 
```

```
Review + Create
  └─ Create (When Prompted)
```

---

# 5. CREATE A `HONEYPOT`

### Step 1: Go to the `Network Security Group` inside your `Virtual Machine`

```
YourVirtualMachine
└─ Networking
  └─ Network Settings
```

---

### Step 2: Delete the `RDP` `Inbound Security Rule`
  
<img width="2196" height="402" alt="Lab 23" src="https://github.com/user-attachments/assets/7dd7b6d6-ca5d-487c-a7c0-4608d753a10a" />

---

### Step 3: `+ Add` a new `Inbound Security Rule`

```
Add Inbound Security Rule
  └─ Source: Any
  └─ Source Port Ranges: *
  └─ Destination: *
  └─ Service: Custom
  └─ Destination Port Ranges: *
  └─ Protocol: Any
  └─ Action: Allow
  └─ Priority: 300
  └─ Name: DANGER_AllowAnyCustomAnyInbound
```

---

### Step 4: Log into your `Virtual Machine` with `Remote Desktop Connection`

```
YourVirtualMachine
└─ Overview
  └─ Public IP Address
```

<img width="405" height="248" alt="Extra 5" src="https://github.com/user-attachments/assets/747f1402-0f15-4f73-ace8-cfc2f558e4d7" /></br>

***Note:** You will need the **username** and **password** you used to create your Virtual Machine to log in.*

---

### Step 5: Turn off the `Windows Defender Firewall`

```
Win + R
  └─ wf.msc
```

<img width="1041" height="779" alt="Lab 28" src="https://github.com/user-attachments/assets/0562dc50-79da-4c5e-b018-1fff70469493" />

---

# 6. `VALIDATE HONEYPOT EXPOSURE`

### Step 1: From your `Local Machine`, ping your `Virtual Machine's` Public IP Address

<img width="452" height="246" alt="Lab 29" src="https://github.com/user-attachments/assets/f560ce9c-ef11-4274-9da2-2424a312c787" />

### Step 2: Simulate `Brute-Force` Attempts

- ### Log out of your `Virtual Machine` and log back in with the incorrect username and password

<img width="451" height="414" alt="Lab 30" src="https://github.com/user-attachments/assets/810de6dd-94ff-41ce-9b70-9f0623a5486e" />

- ### Log back into your `Virtual Machine` and check `Event Viewer`

```
Win + R
└─ eventvwr.msc
  └─ Windows Logs
    └─ Security
```

<img width="907" height="381" alt="Lab 31" src="https://github.com/user-attachments/assets/c7d293e9-db4b-4623-8bb1-454948581740" /></br>

***Note:** EventID `4625` is a failed logon attempt. We can investigate further and see that a user named `employee` tried to log into our Virtual Machine. The honeypot is live!*

---

# 7. CREATE A `LOG ANALYTICS WORKSPACE`

### Step 1: In Azure Portal, search for `Log Analytics Workspaces` 

<img width="626" height="279" alt="Extra 1" src="https://github.com/user-attachments/assets/90014f16-a3ad-4234-b7d7-5ebcca19d05a" />

### Step 2: `+ Create` a new `Log Analytics Workspace`

```
Basics

Project Details
  └─ Subscription: Azure Subscription 1  
  └─ Resource Group: RG-khan
Instance Details 
  └─ Name: LAW-Khan  
  └─ Region: (US) East US 2
Review + Create
  └─ Create (When Prompted)
```

---

# 8. ACTIVATE `MICROSOFT SENTINEL`

### Step 1: In Azure Portal, search for `Microsoft Sentinel` 

<img width="626" height="279" alt="Extra 1" src="https://github.com/user-attachments/assets/0ff5da10-d4bc-499c-b1d2-f903af0417a4" />

---

### Step 2: Select Your `Log Analytics Workspace` and `Add`

<img width="1173" height="124" alt="Lab 7" src="https://github.com/user-attachments/assets/e41d901e-57a8-4bfa-8406-a226fb2f9faa" />

---

### Step 3: In `Microsoft Sentinel`, Install `Windows Security Events`  

```
Content Management
  └─ Content Hub  
Search: Security Event
  └─ ☑ Windows Security Events
    └─ Install
```

<img width="1634" height="984" alt="Lab 11" src="https://github.com/user-attachments/assets/763c4d83-7054-4995-9816-1663209543b5" />

---

### Step 4: Once installed, check `Windows Security Events` and click `Manage`

```
Windows Security Events
  └─ ☑ Windows Security Events via AMA
  └─ Open Connector Page
```

---

### Step 5: Create a `Data Collection Rule`

```
Basic

Rule Details
  └─ Rule Name: DC-khan
  └─ Subscription: Azure Subscription 1
  └─ Resource Group: RG-khan
```

```
Resources

Source
  └─ ☑ Azure Subscription 1
  └─ ☑ RG-khan
  └─ ☑ YourVictualMachine
```

```
Collect
  └─ All Security Events
```

```
Review + Create
  └─ Create (When Prompted)
```

- ### Open a second tab, go to `portal.azure.com` and search for `Virtual Machines`

```
YourVirtualMachine
  └─ Settings
    └─ Extensions + Applications
```

*Note: This is to check if the `AzureMonitorWindowsAgent` extension is installed. Any logs from the `honeypot` will now be sent to `Log Analytics Workspace`.*

---

# 9. `1-HOUR` RESULTS

### *This KQL query filters for failed logon attempts (`Event ID 4625`) that occurred within a one-hour window from `07:46 to 08:46 UTC` on `July 21, 2025`. It then displays key details like timestamp, account, computer, eventID, activity, and IP address, sorted in chronological order.*

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T07:46:00Z) .. datetime(2025-07-21T08:46:00Z))
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| sort by TimeGenerated asc
```
<img width="1047" height="746" alt="image" src="https://github.com/user-attachments/assets/a5ab9372-f4b4-452c-b5ee-63f07a9fa367" />

### *In the first hour after the honeypot VM went live, there were `94` failed login attempts originating from three unique IP addresses: `142.127.226.188`, `91.238.181.94`, and `80.94.95.75`. This early activity confirms that the exposed VM is already attracting external attention.*

---

# 10. `LOG ENRICHMENT` IN MICROSOFT SENTINEL

### Step 1: In Azure Portal, search for `Microsoft Sentinel` 

---

### Step 2: In `Microsoft Sentinel`, select the `Log Analytics Workspace` 

```
Microsoft Sentinel
  └─ Configuration
    └─ Watchlist
      └─ + New
```

---

### Step 3: Create a `Watchlist`

```
General
  └─ Name: geoip
  └─ Alias: geoip
Source
  └─ Browse for Files: geoip-summarized (Excel Spreadsheet)
  └─ SearchKey: Network
Review + Create
  └─ Create (When Prompted)
```

<img width="784" height="364" alt="Lab 51" src="https://github.com/user-attachments/assets/45e08b88-0185-4323-a390-fe52dd31dc62" />

---

### *This query filters failed login attempts (`Event ID 4625`) from the IP address `142.127.226.188`, then enriches the results with `GeoIP` data such as `city`, `country`, and `coordinates`.*

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "142.127.226.188"
    | where EventID == 4625
    | order by TimeGenerated desc;
WindowsEvents
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude
```

<img width="1046" height="710" alt="Lab 52" src="https://github.com/user-attachments/assets/8fce71cf-9edc-46ee-8220-e8e7d6a4350e" />

---

# 11. CREATING A `MAP WORKBOOK`

### Step 1: In Azure Portal, search for `Microsoft Sentinel` 

---

### Step 2: Add a `Workbook`, in `Microsoft Sentinel`

```
Microsoft Sentinel
  └─ Threat Management
    └─ Workbooks
      └─ + Add Workbook
```

---

### Step 3: Create a new `Workbook`

```
New Workbook
  └─ Edit
    └─ Remove Prepopulated Content
      └─ + Add
        └─ Add Query
```

<img width="815" height="713" alt="Lab 54" src="https://github.com/user-attachments/assets/4ff54676-f319-45ea-8d17-8e11e9d346af" />

### *On the `Advanced Editor` Tab, copy and paste the `json`, then click `Done Editing`.*

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

<img width="1145" height="603" alt="Lab 56" src="https://github.com/user-attachments/assets/ef0ca5ef-7add-4057-960e-c610299ac87c" /></br>

### *The map workbook has been created! I named this workbook `Windows VM Attack Map` and saved it to my resource group for future observations.* 

---

# 12. `24-HOUR` RESULTS

### *This KQL query filters for failed login attempts (`Event ID 4625`) targeting the `honeypot VM` over a `24-hour` period starting on `July 21, 2025`, at `07:46 UTC`. Surprisingly, the results revealed `107,836` failed logon attempts!*

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

<img width="1936" height="837" alt="Lab 11" src="https://github.com/user-attachments/assets/412ec00c-824c-4a4f-8d10-ae2ad22e8469" />

---

# 13. `TOP 5 COUNTRIES`

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

<img width="1571" height="829" alt="Extra 7" src="https://github.com/user-attachments/assets/44226dea-0a42-4563-926e-5b7fbf632376" />

---

# 14. `TOP 10 ATTACKER IP ADDRESSES`

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by AttackerIp = IpAddress
| sort by FailedAttempts desc
```

<img width="364" height="424" alt="Extra 8" src="https://github.com/user-attachments/assets/321bb612-079a-46da-90d3-887b46d48414" />

---

# 15. `FAILED LOGON ATTEMPTS TIMELINE`

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| render columnchart
```

<img width="1951" height="739" alt="Extra 10" src="https://github.com/user-attachments/assets/195ef539-1f7e-4bb9-8289-170fd21db8ec" />

<img width="1951" height="735" alt="Extra 11" src="https://github.com/user-attachments/assets/50138024-90df-48dc-82f5-e0c515d97f28" />

### *The timeline illustrates the volume of failed login attempts over time, totaling `117,000`, with several notable spikes. `17,000 at 8 AM`, `8,930 at 9 AM`, and a staggering `70,400 at 8 PM`!*

---

# 16. CREATING A `CUSTOM DETECTION RULE`

### Step 1: In Azure Portal, search for `Microsoft Sentinel`

---

### Step 2: Add an `Analytics Rule`, in `Microsoft Sentinel`

```
Microsoft Sentinel
  └─ Configuration
    └─ Analytics
      └─ + Create
```

### Step 3: Create a new `Scheduled Rule`

```
Analytics Rule Details
  └─ Name: Failed Logon Attempts
  └─ Description: This rule detects Windows logon failures on CORP-NET-EAST
  └─ Severity: Medium
  └─ MITRE ATT&CK
    └─ Credential Access
       └─ T1110 - Brute Force
    └─ Initial Access
       └─ T1078 - Valid Accounts
    └─ Reconnaissance
       └─ T1589 - Gather Identity Information
          └─ T1589.001 - Credentials
  └─ Status: Enabled
```

```kql
SecurityEvent
| where EventID == 4625
| where computer == "CORP-NET-EAST"
| summarize AttemptCount = count() by IpAddress, Account, Computer, bin(TimeGenerated, 5m)
| where AttemptCount > 3
```

```
Alert Enhancement
  └─ Account
    └─ Name - Account
  └─ Host
    └─ HostName - Computer
  └─ IP
    └─ Address - IpAddress
```

```
Query Scheduling
  └─ Run Query Every: 5 Minutes
  └─ Lookup Data: 5 Minutes
  └─ Start Running: Automatically
Alert Threshold
  └─ Generate Alert When Number of Query Results: Is Greater Than 0
Event Grouping
  └─ Group all events into a single alert
Suppression
  └─ Stop running query after alert is generated: On
  └─ Stop running query for: 24 Hours
Review + Create
  └─ Create (When Prompted)
```

<img width="1963" height="587" alt="Lab 65" src="https://github.com/user-attachments/assets/2320310c-5d60-4bd6-a0a7-a63262ae7f37" />

---

# 17. `INCIDENT RESPONSE` IN MICROSOFT SENTINEL

### Step 1: In Azure Portal, search for `Microsoft Sentinel`

---

### Step 2: Investigate `Incidents` triggered by `Analytics Rule`

```
Microsoft Sentinel
  └─ Threat Management
    └─ Incident
```


### *An account named `\EAST` from IP address `80.94.95.43` attempted to log in to the computer `CORP-NET-EAST` `10,470` times, indicating a `brute-force` attempt.*


---

### *Further investigation revealed that the IP address originates from `Maarn, Netherlands`, with coordinates approximately at `latitude 52.0672` and `longitude 5.3781`.*

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

<img width="972" height="188" alt="Extra 15" src="https://github.com/user-attachments/assets/5cd10d8a-6eb9-4358-877b-c044ed60acfa" />

---

### *This IP address has been reported `43` times and flagged as malicious by several reputable security vendors, including `AlphaMountain.ai`, `CyRadar`, and `Fortinet`.*

<img width="1308" height="523" alt="Extra 13" src="https://github.com/user-attachments/assets/604a4cd9-c7d6-4d7e-9986-ac1c91e2f517" /></br>

<p = align=center>
<img width="502" height="494" alt="Extra 14" src="https://github.com/user-attachments/assets/0fe2b512-1039-47bd-b3f2-361d204d2734" />
</p>

---

### *The IP address `80.94.95.43` has not recorded any successful login attempts (`Event ID: 4624`), confirming that the computer `CORP-NET-EAST` remains uncompromised.*

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

<img width="363" height="97" alt="Extra 16" src="https://github.com/user-attachments/assets/c1f5eb42-6884-4756-95b1-360588270cf3" />

---

### Step 3: Block The Malicious IP Address

- ### Search for `Virtual Machines`

```
YourVirtualMachine
  └─ Networking
    └─ Networking Settings
```

- ### `+ Add` a new `Inbound Security Rule`

```
Add Inbound Security Rule
  └─ Source: IP Addresses
  └─ Source IP Addresses/CIDR Ranges: 80.94.95.0/24
  └─ Source Port Ranges: *
  └─ Destination: Any
  └─ Service: Custom
  └─ Destination Port Ranges: *
  └─ Protocol: Any
  └─ Action: Deny
  └─ Priority: 100
  └─ Name: Deny--80.94.95.0-24
```

<img width="2124" height="520" alt="Lab 1" src="https://github.com/user-attachments/assets/0325f06d-2753-4c5f-a6f4-940de9e06bf2" /></br>

### *The CIDR block `80.94.95.0/24` effectively covers all IP addresses from `80.94.95.0` to `80.94.95.255`. Implementing this as an `NSG` rule successfully blocked `80.94.95.43` and any other IPs within the `80.94.95.*` range from attempting to access the honeypot.*


---


# `1 WEEK` RESULTS

### *This KQL query filters for failed login attempts (`Event ID 4625`) targeting the `honeypot VM` over a `1 week` period between `July 21, 2025` and `July 28, 2025`. Surprisingly, the results revealed `315,565` failed logon attempts!*

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

<img width="1875" height="837" alt="Honey 2" src="https://github.com/user-attachments/assets/0b7965af-4212-4f22-966a-13d1730f5ad8" />

---

# `TOP 5 COUNTRIES`

### *This KQL query analyzes failed login attempts (`Event ID 4625`) by enriching the data with `IP geolocation` from a custom watchlist. It identifies the `top five countries` with the highest number of failed attempts, then summarizes and displays each country’s failure count along with geographic details like city, latitude, and longitude for visualization or threat analysis.*

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

<img width="1578" height="834" alt="Honey 3" src="https://github.com/user-attachments/assets/1a3f27f7-abbf-42b9-8750-385563254c9f" />

---

# `TOP 10 ATTACKER IP ADDRESSES`

### *This KQL query identifies the `IP addresses` responsible for the most failed login attempts (`Event ID 4625`) within the time range of `July 21 to July 28, 2025`. It filters the security event logs for that event ID and time window, then counts the number of failed attempts per IP address.. The results are sorted in descending order to highlight the IPs with the highest number of failed logins.*

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T00:00:00Z) .. datetime(2025-07-28T23:59:59Z))
| summarize FailedAttempts = count() by AttackerIp = IpAddress
| sort by FailedAttempts desc
```

<img width="323" height="388" alt="Honey 6" src="https://github.com/user-attachments/assets/ef56f187-d3a3-4fbb-861a-1442952140a7" />

---

# `FAILED LOGON ATTEMPTS TIMELINE`

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated between (datetime(2025-07-21T00:00:00Z) .. datetime(2025-07-28T23:59:59Z))
| summarize FailedAttempts = count() by AttackerIp = IpAddress
| sort by FailedAttempts desc
```

<img width="2156" height="985" alt="Honey 5" src="https://github.com/user-attachments/assets/061e5a1d-4407-498a-b7c7-bfd535873790" />

### *The timeline illustrates the volume of failed login attempts over time, totaling `315K`, with several notable spikes. `July 21st` around `8 PM` remains the highest at `70,400` failed logon attempts.*

---
