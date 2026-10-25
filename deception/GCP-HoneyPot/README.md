# Cloud Threat Luring: T-Pot 24.04.1 on Google Cloud Platform

Welcome to my honeypot analysis project. In this guide, I'll walk you through deploying and configuring a T-Pot honeypot on Google Cloud Platform (GCP). The goal is to observe attacker playbooks in real traffic, capture and parse malicious payloads at scale, and automate infrastructure deployment and monitoring via infrastructure-as-code.

## Table of Contents

- [Prerequisites](#prerequisites)
- [GCP VM Configuration](#gcp-vm-configuration)
- [Firewall Configuration](#firewall-configuration)
- [T-Pot Installation](#t-pot-installation)
- [Verifying the T-Pot Service](#verifying-the-t-pot-service)
- [Accessing the T-Pot Dashboard](#accessing-the-t-pot-dashboard)
- [What I Learned](#what-i-learned)


## Prerequisites

- A Google Cloud account with a verified payment method
- $300 free trial credit (valid for 90 days)
- Basic familiarity with Linux shell and Git
- (Recommended) Google Pay enabled on your account

## GCP VM Configuration

1. **Machine Type**
   - Minimum: 8 GB RAM (16 GB recommended)
   - Storage: 128 GB boot disk
   - Estimated cost: ~$50/month (covered by free trial)

2. **Operating System**
   - Ubuntu 24.04 LTS Minimal (x86_64)
   - Increase boot disk from default 10 GB to 128 GB

3. **Networking & Data Protection**
   - Enable HTTP and HTTPS traffic
   - In Observability, disable backups and turn off the Ops Agent

4. **Create the VM**
   - Click **Create** in the Compute Engine console
   - Wait ~2–5 minutes for it to boot

## Firewall Configuration

1. In the VM details, enable **Set up firewall rules**
2. Create a rule with:
   - **Targets**: All instances in the network
   - **Source IPv4 ranges**: `0.0.0.0/0`
   - **Protocols and ports**: Allow all

## T-Pot Installation

SSH into your VM (do **not** switch to root; use your default sudo-enabled user) and run:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git -y

git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh
# when prompted:
#   • type 'y' and press Enter
#   • choose 'h' for HIVE sensors
#   • enter your desired web UI username/password
#   • wait for it to finish port remapping
sudo reboot
```

## Verifying the T-Pot Service

After reboot, verify the service is running:

```bash
sudo systemctl status tpot
```

## Accessing the T-Pot Dashboard

1. Open your browser to `https://<YOUR_VM_IP>:64297`
2. Accept the risk/continue warning
3. Log in with the credentials you set

You should now see live attack data flowing into Kibana and the suite of T-Pot analysis tools.

## What I Learned

- How to provision a GCP VM with the right specs for containerized sensors
- Best practices for OS selection and disk sizing
- Network hardening via firewall rules and VPC isolation
- Installing Git under a sudo-enabled non-root user
- Running the T-Pot installer and verifying service changes (SSH port remapping)
- Validating browser-based SSH on a custom port and confirming live traffic ingestion



# honeypot-threat-research

I deployed a T-Pot honeypot on Google Cloud for 28 days and left it exposed to the internet to see what would show up. This repo documents the attack campaigns that emerged, the CVEs being actively exploited, where the traffic was coming from, and what patterns kept repeating across the full deployment.


## Deployment

| | |
|---|---|
| **Platform** | T-Pot Community Edition on Ubuntu 24.04 LTS |
| **Infrastructure** | Google Cloud Platform |
| **Period** | February 1 to February 28, 2026 |
| **Total Events** | 96,408,585 |
| **Days Captured** | 28 of 28 |
| **Collection Method** | Elasticsearch DSL queries, daily |



---

**Deployment Period:** 2026/02/01 to 2026/02/28

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## About This Report

This report is part of a hands-on project focused on building practical skills in threat data analysis and CVE research. It is one report in an ongoing series covering the February 2026 T-Pot deployment.

---

## Summary

Three CVEs generated the most Suricata IDS signature hits across the 28-day deployment.

**CVE-2018-13379** (Fortinet FortiOS SSL VPN path traversal) produced **29,938 events**, with a small amount of high-volume burst days. **CVE-2024-14007** (TVT NVMS-9000 authentication bypass) generated **1,878 events** with activity every single day of the deployment. **CVE-2025-55182** (React Server Components RCE, disclosed December 2025) produced **1,527 events** and declined through the second half of the month.

Each CVE showed a different scanning pattern. CVE-2018-13379 came in bursts targeting a legacy VPN flaw. CVE-2024-14007 ran as steady daily probing consistent with probable botnet activity. CVE-2025-55182 reflected likely opportunistic scanning for a recently disclosed web application vulnerability.

---

## Background

Event counts in this report show Suricata IDS signature matches, but it is not a confirmed exploitation. The amounts listed represent inbound attempt volume only.

---

## CVE-2018-13379: Fortinet FortiOS SSL VPN Path Traversal

A path traversal flaw in the FortiOS SSL VPN web portal where an unauthenticated attacker sends crafted HTTP requests to read system files. The primary target is the `sslvpn_websession` file, which stores VPN session data and credentials in cleartext.

**Affected products:** FortiOS 5.4.6–5.4.12, 5.6.3–5.6.7, 6.0.0–6.0.4 and FortiProxy 1.0.0–1.0.7, 1.1.0–1.1.6, 1.2.0–1.2.8, 2.0.0. Patches released 2019.

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3.1 | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | NVD |
| CVSS v3 (alt) | 9.1 | Shodan CVEDB |
| EPSS | 94.47% (top 100th percentile) | Shodan CVEDB |
| CISA KEV | Yes, added 2021/11/03 | CISA |
| Ransomware | Known association | Shodan CVEDB |

**Observed activity:** 29,938 total events across 28 days, and the honeypot saw zero activity on 13 of those days. The other 15 days varied in amounts. On 2026/02/15, there were **9,338 events**, which is 31.2% of the month's total for this CVE. On 2026/02/21, there were **7,684 events** (25.7%). The remaining 13 active days ranged from 356 to 2,483.

**Assessment:** CVE-2018-13379 was patched in 2019. The CISA KEV action deadline passed in May 2022, however it is still the most scanned CVE in this dataset by a large margin. The on/off pattern, silence then spiking sharply, points to probable short-duration automated scanning campaigns rather than persistent probing from a fixed source. The honeypot is not a FortiOS device, so nothing here could be exploited. These events are basic reconnaissance, and the volume suggests scanners continue to find unpatched Fortinet devices on the internet.

**Defender note:** Any FortiOS or FortiProxy version listed above with SSL VPN enabled should be patched or decommissioned. Public PoC exploits, including a Metasploit module, have been available since 2019.

---

## CVE-2024-14007: Shenzhen TVT NVMS-9000 Authentication Bypass

An authentication bypass in the NVMS-9000 control protocol, and sending a single crafted TCP payload to the exposed control port lets an unauthenticated attacker run privileged administrative queries. Successful exploitation returns admin usernames and passwords in cleartext, plus network and device configuration. Affected commands include `queryBasicCfg`, `queryUserList`, `queryEmailCfg`, `queryPPPoECfg`, and `queryFTPCfg`. This firmware is used across many white-labeled DVR, NVR, and IP camera products.

**Affected products:** NVMS-9000 firmware prior to 1.3.4. Fixed in 1.3.4.

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3 | Not published | NVD (analysis pending) |
| CVSS v4.0 | 8.7 (AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N) | VulnCheck |
| EPSS | 0.07% (top 20.3rd percentile) | Shodan CVEDB |
| CISA KEV | No | CISA |
| VulnCheck KEV | Yes | VulnCheck |
| Ransomware | None confirmed | Shodan CVEDB |

**Observed activity:** 1,878 total events. Activity was present all 28 days. Daily counts ranged from 38 (2026/02/14) to 174 (2026/02/07), averaging 67 events per day, with no significant spikes.

**Assessment:** The daily pattern points to probable botnet infrastructure running continuously rather than campaign-based scanning. GreyNoise documented a surge in exploitation attempts targeting TVT DVRs around this period. The ELEVEN11 botnet, a Mirai variant, has been specifically linked to active exploitation of this CVE. The low EPSS score reflects how recently this CVE was formally added to NVD (November 2025), not how actively it is being targeted. The VulnCheck KEV tag and external threat reporting both indicate real-world exploitation is ongoing.

**Defender note:** Update NVMS-9000 firmware to 1.3.4 or later, and do not expose the control port to the internet. If you manage white-labeled DVR or NVR equipment, verify whether it uses TVT firmware. Check for rebranding since it makes affected devices easy to miss.

---

## CVE-2025-55182: React Server Components RCE (React2Shell)

An unsafe deserialization flaw in the React Server Components (RSC) "Flight" protocol where an unauthenticated attacker sends a crafted POST request to a Server Function endpoint. The server deserializes the malicious payload without sufficient validation and executes attacker-controlled code under the Node.js process. Default configurations are vulnerable and the application does not need to specifically use Server Functions. This was disclosed 2025/12/03.

**Affected products:** react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack versions 19.0, 19.1.0, 19.1.1, and 19.2.0; Next.js 14.3.0-canary.77 through 16.x (App Router); React Router, Waku, RedwoodSDK, Parcel, and Vite RSC plugins. 

| Metric | Value | Source |
|--------|-------|--------|
| CVSS v3 | 10.0 | CNA (Meta); NVD assessment pending |
| EPSS | 59.56% (top 98.2nd percentile) | Shodan CVEDB |
| CISA KEV | Yes | Shodan CVEDB |
| Ransomware | Known association | Shodan CVEDB |

**Observed activity:** 1,527 total events. Active all 28 days. The first two weeks averaged roughly 65 events per day. The final week averaged 28 per day, ending at 8 on 2026/02/28.

**Assessment:** This CVE was disclosed about two months before this deployment started. Seeing it as the third highest CVE in February lines up with reporting from Google, Amazon, Microsoft, and Palo Alto, who all documented active exploitation within hours of the December 2025 disclosure. Post-exploitation activity included cryptocurrency miners, Cobalt Strike beacons, and backdoors including SNOWLIGHT, VShell, and COMPOOD. China-nexus threat groups were named in exploitation campaigns by both Amazon and Google threat intelligence. The declining event trend through February may reflect possible patching implementation to vulnerable systems.

**Defender note:** Patch to the fixed versions listed above. CVE-2025-66478 was initially issued separately for Next.js but was rejected as a duplicate of CVE-2025-55182. Detections referencing either ID point to the same flaw.

---

## Data Reference

### Table 1: CVE Summary

| CVE | Total Events | Active Days | Peak Day | Peak Count |
|-----|-------------|-------------|----------|------------|
| CVE-2018-13379 | 29,938 | 15 of 28 | 2026/02/15 | 9,338 |
| CVE-2024-14007 | 1,878 | 28 of 28 | 2026/02/07 | 174 |
| CVE-2025-55182 | 1,527 | 28 of 28 | 2026/02/07 | 140 |

### Table 2: Daily Event Counts

| Day | Date | CVE-2018-13379 | CVE-2024-14007 | CVE-2025-55182 |
|-----|------|----------------|----------------|----------------|
| 01 | 2026/02/01 | 0 | 77 | 44 |
| 02 | 2026/02/02 | 0 | 74 | 45 |
| 03 | 2026/02/03 | 1,271 | 56 | 35 |
| 04 | 2026/02/04 | 1,316 | 42 | 41 |
| 05 | 2026/02/05 | 2,483 | 102 | 78 |
| 06 | 2026/02/06 | 1,384 | 62 | 105 |
| 07 | 2026/02/07 | 941 | 174 | 140 |
| 08 | 2026/02/08 | 0 | 75 | 81 |
| 09 | 2026/02/09 | 0 | 69 | 50 |
| 10 | 2026/02/10 | 0 | 49 | 38 |
| 11 | 2026/02/11 | 1,638 | 47 | 55 |
| 12 | 2026/02/12 | 1,167 | 51 | 85 |
| 13 | 2026/02/13 | 0 | 43 | 69 |
| 14 | 2026/02/14 | 356 | 38 | 53 |
| 15 | 2026/02/15 | 9,338 | 53 | 42 |
| 16 | 2026/02/16 | 0 | 50 | 61 |
| 17 | 2026/02/17 | 807 | 51 | 43 |
| 18 | 2026/02/18 | 0 | 48 | 70 |
| 19 | 2026/02/19 | 0 | 68 | 103 |
| 20 | 2026/02/20 | 0 | 68 | 40 |
| 21 | 2026/02/21 | 7,684 | 77 | 50 |
| 22 | 2026/02/22 | 0 | 74 | 40 |
| 23 | 2026/02/23 | 0 | 79 | 34 |
| 24 | 2026/02/24 | 0 | 80 | 30 |
| 25 | 2026/02/25 | 0 | 74 | 14 |
| 26 | 2026/02/26 | 0 | 82 | 47 |
| 27 | 2026/02/27 | 1,019 | 64 | 26 |
| 28 | 2026/02/28 | 534 | 51 | 8 |

---

## Methodology Notes

**CVE-2018-13379 double-signature:** Two Suricata rules fired for this CVE with identical per-day counts, meaning they matched the same traffic. This report uses one signature's count (29,938). The combined total across both signatures is 59,876.

**CVSS sourcing:** NVD is the primary CVSS source in this report. For CVE-2018-13379, NVD publishes 9.8 and Shodan CVEDB returns 9.1. This kind of discrepancy is common. For CVE-2024-14007, NVD has not published a v3 score; the v4.0 score of 8.7 comes from VulnCheck. For CVE-2025-55182, NVD has not completed its analysis and the score of 10.0 comes from the CNA (Meta).

**EPSS scores** come from Shodan CVEDB and reflect a single point in time snapshot. The score for CVE-2024-14007 (0.07%) may not yet reflect full exploitation data given how recently the CVE was formally published.

---


---


# Geographic Attribution: February 2026 Honeypot Deployment

**Deployment Period:** February 1, 2026 to February 28, 2026

**Honeypot:** T-Pot Community Edition, Google Cloud Platform

**Data Source:** Elasticsearch DSL queries, Kibana Dev Tools

**TLP:** TLP:CLEAR

---

## Summary

The Netherlands, Brazil, Ukraine, and the United States were the top source countries across the 28-day deployment. A single Dutch ASN (Alsycon B.V.) produced nearly a third of all traffic in the top-20 ASN totals. Country labels in this dataset reflect where source IPs are registered, which is often a cloud datacenter or hosting provider, not the attacker's actual location.

---

## Background

T-Pot resolves each source IP to a country and ASN using MaxMind's GeoIP database. The country shown is where the IP is registered. Attackers frequently rent servers from cloud providers to run their tools, so the geographic label often reflects infrastructure location rather than operator location.

---

## Findings

### The Netherlands led by a wide margin

Alsycon B.V., a small Dutch hosting provider, was the largest source ASN across the full deployment with 24,045,125 events, over 32% of the top-20 ASN total. Its consistent, high-volume presence throughout February suggests one or a small number of actors used Alsycon-hosted servers as persistent attack infrastructure.

### Brazil appeared across many ASNs

Nine Brazilian ISPs appeared in the top 20 ASNs, spread across different states and IP ranges. Traffic was distributed across many sources rather than concentrated, which is more consistent with compromised endpoints or botnet activity than a focused campaign.

### DigitalOcean was the largest cloud provider source

DigitalOcean ranked second overall with 13,767,116 events and appeared on nearly every day of the deployment. Google LLC contributed 3,064,962 events. Together they account for roughly 23% of the top-20 ASN total. Google Cloud traffic is notable given this honeypot ran on GCP, meaning some attackers were using the same provider.

### Ukraine was a persistent mid-tier source

Two Ukrainian ASNs appeared across the full deployment: FOP Dmytro Nedilskyi (5,436,292 events) and LLC Vash Kredit Bank (1,704,237 events). FOP Dmytro Nedilskyi is a small hosting provider. Both showed up on multiple days at consistent volume.

---

## Analysis

Most of the top-country volume comes from hosting providers and cloud infrastructure, not residential networks. The Netherlands ranking first is a function of one hosting provider being heavily used. Brazil's spread across many small ISPs points to botnet or compromised-device activity rather than a single operator. Cloud provider traffic from the US reflects attacker preference for disposable VPS infrastructure.

Nation-state attribution is not possible from this data. Infrastructure location and operator location are different things, and this dataset has no signals to bridge that gap.

MaxMind's database has documented accuracy limitations for cloud provider ranges and VPN exit nodes, so some country labels may be incorrect. This is a known limitation.

---

## Defender Notes

Country-level blocks would be ineffective. The same actors appear across multiple countries and providers. Blocking specific ASNs that show persistent high-volume scanning with no legitimate use case is a better course of action.

---

## Data Reference

### Top ASNs, Full Deployment (28 Days)

| ASN | Events | Notes |
|-----|--------|-------|
| Alsycon B.V. | 24,045,125 | Dutch hosting provider |
| DigitalOcean, LLC | 13,767,116 | Cloud provider |
| FOP Dmytro Nedilskyi | 5,436,292 | Ukrainian hosting provider |
| Smart Servico de Internet Ltda | 3,332,596 | Brazilian ISP |
| Google LLC | 3,064,962 | Cloud provider |
| OXMAN TECNOLOGIA LTDA | 3,032,659 | Brazilian ISP |
| BITNET TELECOM | 2,986,685 | Brazilian ISP |
| BERTONCELLO PROVEDOR DE INTERNET LTDA ME | 2,603,657 | Brazilian ISP |
| GA Telecom | 2,398,612 | Brazilian ISP |
| DGNETSP EIRELI | 2,161,650 | Brazilian ISP |
| LLC Vash Kredit Bank | 1,704,237 | Ukrainian provider |
| HostPapa | 1,458,267 | Canadian hosting |
| Sinal do Ceu Telecom | 1,374,599 | Brazilian ISP |
| JL INFORMATICA E TELECOM LTDA - ME | 1,213,548 | Brazilian ISP |
| JK TELECOMUNICACOES LTDA | 1,065,785 | Brazilian ISP |
| TOTAL PLAY TELECOMUNICACIONES SA DE CV | 1,035,003 | Mexican ISP |
| Flyservers S.A. | 979,512 | Hosting provider |
| Enoki & Ruiz Ltda - ME | 862,730 | Brazilian ISP |
| GTT Communications Inc. | 845,983 | US transit provider |
| FATIMA VIDEO ELETRONICA LTDA ME | 665,865 | Brazilian ISP |

### Top Countries by Volume (T-Pot Dashboard, Full Period)

| Rank | Country |
|------|---------|
| 1 | Netherlands |
| 2 | United States |
| 3 | Ukraine |
| 4 | Romania |
| 5 | France |

*Dashboard country attribution is based on MaxMind GeoIP. Cloud and hosting provider IPs may resolve to the country of the datacenter, not the operator.*

