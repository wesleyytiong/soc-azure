# Building a SOC + Honeynet in Azure (Live Traffic)
![Cloud Honeynet / SOC](https://github.com/wesleyytiong/soc-azure/blob/main/images/soc-azure.png)

## Introduction

This project demonstrates building a mini honeynet in Azure, where various logs are collected and analyzed using a Log Analytics workspace and Microsoft Sentinel. Over a 24-hour period, I measured key security metrics in an unprotected environment, applied security controls, and measured the metrics again over the next 24 hours. The metrics include:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Alerts from Log Analytics)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (NSG Flow Logs)

## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Machines (2 Windows, 1 Linux)
- Virtual Network (VNet)
- Network Security Group (NSG)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

### Key Setup Steps:
- NSG Flow Logs: Enabled Flow Logs for both NSGs, ensuring logs were sent to our Log Analytics workspace. If the logs weren’t showing, a new storage account was created in the correct region to match the VMs.
- Data Collection Rules (DCR): Configured DCRs for the VMs to ensure Windows Security events and Linux Syslog data were ingested into Sentinel. The agent for both VMs was verified to ensure successful provisioning.
- Content Hub: Installed “Windows Security Events” and “Syslog” from the Sentinel Content Hub for proper log collection from Windows and Linux sources, respectively.
- Azure Activity Logs: Set up queries to monitor resource activities, such as the creation and deletion of Resource Groups, changes to NSGs, and activities related to security incidents.
- Azure AD (Microsoft Entra ID) Logging: Configured logging for Azure AD to collect both Audit and Sign-in logs. This involved generating logs by creating and deleting a “dummy_user” and analyzing the changes within Log Analytics Workspace using KQL queries.

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

## Attack Maps Before Hardening / Security Controls
NSG Allowed Inbound Malicious Flows
![NSG Allowed Inbound Malicious Flows](https://github.com/wesleyytiong/soc-azure/blob/main/images/(before)-nsg-malicious-allowed-in-24h.png)<br>
Linux Syslog Auth Failures
![Linux Syslog Auth Failures](https://github.com/wesleyytiong/soc-azure/blob/main/images/(before)-syslog-ssh-auth-fail-24h.png)<br>
Windows RDP/SMB Auth Failures
![Windows RDP/SMB Auth Failures](https://github.com/wesleyytiong/soc-azure/blob/main/images/(before)-windows-rdp-smb-auth-fail-24h.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2024-09-02T17:07:45
Stop Time 2024-09-03T17:07:45

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 232419
| Syslog                   | 1153
| SecurityAlert            | 6
| SecurityIncident         | 217
| AzureNetworkAnalytics_CL | 703

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2024-09-03T19:35:07
Stop Time	2024-09-04T19:35:07

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 18440
| Syslog                   | 0
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Results

After the initial 24 hours, I applied security controls to harden the environment. This included restricting NSG traffic to only allow my admin workstation and enabling firewalls and private endpoints for Azure resources. The following results were observed:

- The number of security events significantly decreased.
- Alerts triggered by Sentinel dropped, and the flow of malicious traffic was curtailed.
- Queries on Azure Activity Logs showed a reduction in resource deletions and security-related changes.
- In both Admin Mode and Attacker Mode, I simulated various user behaviors, from brute force attacks to role assignments in Azure AD, and observed these activities within the logs. The logs demonstrated the effectiveness of the applied security controls in reducing security incidents and protecting the infrastructure.
