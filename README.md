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

The architecture of the honeynet in Azure consists of the following components:

- Virtual Machines (2 Windows, 1 Linux)
- Virtual Network (VNet)
- Network Security Group (NSG)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

## Key Setup Steps
### AAD/Tenant Logs (Identity-Level Monitoring)
- Azure AD (Microsoft Entra ID) Logging: Configured logging for Azure AD to collect both Audit and Sign-in logs. This involved generating logs and analyzing the changes within Log Analytics Workspace using KQL queries.
### Resource Plane (Resource-Level Monitoring)
- NSG Flow Logs: Enabled Flow Logs for both NSGs, ensuring logs were sent to the Log Analytics workspace
- Content Hub: Installed “Windows Security Events” (specifically, ```EventID = 4625``` for failed login attempts via RDP/SMB, and ```EventID = 18456``` in application logs for login attempts to MS SQL Server) and “Syslog” (capturing logs from ```/var/logs/```) from the Sentinel Content Hub. This ensures comprehensive log collection from Windows and Linux sources, respectively.
- Data Collection Rules (DCR): Configured Data Collection Rules for the VMs using the Azure Monitoring Agent (AMA) to ensure that Windows Security events and Linux Syslog data were properly ingested into Sentinel. Verified successful provisioning of the agent on both VMs.
### Management Plane (Subscription-Level Monitoring)
- Azure Activity Logs: Set up queries to monitor resource activities, such as the creation and deletion of Resource Groups, changes to NSGs, and activities related to security incidents.
- Azure Sentinel: Created and configured watchlists using ```geoip.csv``` to monitor and analyze malicious traffic, enabling Microsoft Defender for Cloud to forward logs from servers, key vaults, and storage accounts to the Log Analytics Workspace, and imported and managed custom analytics rules to detect and respond to security threats.

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

## Attack Maps Before Hardening / Security Controls
## NSG Allowed Inbound Malicious Flows
### The query below analyzes malicious network flows captured in the Azure Network Analytics logs, extracts details like the source and destination IPs, ports, and protocols, and enriches this data with geolocation information using a GeoIP database. The output includes details about the malicious flow, as well as where the attacks are originating from:
```
// Load the watchlist "geoip", which contains geolocation data for IP addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");

// Query Azure Network Analytics logs for flows labeled as "MaliciousFlow"
let MaliciousFlows = AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"   // Filter for malicious network flows
| order by TimeGenerated desc   // Order the results by time in descending order (most recent first)
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;

// Perform an IP lookup using the GeoIP database to find geographic information for the source IPs
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)

// Project the final set of fields for the output
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")
```
![NSG Allowed Inbound Malicious Flows](https://github.com/wesleyytiong/soc-azure/blob/main/images/(before)-nsg-malicious-allowed-in-24h.png)<br>
## Linux Syslog Auth Failures
### The query below is designed to analyze failed login attempts from syslog, extract the source IP addresses, look up their geographic locations using a GeoIP database, and display key information about the source and destination of these attempts, including where in the world the attempts are coming from
```// Load the watchlist "geoip", which contains geolocation data for IP addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");

// Define a regular expression pattern to extract IPv4 addresses in the format xxx.xxx.xxx.xxx
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";

// Query the Syslog data
Syslog
| where Facility == "auth"   // Filter to only include logs from the "auth" facility (authentication logs)
| where SyslogMessage startswith "Failed password for"   // Only include logs that start with "Failed password for" (failed login attempts)
| order by TimeGenerated desc   // Order the logs by the time they were generated, with the most recent entries first
| project TimeGenerated, SourceIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type

// Perform an IP lookup using the GeoIP database to find geographic information for the source IPs
| evaluate ipv4_lookup(GeoIPDB_FULL, SourceIP, network)

// Project the final set of fields for the output
| project TimeGenerated, SourceIP, DestinationHostName, DestinationIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")");
```
![Linux Syslog Auth Failures](https://github.com/wesleyytiong/soc-azure/blob/main/images/(before)-syslog-ssh-auth-fail-24h.png)<br>
## Windows RDP/SMB Auth Failures
### The query below extracts failed logon attempts (Event ID 4625) from Windows security logs, matches the source IP address with geographic location data using the GeoIP watchlist, and outputs details such as the account name, computer, logon type, and geographic location of the IP address attempting the logon
```// Load the watchlist "geoip", which contains geolocation data for IP addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");

// Query the SecurityEvent table for Windows events
let WindowsEvents = SecurityEvent;

// Filter for Event ID 4625, which corresponds to failed logon attempts
WindowsEvents 
| where EventID == 4625   // EventID 4625 is for "An account failed to log on"
| order by TimeGenerated desc   // Order by the time the event was generated, with the most recent first

// Perform an IP lookup using the GeoIP database to find geographic information for the source IPs
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)

// Project the final set of fields for the output
| project TimeGenerated, Account, AccountType, Computer, EventID, Activity, IpAddress, LogonTypeName, network, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")");
```

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

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening```

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
