# Splunk  
# Building a SIEM Environment in Splunk (Live Traffic)

![image](https://github.com/user-attachments/assets/61ad46fc-30a7-4953-b94f-12ed976adbcc)


## Introduction

In this project, we build a mini SIEM environment using Splunk. We integrate logs from various sources into our Splunk deployment, which then creates dashboards, detects anomalies, triggers alerts, and generates incidents. First, we measure security metrics in an *insecure* environment for 24 hours. Next, we apply security controls to harden the setup, measure these metrics for another 24 hours, and compare the results.

The metrics we will show are:

- **WinEventLog** (Windows Event Logs)
- **Syslog** (Linux Syslog)
- **Alerts** (Triggers within Splunk based on saved searches)
- **Notable Events** (Incidents or notable events in Incident Review)
- **Network_Traffic** (Firewall or network logs ingested by Splunk)

---

## Architecture Before Hardening / Security Controls

![image](https://github.com/user-attachments/assets/36b28fc6-0410-4d2d-bfd0-4ebda1164477)


### Environment Details

- **Splunk Server** (single instance) running on a Linux VM.  
- **Windows VM** with open RDP, SMB shares, and minimal firewall restrictions.  
- **Linux VM** (e.g., Ubuntu) running SSH, FTP, and no host-based firewall.  
- **Network**: 
  - All machines on the same subnet.  
  - No strict ingress/egress rules.  

All resources were initially deployed with broad exposure. The Windows and Linux machines had their firewalls wide open, and Splunk was set to ingest any data without filtering.

---

## Architecture After Hardening / Security Controls

![image](https://github.com/user-attachments/assets/0f91b7a0-7caf-434e-a130-706f6342c634)



### Security Improvements

- **Network Segmentation**: The Windows and Linux VMs are now behind stricter firewall rules or separate VLANs.  
- **Host-Based Firewalls**:  
  - Windows Firewall now only allows RDP traffic from a specific admin IP range.  
  - Linux iptables blocks external SSH except from admin IPs.  
- **Splunk Tuning**:  
  - Refined saved searches and alert thresholds to reduce noise.  
  - Enabled data model acceleration for faster search performance.  
- **Credential Hardening**:  
  - Enforced complex passwords on both Windows and Linux.  
  - Removed or disabled default accounts/services.

---

## Attack Dashboards Before Hardening / Security Controls

1. **Network Attacks**  
   ![image](https://github.com/user-attachments/assets/a46575e8-8417-4194-9f58-8b6205475fc6)


2. **Authentication Failures (Linux Syslog)**  
   ![Linux Auth Failures](https://i.imgur.com/7f7ZaMx.png)

3. **Windows Security Events**  
   ![Windows Event Log Failures](https://i.imgur.com/uFKppWA.png)

---

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:  
**Start Time**: 2024-02-01 10:00  
**Stop Time**: 2024-02-02 10:00

| Metric          | Count  |
|-----------------|-------:|
| WinEventLog     | 15,932 |
| Syslog          | 2,784  |
| Alerts          | 12     |
| Notable Events  | 225    |
| Network_Traffic | 4,620  |

> Many brute-force attempts from unknown IPs targeted Windows RDP and Linux SSH, leading to multiple Splunk alerts and notable events.

---

## Attack Dashboards After Hardening / Security Controls

Post-hardening, the Splunk dashboards and searches reveal **minimal** suspicious activity:

- **Network Attacks**: No external scanning detected.
- **Linux Auth Failures**: Only a handful from authorized admin IP.
- **Windows Security Events**: Marked decline in failed logins and SMB attempts.

---

## Metrics After Hardening / Security Controls

The table below shows the metrics captured for another 24 hours after applying security controls:  
**Start Time**: 2024-02-04 14:00  
**Stop Time**: 2024-02-05 14:00

| Metric          | Count |
|-----------------|------:|
| WinEventLog     | 8,210 |
| Syslog          | 312   |
| Alerts          | 0     |
| Notable Events  | 0     |
| Network_Traffic | 980   |

> Almost all traffic is now from known sources, and no Splunk alerts or notable events were triggered.

---

## Conclusion

By setting up a Splunk-based SIEM environment and comparing **pre- and post-hardening** states, we clearly see:

1. **Significantly fewer** authentication failures.  
2. **Reduced** external scanning and network traffic.  
3. **Zero** triggered alerts or notable events once access was strictly controlled.

While legitimate user activity in a production environment could still generate a higher volume of logs post-hardening, malicious attempts would be largely mitigated by host-based firewalls, stricter network policies, and refined Splunk alerting thresholds.

---
