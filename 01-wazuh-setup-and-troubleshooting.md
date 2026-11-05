# Lab Setup Log 01: Wazuh SIEM deployment and troubleshooting

**Date:** 2026-11-04
**Goal:** Deploy a Wazuh SIEM on my laptop as the core of a home SOC lab.

## Environment

| Item | Value |
|---|---|
| Host | Lenovo Legion 5, 16 GB RAM, Windows 11 |
| Hypervisor | Oracle VirtualBox 7.2 |
| SIEM | Wazuh 4.14.9 official OVA (Amazon Linux 2023, all-in-one) |
| Lab network | VirtualBox Host-only adapter (192.168.56.0/24) |
| Wazuh server IP | 192.168.56.101 |

## 1. Wazuh deployment

- Checked that hardware virtualization (VT-x) was enabled in the host.
- Downloaded the OVA from the official Wazuh package server (stable release, not the 5.0 release candidates).
- Imported into VirtualBox and adjusted before first boot:
  - **RAM: 8 GB → 6 GB**, to leave room for a victim VM and the host on 16 GB total.
  - **Hardware Clock in UTC enabled**, as recommended by the Wazuh docs, to avoid time skew. Accurate timestamps are essential to build an incident timeline.
  - **Graphics controller set to VMSVGA**, as recommended by the Wazuh docs, to avoid a frozen VM window.
  - **Network changed from Bridged to Host-only.** In Bridged mode the SIEM, which ships with well-known default credentials, would be reachable by anyone on the same Wi-Fi network. Host-only keeps the lab isolated and gives a stable IP regardless of which network the laptop is on.
- Accessed the dashboard from the host browser at `https://192.168.56.101`.

## 2. Incident: SIEM blocked by full disk

**Symptom:** the dashboard showed errors creating index patterns: `disk usage exceeded flood-stage watermark, index has read-only-allow-delete block`.

**Investigation (evidence first):**
- `df -h` → root partition `/dev/sda1` at **100%** (25G used of 25G).
- The VirtualBox details showed the imported virtual disk was **25 GB**, while the Wazuh documentation lists **50 GB** for the OVA. I had the evidence in a screenshot right after import and did not compare it with the docs.

**Fix:**
1. Powered off the VM and resized the virtual disk to ~60 GB in VirtualBox (Virtual Media Manager).
2. Booted and confirmed with `lsblk` that the disk (`sda`) was 60.3G but the partition (`sda1`) was still 25G.
3. Checked the filesystem type with `df -hT /` → **xfs**.
4. Extended the partition: `sudo growpart /dev/sda 1`
5. Extended the filesystem: `sudo xfs_growfs -d /` (data blocks changed from 6550523 to 15794075).
6. `df -h` → `/dev/sda1` at 61G, **26% used**.
7. The indexer released the read-only block on its own once usage dropped; the dashboard loaded normally.

**Lesson:** the Wazuh rule **531 (Partition usage reached 100%)** fired at **18:20:58**. I only noticed the dashboard error around 18:32. The SIEM detected the problem about 12 minutes before I did.

## 3. Hardening: default credentials

Every copy of the Wazuh OVA ships with the same default credentials. I changed them:
- System user `wazuh-user`: changed with `passwd`.
- Wazuh indexer and API users: changed with the official tool, all-in-one mode:
  `sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a -A -au wazuh -ap wazuh`
- New passwords stored in a password manager.
- Used SSH from the host to the VM so long random passwords could be copied safely.

**Verification (both directions):**
- `curl -k -u admin https://localhost:9200` with the old password → **Unauthorized**.
- Same test with the new password → OpenSearch cluster info returned.
- First attempt failed because the copied password was incomplete (selection stopped at a special character). Re-copied by dragging the full string.

## 4. First triage on my own SIEM

Filtered the Discover view for rule levels 7 to 11 on `wazuh-server` and added the columns `rule.description`, `rule.level` and `rule.id`. The 8 medium alerts came from 2 rules:

| Rule | Description | Verdict |
|---|---|---|
| 531 | Partition usage reached 100% (disk space monitor) | **True positive, not malicious.** Real disk exhaustion caused by an undersized virtual disk. Resolved. |
| 533 | Listened ports status (netstat) changed | **True positive, not malicious (likely).** Consistent with my own reboots, network change and service restarts during setup. Not investigated in depth. |

## 5. Victim VM: attempts and decisions

**Windows 11 VM (abandoned):**
- The installer stayed on a black screen.
- The VirtualBox status bar showed the "turtle" icon with **Execution Engine: native API**: VirtualBox was running on top of the Windows hypervisor instead of using VT-x directly, which is much slower.
- `msinfo32` showed **Virtualization-based security: Running** with **Hypervisor-enforced Code Integrity** (Memory Integrity), and only **1.29 GB** of free RAM with both VMs on.
- Disabling Memory Integrity removed HVCI, but VBS kept running and a hypervisor was still detected. No Hyper-V related Windows features were enabled.
- Decision: delete the Windows VM and its ISO, and **turn Memory Integrity back on** instead of making further changes to the host boot configuration.

**Linux Mint VM (not installed):**
- Discovered the VM had always been booting from the live ISO (the "Install Linux Mint" icon was on the desktop), so nothing was ever persisted.
- The installer crashed twice: once in the timezone step (`ubi-timezone.py`, `geoname_cb`, `AttributeError: 'NoneType' object has no attribute 'get_data'`) and once in partitioning after relaunching in the same session (`ubi-partman failed with exit code 10`).

**Current decision:** use **Ubuntu Server 24.04 LTS** as the victim. It has no GUI (lighter under the slower hypervisor mode) and Wazuh has tested agent compatibility with 24.04.

## Next steps

- [ ] Install Ubuntu Server 24.04 LTS (NAT for internet + Host-only to reach Wazuh)
- [ ] Install and enroll the Wazuh agent
- [ ] First attack simulation: SSH brute force against the Ubuntu server, detected by Wazuh
