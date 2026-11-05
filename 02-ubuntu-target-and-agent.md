# Lab Setup Log 02: Ubuntu target, Wazuh agent and time sync

**Date:** 2026-11-05
**Goal:** Add a monitored Linux endpoint to the lab and connect it to the Wazuh SIEM.

## Environment (after this log)

| Role | VM | Network | IP |
|---|---|---|---|
| SIEM | Wazuh 4.14.9 OVA | Adapter 1: Host-only, Adapter 2: NAT | 192.168.56.101 |
| Target | Ubuntu Server 24.04 LTS (`ubuntu-lab`) | Adapter 1: NAT, Adapter 2: Host-only | 192.168.56.103 |
| Host | Windows 11 (VirtualBox 7.2) | Host-only | 192.168.56.1 |

RAM budget: 6 GB (Wazuh) + 2 GB (Ubuntu), leaving about 8 GB for the host.

## 1. Choosing the target

- After the Windows 11 and Linux Mint attempts in log 01, I chose **Ubuntu Server 24.04 LTS**: no GUI, so it runs well even with VirtualBox in the slower Hyper-V mode.
- I picked **24.04** instead of the newer 26.04 because I found evidence of Wazuh agent testing on 24.04 and none for 26.04 with Wazuh 4.14.

## 2. ISO integrity check

Downloaded `ubuntu-24.04.3-live-server-amd64.iso` from `releases.ubuntu.com/24.04` and verified it against the official `SHA256SUMS` file:

```powershell
(Get-FileHash "$env:USERPROFILE\Downloads\ubuntu-24.04.3-live-server-amd64.iso" -Algorithm SHA256).Hash -eq "<official hash>"
```

Result: **True**.

## 3. VM and installation

- VM `UBUNTU-LAB`: 2 GB RAM, 2 CPUs, 25 GB dynamic disk, unattended installation disabled.
- **Network:** Adapter 1 NAT (internet for packages) and Adapter 2 Host-only (path to Wazuh). The installer showed `enp0s3` = 10.0.2.15 and `enp0s8` = 192.168.56.103.
- **Keyboard:** Portuguese (Brazil). In the Wazuh VM (US layout by default) characters like `/` were on the wrong keys; on this VM they worked.
- **Storage:** whole virtual disk, **LVM disabled** so the root filesystem would use the full disk (confirmed later: `Usage of /: 19.2% of 24.44GB`).
- **OpenSSH server installed**, password authentication allowed: SSH is the attack surface for the first simulation.

**Problems during installation:**
- The first installation attempt failed near the end. I did not capture the error message, so the cause is unknown.
- In the second attempt, the kernel printed `soft lockup - CPU#1 stuck for 44s! [unattended-upgr]` while installing security updates. I treated it as a symptom of the slow virtualization mode (similar to the `clocksource` warnings on the Wazuh VM) and waited; the installation completed.
- The installer then stayed on **"Rebooting..."** for over an hour. Since every installation step had completed in the log, I ejected the ISO (forced) and reset the VM. It booted from disk: `Ubuntu 24.04.3 LTS ubuntu-lab tty1`.

## 4. Post-install

- Applied updates: `sudo apt update && sudo apt upgrade -y` (77 updates available).
- Ignored the `do-release-upgrade` prompt to 26.04.1 to stay on the version with confirmed agent compatibility.
- The Wazuh dashboard later reported the OS as **Ubuntu 24.04.5 LTS**. Likely the point release brought by the upgrade; not verified.
- Snapshot **`base-limpa`**: Ubuntu installed and updated, no agent.

## 5. Wazuh agent

Generated the install command in the dashboard (**Deploy new agent** → Linux DEB amd64, server 192.168.56.101, name `ubuntu-lab`) and reviewed it before running: official package server, agent version 4.14.9 matching the server.

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.9-1_amd64.deb && sudo WAZUH_MANAGER='192.168.56.101' WAZUH_AGENT_NAME='ubuntu-lab' dpkg -i ./wazuh-agent_4.14.9-1_amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verification: service logs showed all components started (`wazuh-execd`, `wazuh-syscheckd`, `wazuh-logcollector`, `wazuh-modulesd`) and **agent 001 `ubuntu-lab` appeared as Active** in the dashboard.

Snapshot **`agente-ok`**: agent installed and active.

**Note:** right after boot, SSH to the Ubuntu VM timed out several times and later worked. Most likely the services were still starting (slow boot in this virtualization mode). Not confirmed.

## 6. Incident: lost dashboard admin password

The random admin password generated in log 01 had not been saved. Recovery:

1. Saved a new password in the password manager **first**.
2. SSH into the Wazuh VM as `wazuh-user` (password still known).
3. Changed only the admin user with the official tool:
   ```
   sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p '<new password>'
   ```
4. Cleared the shell history (`history -c`), since the password was typed in the command.
5. Logged in to the dashboard with the new password.

**Lesson:** a new credential goes into the password manager before it is applied.

## 7. Incident: SIEM clock drift

Found during write-up 01: a Wazuh alert timestamp was 38 seconds **earlier** than the event that caused it.

- `date -u`: Ubuntu 20:27:29, Wazuh 20:26:36 (Wazuh behind by roughly 50 seconds).
- `timedatectl` on Wazuh: `NTP service: active`, `System clock synchronized: no`.
- Root cause: the Wazuh VM was Host-only only, with no route to a time server.
- Fix: added **Adapter 2 = NAT** to the Wazuh VM (Adapter 1 kept on Host-only so the IP stayed 192.168.56.101). First attempt used "NAT Network" by mistake, which needs a named network; switched to plain "NAT".
- Result: `System clock synchronized: yes`. Interface names changed (NAT = `eth0` 10.0.3.15, Host-only = `eth1` 192.168.56.101), but the IP and SSH access were unchanged.
- Validated with a second attack run: alert 2 seconds **after** the event. Details in write-up 01.

## Next steps

- [ ] Snapshot of the Wazuh VM in its current state
- [ ] More attack simulations (failed logins for an existing user, Atomic Red Team on Linux)
