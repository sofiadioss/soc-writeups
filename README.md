# SOC Write-ups

Hands-on blue team practice: network traffic analysis, log triage and
detection, documented step by step.

Each write-up focuses on the **investigation process**: what I looked at,
why, what I found and how I would detect it again. Flags and room answers
are not published.

## Write-ups

| # | Topic | Tools | Platform | Date |
|---|-------|-------|----------|------|
| 01 | [Detecting an SSH brute-force attempt](attack-sims/writeup-01-ssh-brute-force.md) | Wazuh, Ubuntu Server, OpenSSH | Home SOC lab | 2026-11-05 |

## Home SOC lab

A Wazuh SIEM and an Ubuntu Server endpoint (Wazuh agent) on an isolated
VirtualBox network. The setup logs document every step, including what broke
and how I fixed it.

| # | Log | What it covers |
|---|-----|----------------|
| 01 | [Wazuh SIEM deployment and troubleshooting](lab-setup/01-wazuh-setup-and-troubleshooting.md) | Wazuh deployment, full-disk incident, default credentials, first triage |
| 02 | [Ubuntu target, Wazuh agent and time sync](lab-setup/02-ubuntu-target-and-agent.md) | Ubuntu Server install, agent enrollment, SIEM clock drift |

## Structure of each write-up

1. **Scenario:** the context of the lab or alert
2. **Tools:** what I used and why
3. **Investigation:** step by step reasoning
4. **Findings:** what happened, with evidence
5. **Detection:** how to catch it next time (MITRE ATT&CK when it applies)
6. **Lessons learned**

## About me

Computer Science student focused on SOC and blue team work.
[GitHub profile](https://github.com/sofiadioss) |
[LinkedIn](https://linkedin.com/in/sofia-dios-1359aa2b7)
