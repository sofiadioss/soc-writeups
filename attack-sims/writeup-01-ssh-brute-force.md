# Write-up 01: Detecting an SSH brute-force attempt with Wazuh

**Date:** 2026-11-05
**Type:** Attack simulation + detection validation (home SOC lab)
**MITRE ATT&CK:** [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) (Tactic: Credential Access)

## Summary

I simulated an SSH brute-force attempt against a monitored Ubuntu server and validated that Wazuh detected it. Before running the attack, I wrote down the detection I expected based on the Wazuh documentation. The expected alert fired (rule **5712**, level 10). During the analysis I also found a **clock skew of roughly 40 to 55 seconds** (38 s in the alert timeline, about 53 s by `date -u`) between the SIEM and the endpoint, which made one alert appear **before** the event that caused it. I fixed the root cause and validated the fix with a second run.

## Lab environment

| Role | Host | IP (Host-only network) |
|---|---|---|
| SIEM | Wazuh 4.14.9 (official OVA, all-in-one) | 192.168.56.101 |
| Target | Ubuntu Server 24.04 LTS, OpenSSH, Wazuh agent 4.14.9 (agent ID 001, `ubuntu-lab`) | 192.168.56.103 |
| "Attacker" | My Windows host (VirtualBox Host-only adapter) | 192.168.56.1 |

All VMs run in VirtualBox on an isolated Host-only network.

## Hypothesis

From the Wazuh documentation ([Detect an SSH brute-force attack](https://documentation.wazuh.com/4.2/learning-wazuh/ssh-brute-force.html)):

- Rule **5710** (level 5): `sshd: Attempt to login using a non-existent user`
- Rule **5712** (level 10): `sshd: brute force trying to get access to the system`, fires when 5710 matches **8 times from the same source IP within 120 seconds**

**Expected result:** repeated failed SSH logins with a non-existent user, in under 2 minutes, should trigger rule 5712 at level 10.

Note: the documentation page is for Wazuh 4.2. My server runs 4.14.9, so part of the goal was to confirm the rule still behaves this way.

## Attack simulation

From the Windows host, repeated several times:

```
ssh hacker@192.168.56.103
```

- `hacker` does not exist on the target.
- Wrong password on every prompt (3 prompts per connection), new connection each time.
- No attack tooling was used; the goal was to reproduce the log pattern of a brute-force attempt.

Run 1 started at about 17:14 (UTC-3). Run 2 ran from 18:50 to 18:52 (UTC-3).

## Evidence on the endpoint

Watching the authentication log live on the target (`sudo tail -f /var/log/auth.log`):

```
sshd[4971]: Failed password for invalid user hacker from 192.168.56.1 port 54958 ssh2
sshd[4971]: Connection reset by invalid user hacker 192.168.56.1 port 54958 [preauth]
sshd[4971]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1
```

Unrelated `CRON ... session opened for user root` lines also appeared in the same window. They are a scheduled system task, not part of the attack.

## Detection in Wazuh

Threat Hunting, filtered by `agent.name:ubuntu-lab`, last 15 minutes: **23 alerts** during run 1, from four rules:

| Rule | Level | Description | Meaning |
|---|---|---|---|
| 5710 | 5 | sshd: Attempt to login using a non-existent user | One per invalid-user attempt |
| 5503 | 5 | PAM: User login failed. | Same failures seen by the PAM layer |
| 2502 | 10 | syslog: User missed the password more than one time | Repeated password failures |
| **5712** | **10** | **sshd: brute force trying to get access to the system. Non existent user.** | **Correlation: the brute-force pattern** |

**Hypothesis confirmed.** Key fields of the 5712 alert:

| Field | Value |
|---|---|
| `data.srcip` | 192.168.56.1 |
| `data.srcuser` | hacker |
| `rule.frequency` | 8 |
| `rule.mitre.id` / `technique` | T1110 / Brute Force |
| `rule.mitre.tactic` | Credential Access |
| `location` | journald |
| `rule.groups` | syslog, sshd, authentication_failures |

The `previous_output` field lists the 7 earlier log lines that, together with the current one, reached the frequency of 8. They come from **two different SSH connections** (source ports 49648 and 49649), which shows the correlation is based on the **source IP**, not on a single session.

Observations:

- A single failed login (5710) is only level 5. Anyone mistypes a username. The **pattern** (many failures, same source, short time) is what makes it a brute-force alert.
- On Ubuntu 24.04 the agent read these events from **journald**, not from `/var/log/auth.log` directly.
- The alert is also mapped to compliance controls (PCI DSS, GDPR, HIPAA, NIST 800-53, TSC).

## Finding: clock skew between SIEM and endpoint

**Symptom.** The run-1 alert had:

- `timestamp` (Wazuh server clock): **17:15:39.556** (UTC-3) = 20:15:39 UTC
- `full_log` (Ubuntu clock): **20:16:17 UTC**

The alert appeared **38 seconds before** the event that triggered it, which is impossible if both clocks are correct.

**Investigation.**

1. `date -u` on both hosts: Ubuntu `20:27:29`, Wazuh `20:26:36`. The Wazuh server was behind by about 53 seconds (an approximate value, since it includes the few seconds between the two commands).
2. `timedatectl` on the Wazuh server: `NTP service: active`, `System clock synchronized: no`.

**Root cause.** The Wazuh VM was only connected to the Host-only network, so its NTP client could not reach any time server. The Ubuntu VM has a NAT adapter and was synchronized.

**Fix.** Added a second network adapter (NAT) to the Wazuh VM, keeping Adapter 1 on Host-only so the server kept its IP (192.168.56.101). NAT allows outbound connections only, so the dashboard is still not reachable from outside the host. After boot, `timedatectl` showed `System clock synchronized: yes`.

**Validation (run 2).**

| | Date | Event time (`full_log`) | Alert time (`timestamp`) | Difference |
|---|---|---|---|---|
| Run 1 (before fix) | 2026-11-05 | 20:16:17 UTC | 20:15:39 UTC | Alert **38 s before** the event |
| Run 2 (after fix) | 2026-11-05 | 21:52:06 UTC | 21:52:08 UTC | Alert **2 s after** the event |

Run 2 also triggered rule 5712 with the same fields (T1110, frequency 8, source 192.168.56.1, two connections on ports 50452 and 64359), so the detection is reproducible.

**Why it matters.** Incident investigation depends on an accurate timeline, especially when correlating logs from several sources. A skewed SIEM clock can put events in the wrong order and lead to wrong conclusions.

## Reading the detection rule

Run 1 continued after 5712 fired, but only one 5712 alert appeared. To understand why, I read the rule on my own server:

```
sudo grep -rn -A8 'id="5712"' /var/ossec/ruleset/rules/
```

```xml
<rule id="5712" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>sshd: brute force trying to get access to the system. Non existent user.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  ...
</rule>
```

(file: `/var/ossec/ruleset/rules/0095-sshd_rules.xml`, Wazuh 4.14.9)

- `frequency="8"` + `timeframe="120"`: 8 matches of rule 5710 within 120 seconds.
- `<same_source_ip />`: the matches must share the source IP. This is why failures from two different SSH connections were correlated.
- `ignore="60"`: per the Wazuh rules syntax documentation, the time in seconds to ignore the rule after it triggers, to avoid alert floods. This is the most likely explanation for the single 5712 alert during run 1. I did not record the exact timing of every attempt in run 1, so I could not fully confirm it against the timeline; a timed re-run is listed in the next steps.

The rule on 4.14.9 matches the one described in the 4.2 documentation.

## Follow-up investigation: did the source get in?

The key question after a brute-force alert is whether the same source achieved a **successful** login.

**Query** (Threat Hunting, time range: today):

```
agent.name:ubuntu-lab and data.srcip:192.168.56.1 and rule.groups:authentication_success
```

**First result: 0 hits.** However, I had logged in from 192.168.56.1 as `sofia` earlier that afternoon. Those logins happened **before the Wazuh agent was installed**, so they were outside the SIEM's visibility. Lesson: *no evidence is not evidence of absence*. The correct conclusion would be "no successful login **within the monitored period**", and the analyst must first confirm the visibility window.

**Second test.** With the agent running, I logged in legitimately from the same host (`ssh sofia@192.168.56.103`, correct password) and ran the same query:

| Field | Value |
|---|---|
| `rule.id` / `level` | **5715** / 3 |
| `rule.description` | sshd: authentication success. |
| `data.srcip` | 192.168.56.1 |
| `data.dstuser` | sofia |
| `full_log` | `Accepted password for sofia from 192.168.56.1 port 58712 ssh2` (22:03:06 UTC) |
| `timestamp` | 22:03:08 UTC |
| `rule.mitre` | T1078 Valid Accounts, T1021 Remote Services |

**Analysis.**

- The same source IP produced a brute-force alert (5712, user `hacker`, 21:52 UTC) and, 11 minutes later, a successful login for a **different, valid** user (`sofia`). Without context, this matches a classic pattern: guess credentials, then log in with a valid account (T1078).
- The success alert is only **level 3**. On its own it would not stand out; the link to the earlier brute force had to be made by the analyst, by pivoting on the source IP.
- An L1 analyst should not conclude "compromised" or "benign" from this alone. Next questions: Is 192.168.56.1 a known, authorized workstation? Does `sofia` normally log in from it at this time? What was done during the session (sudo, new files, outbound connections)?

**Verdict (with lab context).** Brute force: true positive, simulated and authorized. Login as `sofia`: benign, legitimate administration from my own host.

## Response and recommendations

What I would recommend if this alert came from an unknown source in a real environment:

**Triage and containment**

- Confirm whether the source IP belongs to an authorized workstation before taking action.
- If it does not, block the source IP at the firewall. Wazuh Active Response (for example, `firewall-drop`) can do this automatically for rule 5712.
- Check every account that logged in successfully from that IP and review what happened during those sessions.

**Hardening**

- Disable password authentication for SSH (`PasswordAuthentication no`) and use key-based authentication only.
- Disable direct root login (`PermitRootLogin no`).
- Limit attempts per connection (`MaxAuthTries`) and add rate limiting, for example with fail2ban.
- Allow SSH only from the management network instead of every host.

**Detection improvements**

- Create a correlation rule that raises the level of a successful login (5715) when the same source IP triggered 5712 shortly before. In this lab, that link had to be made manually.
- Monitor NTP synchronization on the SIEM itself, since a skewed clock breaks the incident timeline.

## Next steps

- Test failed logins for an **existing** user, which should trigger a different rule chain.
- Re-run the attack with timestamps for each attempt to confirm the effect of `ignore="60"`.
- Investigate how SSH key-only authentication changes this scenario.
