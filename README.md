# 🔎 siem-detection-rules

Detection rules I wrote for the attacker behaviors a SOC sees most often. Each detection exists in two forms:

- **[Sigma](https://github.com/SigmaHQ/sigma)**: a vendor-neutral YAML format that converts to Splunk, Elastic, Microsoft Sentinel, QRadar, and more
- **Splunk SPL**: ready-to-paste searches with thresholds, grouping, and severity logic

Every rule is mapped to **MITRE ATT&CK**, documents its false positives, and is checked automatically by a validator that runs in GitHub Actions on every push.

---

## 📋 Detection Coverage

| Detection | Sigma rule | Splunk search | ATT&CK | Level |
|---|---|---|---|---|
| SSH brute force (+ success after failures) | [`ssh_auth_failures.yml`](sigma/linux/ssh_auth_failures.yml) | [`ssh_bruteforce.spl`](splunk/ssh_bruteforce.spl) | T1110.001 | Medium → Critical |
| New local Linux user created | [`new_local_user_created.yml`](sigma/linux/new_local_user_created.yml) | n/a | T1136.001 | Medium |
| Windows brute force / password spraying | [`failed_logon_bruteforce.yml`](sigma/windows/failed_logon_bruteforce.yml) | [`windows_bruteforce.spl`](splunk/windows_bruteforce.spl) | T1110.001, T1110.003 | Low → High |
| PowerShell with encoded command | [`powershell_encoded_command.yml`](sigma/windows/powershell_encoded_command.yml) | [`encoded_powershell.spl`](splunk/encoded_powershell.spl) | T1059.001, T1027 | High |
| Security event log cleared | [`security_log_cleared.yml`](sigma/windows/security_log_cleared.yml) | [`log_cleared_and_admin_changes.spl`](splunk/log_cleared_and_admin_changes.spl) | T1070.001 | High |
| User added to admin group | [`user_added_to_admin_group.yml`](sigma/windows/user_added_to_admin_group.yml) | [`log_cleared_and_admin_changes.spl`](splunk/log_cleared_and_admin_changes.spl) | T1098 | High |
| Scheduled task from suspicious path | [`scheduled_task_created.yml`](sigma/windows/scheduled_task_created.yml) | [`log_cleared_and_admin_changes.spl`](splunk/log_cleared_and_admin_changes.spl) | T1053.005 | Medium |

**ATT&CK tactics covered:** Credential Access · Execution · Persistence · Privilege Escalation · Defense Evasion

---

## 🚀 Using the Rules

**Convert Sigma to your SIEM's query language** with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):
```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p splunk_windows sigma/windows/powershell_encoded_command.yml
```

**Run a Splunk search:** paste any `.spl` file into the Splunk search bar and adjust `index=` to match your environment. Splunk Free works for a home lab.

**Validate the rules locally:**
```bash
pip install pyyaml
python3 validate_rules.py
```
```
7 rule(s) checked, 0 problem(s)
```

---

## 🧠 How I Approach Writing Detections

1. **Start from the attacker technique** (ATT&CK), not from whatever log happens to be available.
2. **Know the event:** 4625 vs 4624, logon type 3 vs 10, Sysmon EID 1 vs 4688.
3. **Use thresholds and context, not single events.** One failed login is noise; a success after 20 failures is an incident. The severity logic in the SPL reflects that.
4. **Write down false positives up front** so the next analyst can tune the rule instead of ignoring it.
5. **Test before shipping.** The validator catches broken YAML, missing ATT&CK tags, and conditions that reference selections that don't exist.

## 🗺️ Roadmap

- [ ] Replay attacks in my home lab (Atomic Red Team) and screenshot each rule firing
- [ ] Add Elastic (KQL) and Microsoft Sentinel (KQL) versions
- [ ] Sysmon rules: LSASS access (T1003.001), suspicious parent/child processes
- [ ] Linux: cron persistence, sudo abuse, reverse-shell command lines

---

Part of my [cybersecurity portfolio](https://github.com/kamronw23/Portfolio) · See also: [security-scripts](https://github.com/kamronw23/security-scripts)
