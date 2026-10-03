---
title: "TryHackMe: Greenholt Phish Lab Writeup"
description: Analyzing a fake SWIFT payment email, from the red flags in the message to the headers, SPF/DMARC and the malicious attachment.
date: 2026-10-02 18:45:00 +0300
categories: [SOC Operations, Phishing Analysis]
tags: [tryhackme, phishing, email-analysis, header-analysis, spf, dmarc, virustotal, agent-tesla]
---

Room: [Phishing Emails 5 (Greenholt Phish)](https://tryhackme.com/room/phishingemails5fgjlzxc)

## Scenario

A sales executive at Greenholt PLC reported a suspicious email received from a known customer. The message had a generic greeting, an unexpected request for a money transfer and an unsolicited attachment, and according to the employee this isn't how the customer usually writes. The email was escalated to the SOC, and the goal is to analyze it and decide if it's legitimate or phishing.

## The email

![The email in Thunderbird](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/01-email-top.png){: w="700" }

![The bottom of the email](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/02-email-bottom.png){: w="700" }

Main artifacts:

- **Subject:** `webmaster@redacted[.]org your: Transfer Reference Number:(09674321)`
- **Display name:** Mr. James Jackson
- **From:** `info@mutawamarine[.]com`
- **Reply-To:** `info.mutawamarine@mail[.]com`
- **To:** `webmaster@redacted[.]org`
- **Transaction date in the body:** `10-06-2020 09:18:55`
- **Attachment:** `SWT_#09674321____PDF__.CAB`

The first suspicious thing is the difference between From and Reply-To. The sender claims to write from `info@mutawamarine[.]com`, but any reply goes to `info.mutawamarine@mail[.]com`, an address on a free webmail service.

The second one is the company. The From address belongs to the `mutawamarine[.]com` domain, but the signature says the sender works for SEC MARINE SERVICES PTE LTD. The domain and the company name don't match, which points to impersonation.

The third is the attachment name. `SWT_#09674321____PDF__.CAB` has "PDF" in the name to make the file look harmless. Windows hides known file extensions by default, so the victim would only see `SWT_#09674321____PDF__` and think it's a PDF, when the real extension is `.CAB`.

The fourth is the financial lure. A SWIFT transfer of $149,650 USD with a "receipt of payment" attached is meant to make the victim curious and open the file.

Finally, the greeting is `Good day webmaster@redacted[.]org ,` instead of a name, because the attacker doesn't know who they're writing to, and there's a grammar mistake ("funds has been transferred"). Both fit a generic, mass-sent phishing email.

## Headers

I opened the message source in Thunderbird to look at the headers.

![Message source with the Received headers](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/03-headers-source.png)

The originating IP is **`192.119.71[.]157`**. In the same `Received` line the sending server used `helo=mutawamarine[.]com`, and the envelope-from is `info@mutawamarine[.]com`, so the Return-Path domain is `mutawamarine[.]com`. The spam filter on the receiving server marked it `X-Spam-Status: No`, so it went straight through.

Looking up the IP:

![IP lookup](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/04-ip-lookup.png){: w="700" }

The IP belongs to **HostPapa**, in a data center in Buffalo, New York.

## SPF and DMARC

Next I checked the SPF and DMARC records of the Return-Path domain, `mutawamarine[.]com`, using MXToolbox.

SPF:

```text
v=spf1 include:spf.protection.outlook.com -all
```

![SPF record](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/05-spf-lookup.png){: w="700" }

This only allows Microsoft Outlook servers to send email for the domain, and everything else is rejected (`-all`). The email came from a different IP, not from Outlook.

DMARC:

```text
v=DMARC1; p=quarantine; fo=1
```

![DMARC record](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/06-dmarc-lookup.png){: w="700" }

The policy is `quarantine`, so emails that fail the DMARC check should be sent to quarantine.

## The attachment

I downloaded the attachment in the VM and got its SHA256 hash:

```bash
sha256sum SWT_#09674321____PDF__.CAB
```

```text
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
```

![sha256sum output](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/07-sha256sum.png)

Then I searched the hash on VirusTotal.

![VirusTotal details](/assets/img/posts/2026-10-02-tryhackme-greenholt-phish-lab/08-virustotal.png){: w="700" }

49 out of 64 security vendors flag it as malicious. The attacker put a `.CAB` extension on it, but the file is actually a **RAR** archive of about 400 KB (400.26 KB).

The detections classify it as an infostealer (`Trojan-PSW`, password stealer) from the Agent Tesla family. The payload is an obfuscated .NET (MSIL) executable made to avoid antivirus detection, and once it runs on the endpoint it steals credentials saved in browsers, email clients and FTP applications.

## Conclusion

This is a phishing email. The sender redirects replies to a free webmail address, impersonates a company that doesn't match the domain, and uses a fake payment receipt to get the user to open a malicious archive.

## Recommended actions

1. **Email filtering:** block the domain `mutawamarine[.]com` and the address `info.mutawamarine@mail[.]com` at the email gateway.
2. **Network:** block outbound traffic to the IP `192.119.71[.]157` on the firewall.
3. **EDR / endpoint:** add the SHA256 hash `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` to the blocklist.
4. **Host isolation:** if anyone ran the attachment, isolate their system immediately and reset their passwords, including anything saved in the browser, email client or FTP applications.

The lab and the analysis are mine. I used Claude to help organize my notes and format the post.