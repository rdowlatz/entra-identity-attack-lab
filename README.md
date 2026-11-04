# entra-identity-attack-lab
# Identity Attack Investigation Lab (Microsoft Entra ID)

A hands-on identity security lab: two identity-based attacks were simulated against a Microsoft Entra ID tenant and detected from its sign-in logs using **KQL**, then written up as a structured incident report with evidence, confidence levels, MITRE ATT&CK mapping, and remediation.

**Author:** Rosha Dowlatzarei · **Date:** November 2026

---

## Summary

| Scenario | Signal | MITRE |
| --- | --- | --- |
| Password spray | 6 accounts, 1 source IP, 50126 failures, under 3 minutes | T1110.003 |
| Impossible travel | One account, successful logins from CA and US, 2 minutes apart | T1078 |

Both attacks were confirmed from log evidence alone (no reliance on paid Identity Protection alerts), detected with KQL queries that transfer directly to Microsoft Sentinel, and addressed with the remediation below.

---

## Environment and methodology

The lab is a Microsoft Entra ID tenant on the **Free** licensing tier, with 8 test user identities. The Free tier has no Identity Protection, Conditional Access, or built-in risk detections (those require Entra ID P2), so detection was done **manually with KQL** rather than read from automated alerts. This was a deliberate choice: writing the detection logic demonstrates the analytical skill directly, instead of reading a dashboard.

Sign-in logs were streamed from Entra ID to an Azure **Log Analytics workspace** via a diagnostic setting (`SignInLogs` and `NonInteractiveUserSignInLogs`). Detection queries were written in **KQL** (Kusto Query Language) and run against the `SigninLogs` table.

Each attack was simulated manually against the lab's own accounts, producing the same log pattern a real attack generates without running external tooling against live infrastructure. Security defaults are enabled on the tenant (legacy authentication blocked), so the spray ran against the standard interactive sign-in endpoint.

**Key log fields used:** `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `LocationDetails` (city / country), `ResultType`, `ResultDescription`, `AppDisplayName`.

**Result codes observed:**

| Code | Meaning |
| --- | --- |
| 0 | Successful sign-in |
| 50126 | Invalid username or password (failed credential check) |
| 50140 | "Keep me signed in" interrupt (benign noise, not an attack) |

---

## Scenario 1: Password spray

**Finding:** A single source IP attempted one password against 6 different accounts within a 3-minute window, producing 6 failed-credential events. This is a password spray.

### Timeline

| Field | Value |
| --- | --- |
| First attempt | 2026-11-03 23:50:38 UTC |
| Last attempt | 2026-11-03 23:53:27 UTC |
| Duration | 2 min 49 sec |
| Source IP | 206.12.177.66 |
| Failed attempts | 6 |
| Distinct accounts targeted | 6 |
| Result code | 50126 (invalid credentials) |
| Application | OfficeHome |

### Evidence

The pattern that confirms a spray rather than an isolated login mistake:

- **One IP, many accounts.** Six distinct users failed from the same address.
- **One password.** Each account saw a single failed attempt, consistent with one guessed password tried across the directory (spraying stays under lockout thresholds by not repeating against one account).
- **Tight window.** All six failures fell inside 2 minutes 49 seconds. No legitimate scenario produces six different users failing from one IP that fast.
- **Uniform result.** Every event was code 50126, from the same application (OfficeHome).

![Password spray detection row](screenshots/spray-detection.png)
![Password spray raw events](screenshots/spray-raw-events.png)

### Detection

The detection (see [`queries/password-spray-detection.kql`](queries/password-spray-detection.kql)) groups failures by source IP and flags any IP that failed against 5 or more distinct accounts. Against this data it returned a single row: the attacking IP, 6 failed attempts, 6 targeted accounts, with the full user list and time window.

### Assessment

Confidence: **High.** One source, six distinct targets, a single uniform failure code, and a sub-3-minute window are characteristic of automated password spraying with no benign explanation.

### MITRE ATT&CK

| Tactic | Technique |
| --- | --- |
| Credential Access (TA0006) | T1110.003 - Brute Force: Password Spraying |

---

## Scenario 2: Impossible travel

**Finding:** One account signed in successfully from Vancouver, Canada and then from Los Angeles, United States just 2 minutes apart. No real travel covers that distance in that time, so one of the two sessions is not the legitimate user.

### Timeline

| Field | Value |
| --- | --- |
| Account | (test user) |
| Sign-in 1 | 2026-11-04 00:41:14 UTC - Vancouver, CA |
| Sign-in 2 | 2026-11-04 00:43:07 UTC - Los Angeles, US |
| Time between | 2 minutes |
| Both results | Success (code 0) |

### Evidence

- **Same account.** Both sessions authenticated as the same user.
- **Both succeeded.** Unlike the spray, these are successful logins (code 0), which is what makes impossible travel dangerous: valid credentials, used from two places.
- **Two countries, 2 minutes apart.** The country changed from CA to US between consecutive sign-ins with only 2 minutes elapsed.
- The repeated Los Angeles entries after the first are the same session re-authenticating (token refresh, app re-auth). They did not trigger the detection because the country did not change, the logic working correctly.

![Two-location sign-in list](screenshots/two-location-list.png)
![Impossible travel detection row](screenshots/impossible-travel-detection.png)

### Detection

The detection (see [`queries/impossible-travel-detection.kql`](queries/impossible-travel-detection.kql)) sorts each user's successful sign-ins in time order, compares each to the one before it, and flags any case where the same user's country changed between consecutive logins. It returned one row: the user, CA to US, 2 minutes apart.

### Assessment

Confidence: **High that the geography is inconsistent; the specific account's compromise is simulated.** In this lab the second login was generated with a VPN, so it is known-benign. In production, the same signal would warrant treating the account as potentially compromised pending confirmation.

### MITRE ATT&CK

| Tactic | Technique |
| --- | --- |
| Initial Access (TA0001) / Defense Evasion (TA0005) | T1078 - Valid Accounts |

---

## What the evidence supports vs what remains uncertain

### Supported

- The password spray clearly happened: six accounts, one IP, one failure code, under 3 minutes. The log pattern is unambiguous.
- The impossible-travel sign-in shows a geographically inconsistent authentication for one account that merits investigation.
- The detection logic is sound and repeatable: both queries fire on the attack data and stay quiet on benign activity (the 50140 noise and the US-to-US repeat logins did not trip them).

### Uncertain

- **Spray detection threshold.** The rule flags an IP that fails against 5+ distinct accounts, a tuning choice with a tradeoff: too low and normal password mistakes become false positives; too high and a slow, low-and-slow spray slips under it. The threshold should be tuned to the size of the real environment.
- **Impossible travel is a signal, not a verdict.** A country change in a short window does not by itself prove compromise. Legitimate causes exist: a corporate VPN, a proxy, a cloud service signing in on the user's behalf, or mislocated IP geolocation. It should feed an investigation, not an automatic block, unless paired with other risk signals.
- **IP geolocation accuracy.** Location is inferred from IP, which can be wrong or deliberately masked. The lab "travel" was produced with a VPN, which is itself the point: an attacker can place themselves anywhere, so IP location is evidence, not proof.
- **Free-tier retention.** The Free tier keeps sign-in history for only 7 days in the portal. Routing logs to Log Analytics extends retention, but an investigation started late could lose evidence.
- **Simulated scope.** Both attacks were run manually against lab accounts. A real spray would use automated tooling at higher volume, and a real impossible-travel case would lack the known-benign VPN explanation.

---

## Recommended actions

### Immediate (if this were a real incident)

1. For the spray, confirm whether any targeted account also shows a **success** (code 0) from the attacking IP. A success after the failures means that account is compromised: reset its password and revoke active sessions.
2. For the impossible-travel account, contact the user to confirm the second location. If not them, reset credentials, revoke sessions, and review what the session accessed.
3. Block or rate-limit the source IPs at the identity or network layer.

### Preventive controls

| Control | What it stops | Note |
| --- | --- | --- |
| Enforce MFA on all users | A sprayed or stolen password alone no longer grants access | Strongest single control against both scenarios |
| Conditional Access (named locations, risk-based) | Blocks or challenges sign-ins from unexpected countries | Requires Entra ID P1/P2 |
| Smart lockout / password protection | Slows spraying, bans common passwords | Password Protection present on Free tier |
| Keep legacy auth blocked | Removes the non-MFA sign-in path spraying prefers | Already enforced via Security defaults |
| Identity Protection (risk detections) | Automates impossible-travel and spray detection | Requires Entra ID P2 |

### Detection improvements

- Convert both KQL queries into scheduled alert rules (Microsoft Sentinel, or an Azure Monitor alert) so detection runs continuously instead of on demand.
- Add a correlation rule: a spray against an account **followed by** a success from a new location is a far stronger compromise signal than either alone.
- Tune the spray threshold to the real directory size and monitor the false-positive rate.

---

## Repository contents

```
entra-identity-attack-lab/
├── README.md                              This report
├── queries/
│   ├── password-spray-detection.kql       Detection: 5+ accounts failed from one IP
│   ├── impossible-travel-detection.kql    Detection: country change between logins
│   └── investigation-queries.kql          Supporting investigation queries
└── screenshots/                           Evidence (see screenshots/README.md)
```

## Skills demonstrated

Microsoft Entra ID · Azure Log Analytics · KQL · SOC detection engineering · incident investigation and reporting · MITRE ATT&CK · identity and authentication security
