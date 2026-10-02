# THE-INVISIBLE-OAUTH
# SOC WAR ROOM — OPERATION: THE INVISIBLE OAUTH

Date: 01 October 2026
Role: SOC Analyst
Incident Type: Suspected Identity Compromise / OAuth Consent Abuse / Cloud Data Access
Affected User: [priya.sharma@corp.internal](mailto:priya.sharma@corp.internal)
Affected Endpoint:  HR-WS-089
Severity: High — pending evidence confirmation



 1. EXECUTIVE ASSESSMENT

The initial alert should not be closed as simple MFA fatigue.

The observed sequence is:

MFA approval → New OAuth application consent → High-value Graph permissions → Large Graph reads → SharePoint access → Impossible-travel signal

This creates a strong correlation between identity activity and subsequent application-based access to cloud data.

The current working hypothesis is:

An attacker may have socially engineered the user into approving an authentication request and then obtained authorization for a newly consented OAuth application, allowing access to Microsoft Graph resources.

However, I would not yet label this as confirmed token theft or MFA bypass.

The investigation must establish:

1. Whether the MFA approval was associated with an attacker-controlled sign-in.
2. Whether `DocuSign-Prod-Viewer` is legitimate or impersonating a legitimate application.
3. Whether consent was user-level or admin-level.
4. Exactly which delegated/application permissions were granted.
5. Whether the subsequent Graph activity was performed using the newly authorized application.
6. Whether data was merely accessed or actually exfiltrated.

Microsoft Entra audit logs specifically record application permission activity such as “Consent to application”  and “Add delegated permission grant,” making these primary evidence sources.



 2. INITIAL TRIAGE

 2.1 Incident facts currently available

| Time     | Event                             | Initial assessment                                   |
| -------- | --------------------------------- | ---------------------------------------------------- |
| 08:10    | Priya login from India            | Baseline/reference event                             |
| 08:14:22 | MFA approved                      | Suspicious because user says she did not initiate it |
| 08:15:04 | `DocuSign-Prod-Viewer` consented  | Critical pivot point                                 |
| 08:17:33 | Large Graph mailbox reads         | Suspicious post-consent activity                     |
| 08:22:11 | Outlook.exe → Microsoft Graph     | Requires correlation with identity/app telemetry     |
| 08:29:45 | 47 SharePoint files accessed      | Potential data exposure                              |
| 08:31:02 | Impossible travel India → Nigeria | Strong contextual indicator                          |
| 08:31+   | Defender no threat found          | Does not clear identity/cloud activity               |

Important: Defender reporting no endpoint threat does not eliminate an identity/OAuth attack. An OAuth-based attack can operate through cloud APIs without requiring obvious malware execution on the endpoint.



2.2 Evidence I need first

 Identity

 User principal name
 Entra Object ID
 Sign-in event ID
 Correlation ID
 MFA authentication method
 MFA result
 Authentication requirement
 Source IP
 ASN
 Geo-location
  User agent
 Device ID
 Conditional Access result

Microsoft's sign-in logs provide authentication details and Conditional Access information, so these should be checked rather than relying only on the headline MFA event.

 OAuth application

* App ID / Client ID
* Service Principal Object ID
* App display name
* Publisher
* Publisher verification status
* Application registration age
* Reply URLs / redirect URIs
* Application owner
* Permission type
* Granted scopes
* Consent type
* Consent actor
* Consent timestamp
* Other users who authorized the same App ID

### Graph activity

* Graph endpoint
* HTTP method
* Timestamp
* App ID
* User
* Source IP
* User agent
* Resource accessed
* Number of requests
* Number of messages accessed
* SharePoint site
* File names/IDs
* Download activity
* Response status

### Endpoint

* HR-WS-089 process tree
* Browser activity
* Outlook process activity
* Sysmon EID 1
* Sysmon EID 3
* DNS activity
* Browser history if available
* Any suspicious link/file immediately preceding the MFA event



 3. PERMISSION ANALYSIS

The requested permissions are significant.

`Mail.Read`

Allows an application to read the signed-in user's mailbox when used as a delegated permission.

 `Files.Read.All`

Allows an application, in delegated context, to read files that the signed-in user can access.

Therefore, `Files.Read.All` does **not automatically mean the attacker can read every file in the tenant** when operating as the user. The effective access is constrained by the user's own permissions.

 `offline_access`

This requests the ability for the application to maintain access through refresh-token mechanisms rather than requiring the user to interactively authenticate every time.

That makes the combination particularly important from an investigation perspective.

 Analyst assessment

I would classify the permission set as:

High-risk in this context

—not simply because the names contain `.All`, but because they were apparently granted immediately before large-scale mailbox and SharePoint access.

Microsoft's current recommended consent controls specifically treat permissions such as `Files.Read.All` and `Mail.Read` as permissions that should not normally be freely end-user consentable under the recommended low-risk policy.



 4. HYPOTHESIS-DRIVEN INVESTIGATION

 H1 — MFA social engineering followed by illicit OAuth consent

 Hypothesis

 Priya was targeted with an unsolicited MFA request. After she approved it, the attacker caused or induced authorization of an OAuth application and used the resulting authorization to access Graph resources.

 Evidence required

* Entra sign-in logs
* Authentication Details
* MFA event
* Application consent audit event
* App ID
* Permission grant
* Graph activity
* Source IP/ASN
* User agent
* Conditional Access result

 Expected indicators

* Unusual source IP
* Unusual ASN/location
* MFA approval inconsistent with user's activity
* New application consent immediately after MFA
* New permissions
* Graph activity shortly after consent
* New IP/user agent for Graph access
* High request volume
* Sensitive SharePoint access

 Possible false positives

* Legitimate new business application
* IT-approved DocuSign integration
* User intentionally installing a productivity application
* Automated mailbox synchronization

Investigation conclusion

Current status: Supported but not confirmed.

The strongest evidence is the temporal chain:

`MFA approval → OAuth consent → Graph access`

Confirmation requires proving that the same identity/app/session relationship exists across the logs.



 H2 — Legitimate business application / normal synchronization

Hypothesis

 `DocuSign-Prod-Viewer` is an approved business application and its Graph activity represents normal synchronization.

 Evidence required

* IT application inventory
* Application owner
* Publisher verification
* App registration date
* Change/request ticket
* Approved permissions
* Existing users
* Historical Graph volume
* Historical SharePoint access
* Normal source IPs
* Normal user agents

 Expected indicators

* Application existed before incident
* Known publisher
* IT ownership
* Approved change request
* Same App ID used by other legitimate users
* Stable Graph traffic
* Expected sites/mailboxes accessed
* No unusual IP changes

 False positives

A legitimate application can still be abused if an attacker obtains a user's authorization.

### Investigation conclusion

Currently not eliminated.

The name `DocuSign-Prod-Viewer` alone is not proof of legitimacy.

Publisher verification and tenant application inventory must be checked.



H3 — Compromised OAuth access used for BEC/data theft

 Hypothesis

The attacker obtained application-based access to Priya's resources and used Microsoft Graph to collect information for business email compromise or data exfiltration.

 Evidence required

* Mailbox access logs
* Graph endpoints
* Message IDs/resources accessed
* SharePoint access logs
* File download events
* Inbox rule changes
* Forwarding rules
* OAuth activity
* Other users accessed
* External destinations
* DLP alerts

 Expected indicators

* Large mailbox reads
* Sensitive email searches
* Finance-related messages
* SharePoint access outside normal business behavior
* Bulk downloads
* Inbox forwarding
* New rules
* Access from unfamiliar ASN
* Same App ID used against multiple users

 False positives

* Backup/sync tools
* Document management applications
* E-discovery
* Migration jobs
* Security/compliance tooling

 Investigation conclusion

Suspicious data-access activity is already indicated, but exfiltration is not yet proven.

Accessing 47 files establishes potential data exposure. We still need evidence showing whether those files were downloaded/transferred outside the environment.


 5. ATTACK TIMELINE

```text
08:10
│
├── Priya authenticates from India
│
08:14:22
│
├── MFA approval
│   └── User states she did not initiate the request
│
08:15:04
│
├── OAuth application consent
│   └── DocuSign-Prod-Viewer
│   └── Mail.Read
│   └── Files.Read.All
│   └── offline_access
│
08:17:33
│
├── Large Graph mailbox activity
│
08:22:11
│
├── Outlook.exe → Microsoft Graph
│   └── New OAuth token reported
│
08:29:45
│
├── 47 SharePoint files accessed
│   └── Finance-Board-2026
│
08:31:02
│
└── Impossible Travel
    └── India → Nigeria


 Critical pivot

08:15:04 — OAuth consent

This is the point where the investigation should move from:

> "Was this just MFA fatigue?"

to:

> **"What authorization was granted, by whom, to which application, and what did that application subsequently access?"**

OAuth consent is an authorization event; it can allow an application to access protected resources on behalf of the user.

---

# 6. IDENTITY & OAUTH HUNT

## Question 1 — Was the MFA push from an attacker-controlled IP?

**Not established yet.**

The scenario says the MFA-approved event has IP `167.x.x.x` associated with Nigeria ASN, but I need to confirm:

* IP in sign-in event
* ASN
* ISP/provider
* VPN/proxy/TOR reputation
* historical use by Priya
* device associated with sign-in
* user agent
* Conditional Access result

I would avoid calling an IP "attacker-controlled" solely because it is foreign.

---

## Question 2 — Is the OAuth app legitimate?

**Unknown.**

I would investigate:

```text
App ID
   ↓
Service Principal
   ↓
Publisher
   ↓
Publisher verification
   ↓
Application owners
   ↓
Registration date
   ↓
Redirect URIs
   ↓
Tenant application inventory
   ↓
Other users
----

A familiar-looking application name is not sufficient evidence of legitimacy.



 Question 3 — What permissions were granted?

Known:

text
Mail.Read
Files.Read.All
offline_access


These provide potentially valuable access to mailbox and file data in the user's authorization context.



 Question 4 — User or admin consent?

This is a critical investigation field.

I would look for:

```text
Consent actor
Consent type
Principal
App ID
Permission grant
Timestamp
```

Microsoft Entra records user consent and delegated permission grants in application-management audit activity.

If the consent was tenant-wide admin consent, the blast radius could be substantially larger.

If it was user consent, the initial authorization scope may be centered on Priya's delegated access.

---

 7. LATERAL & DATA ACCESS HUNT

I would pivot on:

 User

```text
priya.sharma@corp.internal
```

Search:

* All enterprise apps authorized in previous 7 days
* New permissions
* New OAuth applications
* Other suspicious sign-ins
* MFA events
* Impossible travel
* Other ASNs

 App ID

Search the entire tenant for:

```text
App ID = <DocuSign-Prod-Viewer App ID>
```

Identify:

* Other consenting users
* First seen
* Last seen
* Permissions
* Graph activity
* Source IPs

Source IP

Search:

```text
167.x.x.x
```

across:

* Entra sign-ins
* MFA events
* Other users
* OAuth consent
* Graph activity

If multiple users received suspicious MFA approvals from the same infrastructure, the incident scope expands from single-user compromise to tenant-wide campaign.

---

 8. BEC HUNT

Because `Mail.Read` is available, I would specifically investigate:

* Inbox rules
* Forwarding rules
* Suspicious finance emails
* Password-reset emails
* Vendor/payment conversations
* Recently accessed messages
* Sensitive attachments
* Messages containing financial information
* External mailbox forwarding
* OAuth applications accessing mail

I would also hunt for Graph access to:

```text
/messages
/mailFolders
/mailFolders/{id}/messages
/drives
/sites
/drive/items
```

The exact endpoints available in the telemetry should determine the final conclusion.

---

# 9. SHAREPOINT HUNT

The 47 files from:

`Finance-Board-2026`

are a high-priority investigation point.

I would build:

| Field            | Evidence           |
| ---------------- | ------------------ |
| Site             | Finance-Board-2026 |
| User             | Priya              |
| App ID           | To retrieve        |
| IP               | To retrieve        |
| Timestamp        | 08:29:45 onward    |
| Files accessed   | 47                 |
| Sensitive files  | To classify        |
| Downloaded       | To verify          |
| External sharing | To verify          |
| Destination      | To verify          |

 Important distinction

File access ≠ confirmed exfiltration.

My report would say:

"47 files were accessed, creating potential data exposure. Evidence of actual exfiltration remains to be established."

That distinction is important in a real SOC report.

---

 10. WHAT I WOULD COLLECT BEFORE REVOKING TOKENS

I would preserve evidence **before destructive containment where operationally possible**, while still prioritizing containment if active abuse is continuing.

Evidence:

 Identity

* Sign-in logs
* MFA authentication details
* Conditional Access results
* IP/ASN
* Device ID
* User agent
* Correlation IDs

 OAuth

* App ID
* Service Principal ID
* Consent event
* Consent actor
* Consent type
* Granted permissions
* Publisher
* App registration metadata

Graph

* API endpoints
* timestamps
* source IP
* user agent
* accessed mailbox resources
* accessed SharePoint resources
* request volume

 Data

* 47 affected files
* sensitivity labels
* download events
* sharing events
* external access
* DLP alerts

 Persistence

* Inbox rules
* Forwarding
* Other OAuth apps
* Additional consent grants
* Other suspicious sessions

 Scope

* Same App ID across users
* Same IP across users
* Same MFA campaign across users
* Same application name/publisher pattern

Why not just revoke the token?

Because token revocation answers:

"Can the attacker continue using this authorization?"

It does not answer:

"What did they already access?"

Revoking sessions/tokens is an important containment action, but the investigation must still determine the historical access and whether the attacker created persistence or targeted additional users. Microsoft documents that access/refresh tokens have different lifetimes and that revocation does not necessarily instantly eliminate every existing access mechanism.

---

 11. CONTAINMENT PLAN

 Priority 1 — Stop active access

1. Revoke Priya's sessions/refresh tokens.
2. Block or disable suspicious application access.
3. Remove the malicious/suspicious consent.
4. If active compromise is confirmed, temporarily block the account or restrict sign-in.
5. Force password reset where credential compromise cannot be ruled out.
6. Re-register MFA if the authentication factor may have been compromised.

Microsoft provides administrative mechanisms for revoking a user's sessions/refresh tokens during suspected compromise.

---

 Priority 2 — Stop application persistence

Investigate:

```text
DocuSign-Prod-Viewer
        ↓
App ID
        ↓
Service Principal
        ↓
All granted permissions
        ↓
All users
        ↓
All consent events
```

If malicious:

* Remove consent
* Disable/delete the enterprise application according to IR procedures
* Search for copies/impersonating applications
* Search the App ID tenant-wide

Do not blindly delete an application before preserving its identifiers and evidence.

---

 Priority 3 — Endpoint validation

Isolate `HR-WS-089` if endpoint compromise remains plausible.

Investigate:

* Browser
* Outlook
* Sysmon
* PowerShell
* Processes
* Network connections
* Credential theft indicators
* Infostealer indicators
* Malicious links/files

The absence of a Defender alert does not terminate this investigation.

---

Priority 4 — Data protection

For `Finance-Board-2026`:

* Preserve DLP alerts
* Identify all 47 files
* Determine sensitivity
* Determine whether downloads occurred
* Identify external sharing
* Identify additional accounts accessing the same files

Notify:

* HR/business owner
* Finance/SharePoint data owner
* Incident Response lead
* Appropriate privacy/legal team according to organizational procedure

---

 12. DETECTION ENGINEERING

Detection Name

Suspicious OAuth Consent Followed by High-Risk Graph Access

 Objective

Detect:

 User consent + high-risk Graph permissions + anomalous identity context + subsequent Graph data access.

---

## Telemetry

```text
Microsoft Entra Audit Logs
+
Microsoft Entra Sign-in Logs
+
Microsoft Graph / Microsoft 365 activity telemetry
+
Conditional Access
```

Sysmon/Defender should be used as supporting telemetry rather than the primary detection source.

---

## Relevant fields

```text
user
userId
appId
appDisplayName
servicePrincipalId
publisher
consentType
permission
permissions
srcIP
ASN
country
userAgent
timestamp
graphEndpoint
resource
requestCount
```

---

 Sigma-like logic

```text
title:
  Suspicious OAuth Consent Followed by Graph Data Access

selection_consent:
  event.category = "ApplicationManagement"
  event.action IN (
      "Consent to application",
      "Add delegated permission grant"
  )

selection_high_risk:
  permissions CONTAINS ANY (
      "Mail.Read",
      "Files.Read.All",
      "Files.ReadWrite.All",
      "Sites.Read.All",
      "Mail.ReadWrite",
      "offline_access"
  )

selection_anomaly:
  source_ip IS_NEW_FOR_USER
  OR country IS_NEW_FOR_USER
  OR ASN IS_NEW_FOR_USER

selection_graph:
  graphEndpoint CONTAINS ANY (
      "/messages",
      "/mailFolders",
      "/drives",
      "/sites",
      "/drive/items"
  )

condition:
  selection_consent
  AND selection_high_risk
  AND (
      selection_anomaly
      OR selection_graph
  )
```

 Severity

High

 Why?

The detection does not trigger merely because someone created an OAuth application.

It looks for the stronger combination:

```text
NEW CONSENT
     +
HIGH-RISK PERMISSIONS
     +
ANOMALOUS IDENTITY CONTEXT
     +
RESOURCE ACCESS
```

This reduces the chance of treating every legitimate SaaS integration as malicious.

---

 13. FALSE POSITIVES

Possible legitimate cases:

* Approved DocuSign integration
* Microsoft-approved productivity tools
* Mail synchronization
* Document-management applications
* Security/compliance applications
* Migration projects
* E-discovery

Therefore the detection should enrich the alert with:

```text
Publisher
Application owner
Previous user activity
First-seen timestamp
Historical Graph volume
Approved application inventory
Change ticket
```

The analyst can then distinguish:

new suspicious consent

from

known enterprise application behavior.

---
14. SENIOR SOC QUESTION

 Which signal gives stronger context?

Single signal:

 MFA approved from unusual country

This is suspicious but ambiguous.

It could represent:

* VPN
* travel
* proxy
* false geo-location
* legitimate authentication
* MFA fatigue
* compromised identity

### Correlated signal:

```text
MFA APPROVED
      ↓
OAUTH CONSENT
      ↓
Mail.Read / Files.Read.All
      ↓
GRAPH MAIL READ
      ↓
SHAREPOINT BULK ACCESS
```

This provides much stronger investigative context because multiple independent telemetry sources describe a connected sequence.

The important detection-engineering principle is:

One event tells the SOC that something happened. Correlation tells the SOC what the activity may represent.

MITRE ATT&CK documents OAuth-based token abuse as a way adversaries can gain access to cloud resources through application authorization, including scenarios where a user is socially engineered into granting an application access.

---

# 15. WHY MFA IS NOT THE SECURITY BOUNDARY HERE

MFA successfully authenticated the user.

But authentication and authorization are different questions.

### Authentication

 "Is the user successfully authenticated?"

Authorization

 "What is this application now allowed to access on behalf of that user?"

In this scenario:

```text
MFA
 ↓
User authenticated
 ↓
OAuth authorization
 ↓
Application receives delegated access
 ↓
Graph
 ↓
Mailbox / SharePoint
```

Therefore, even though MFA worked, an attacker can potentially abuse the **authorization layer** after convincing the user to approve the wrong request.

That is why modern identity detection needs to monitor:

authentication + consent + permissions + application behavior + resource access.

---

 16. CURRENT INCIDENT VERDICT

 Working classification

Suspected OAuth consent abuse / identity compromise with potential cloud data exposure

 Confidence

Medium-High based on the scenario correlation, pending log validation.

Confirmed from supplied scenario

* Suspicious MFA approval
* New OAuth consent
* High-value permissions requested
* Large Graph activity
* SharePoint access
* Impossible-travel signal

### Not yet confirmed

* Malicious application
* Attacker-controlled IP
* Token theft
* Actual token replay
* Actual data exfiltration
* Endpoint compromise
* Tenant-wide compromise
* BEC

### Recommended next pivot

App ID + consent audit event → Graph activity → source IP/user-agent correlation.

That pivot should determine whether the OAuth authorization directly explains the subsequent data access.

---

#17. FINAL SOC ANALYST STATEMENT

 I would not close this incident as MFA fatigue because the MFA event is followed within minutes by a new OAuth consent grant and subsequent Graph-based access to mailbox and SharePoint data. The temporal relationship makes OAuth authorization abuse a strong working hypothesis, but I would not mark token theft or exfiltration as confirmed without correlating the Entra consent event, application identity, permission grant, Graph activity, source IP, and accessed resources. The immediate priorities are evidence preservation, application/consent validation, scope determination, and containment of active access.

Primary investigation principle:

Evidence before assumption. Correlation before conclusion. Containment without destroying the evidence needed to understand the blast radius.

 Primary references

Microsoft documents Entra application permission audit activity, including user consent and delegated permission grants.

Microsoft's consent guidance explains the distinction between user and admin consent and how permissions determine application access.

Microsoft's Graph permission documentation describes the effective scope of delegated `Files.Read.All` and `Mail.Read`.

MITRE ATT&CK documents OAuth/application-token abuse under T1528.
