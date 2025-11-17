# ADCS Attack Detection Playbook

## Overview

This playbook provides comprehensive detection strategies, hunting queries, and monitoring configurations for identifying ADCS-based attacks in Active Directory environments.

---

## Table of Contents

1. [Event Log Monitoring](#event-log-monitoring)
2. [Detection Queries](#detection-queries)
3. [Behavioral Analytics](#behavioral-analytics)
4. [Network Detection](#network-detection)
5. [Automated Hunting](#automated-hunting)
6. [Incident Response](#incident-response)

---

## Event Log Monitoring

### Critical Security Events

#### Certificate Request Events (EventID 4886)
```
Log: Security
EventID: 4886
Description: Certificate Services received a certificate request

Key Attributes to Monitor:
- Requester: Who submitted the request
- Template: Which template was used
- Request Attributes: SAN specifications, unusual attributes
- Disposition: Request status
```

**Detection Logic:**
```
Alert if:
- Requester ≠ Certificate Subject SAN
- Request contains privileged account names in SAN
- Unusual template usage patterns
- High-privilege template requests from low-privilege accounts
```

---

#### Certificate Issued Events (EventID 4887)
```
Log: Security
EventID: 4887
Description: Certificate Services issued a certificate

Key Attributes:
- Requester
- Subject
- Certificate Template
- Serial Number
- Validity Period
```

**Detection Logic:**
```
Alert if:
- Certificate issued to privileged account (DA, EA, krbtgt)
- Subject ≠ Requester
- Template has known vulnerabilities
- Certificate issued outside business hours
- Unusual enrollment patterns
```

---

#### Kerberos TGT Request with Certificate (EventID 4768)
```
Log: Security (Domain Controller)
EventID: 4768
Description: Kerberos authentication ticket (TGT) was requested

Key Attributes:
- Account Name
- Pre-Authentication Type: 16 (Public Key/PKINIT)
- Client Address
- Certificate Issuer
- Certificate Serial Number
```

**Detection Logic:**
```
Alert if:
- PKINIT authentication from privileged accounts
- Certificate issuer: Unknown or unexpected CA
- Authentication from unusual IP/location
- Time-based anomalies (after-hours auth)
- Multiple rapid authentications
```

---

#### Active Directory Object Modification (EventID 5136)
```
Log: Security
EventID: 5136
Description: A directory service object was modified

Critical for ESC4 Detection:

Monitor modifications to:
- ObjectClass: pKICertificateTemplate
- Attributes:
  - msPKI-Certificate-Name-Flag
  - msPKI-Certificate-Application-Policy
  - msPKI-Enrollment-Flag
  - nTSecurityDescriptor (ACL changes)
```

**Detection Logic:**
```
Alert if:
- Template modifications by non-PKI admins
- ENROLLEE_SUPPLIES_SUBJECT flag added
- Client Authentication EKU added
- ACL modifications granting enrollment rights
```

---

### CA Audit Log Monitoring

**Location:** `C:\Windows\System32\CertSrv\CertEnroll\<CAName>.log`

**Monitor for:**
```
- "On behalf of" requests (ESC3)
- SAN attributes in requests
- Template usage statistics
- Revocation requests
- Failed enrollments
```

**Example Log Entry:**
```
[Request ID: 12345]
Requester: CORP\lowprivuser
Template: VulnerableTemplate
Request Attributes: upn=Administrator@corp.local
Disposition: Certificate issued
```

---

## Detection Queries

### Splunk Queries

#### ESC1/ESC6 Detection - SAN Mismatch
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4887
| rex field=Message "Requester:\s+(?<Requester>[^\n]+)"
| rex field=Message "Subject:\s+CN=(?<Subject>[^,\n]+)"
| rex field=Message "Certificate Template:\s+(?<Template>[^\n]+)"
| rex field=Message "upn=(?<SAN_UPN>[^,\s\n]+)"
| where isnotnull(SAN_UPN)
| eval Requester_Clean=lower(trim(Requester))
| eval SAN_Clean=lower(trim(SAN_UPN))
| where Requester_Clean != SAN_Clean
| eval Privileged_Target=if(match(SAN_UPN, "(?i)administrator|admin|krbtgt|domain admin"), "Yes", "No")
| where Privileged_Target="Yes"
| table _time, Requester, SAN_UPN, Template, Computer
| sort - _time
```

---

#### ESC3 Detection - Enrollment Agent Usage
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4887
| rex field=Message "Certificate Template:\s+(?<Template>[^\n]+)"
| rex field=Message "Requester:\s+(?<Requester>[^\n]+)"
| where Template="EnrollmentAgent" OR Template="EnrollmentAgentTemplate" OR match(Template, "(?i)agent")
| lookup privileged_accounts.csv user AS Requester OUTPUT is_privileged
| where is_privileged!="true"
| stats count by Requester, Template, Computer
| where count > 0
```

---

#### ESC4 Detection - Template Modifications
```spl
index=windows sourcetype=WinEventLog:Security EventCode=5136
| rex field=Message "Object DN:\s+(?<ObjectDN>[^\n]+)"
| rex field=Message "Attribute:\s+(?<Attribute>[^\n]+)"
| rex field=Message "SubjectUserName:\s+(?<Modifier>[^\n]+)"
| where match(ObjectDN, "CN=Certificate Templates")
| where Attribute IN ("msPKI-Certificate-Name-Flag", "msPKI-Certificate-Application-Policy", "nTSecurityDescriptor", "msPKI-Enrollment-Flag")
| lookup pki_admins.csv user AS Modifier OUTPUT is_pki_admin
| where is_pki_admin!="true"
| table _time, Modifier, ObjectDN, Attribute, NewValue, Computer
| sort - _time
```

---

#### PKINIT Authentication from Privileged Accounts
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4768
| rex field=Message "Account Name:\s+(?<AccountName>[^\n]+)"
| rex field=Message "Pre-Authentication Type:\s+(?<PreAuthType>[^\n]+)"
| rex field=Message "Certificate Issuer Name:\s+(?<CertIssuer>[^\n]+)"
| rex field=Message "Client Address:\s+(?<ClientIP>[^\n]+)"
| where PreAuthType="16"
| lookup privileged_accounts.csv user AS AccountName OUTPUT is_privileged
| where is_privileged="true"
| table _time, AccountName, CertIssuer, ClientIP, Computer
| sort - _time
```

---

### Microsoft Sentinel / Defender KQL Queries

#### ESC1/ESC6 Detection
```kql
SecurityEvent
| where EventID == 4887
| extend Requester = extract("Requester:\\s+([^\\\\\\r\\n]+\\\\[^\\r\\n]+)", 1, EventData)
| extend Subject = extract("Subject:\\s+CN=([^,\\r\\n]+)", 1, EventData)
| extend Template = extract("Certificate Template:\\s+([^\\r\\n]+)", 1, EventData)
| extend SAN = extract("upn=([^,\\s\\r\\n]+)", 1, EventData)
| where isnotempty(SAN)
| where Requester !contains SAN
| where SAN has_any ("Administrator", "krbtgt", "admin", "domain admin")
| project TimeGenerated, Requester, SAN, Template, Computer
| sort by TimeGenerated desc
```

---

#### Certificate-Based Authentication Anomalies
```kql
SecurityEvent
| where EventID == 4768
| extend AccountName = extract("Account Name:\\s+([^\\r\\n]+)", 1, EventData)
| extend PreAuthType = extract("Pre-Authentication Type:\\s+([^\\r\\n]+)", 1, EventData)
| extend CertIssuer = extract("Certificate Issuer Name:\\s+([^\\r\\n]+)", 1, EventData)
| where PreAuthType == "16" // PKINIT
| summarize AuthCount = count(), UniqueIPs = dcount(IpAddress), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName, CertIssuer, Computer
| where AuthCount > 10 or UniqueIPs > 5
| project AccountName, AuthCount, UniqueIPs, FirstSeen, LastSeen, CertIssuer, Computer
```

---

#### Template Modification Hunting
```kql
SecurityEvent
| where EventID == 5136
| extend ObjectDN = extract("Object DN:\\s+([^\\r\\n]+)", 1, EventData)
| extend Attribute = extract("Attribute:\\s+([^\\r\\n]+)", 1, EventData)
| extend Modifier = extract("SubjectUserName:\\s+([^\\r\\n]+)", 1, EventData)
| where ObjectDN contains "CN=Certificate Templates"
| where Attribute in ("msPKI-Certificate-Name-Flag", "msPKI-Certificate-Application-Policy", "nTSecurityDescriptor", "msPKI-Enrollment-Flag")
| where Modifier !has_any ("PKI-Admin", "Administrator", "CA-Admin")
| project TimeGenerated, Modifier, ObjectDN, Attribute, Computer
| sort by TimeGenerated desc
```

---

### Sigma Rules

#### ESC1 - Arbitrary SAN Certificate Request
```yaml
title: ADCS ESC1 - Certificate Request with Arbitrary SAN
id: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p
status: stable
description: Detects certificate requests where Subject Alternative Name differs from requester
author: ADCS Security Research
date: 2025/11/16
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4887
  selection_san:
    EventData|contains:
      - 'upn='
      - 'SAN='
  filter_match:
    # This would need custom logic to compare Requester vs SAN
  condition: selection_event and selection_san
fields:
  - Requester
  - Subject
  - CertificateTemplate
  - Computer
falsepositives:
  - Legitimate enrollment agents (ESC3)
  - Help desk certificate enrollment
level: high
tags:
  - attack.credential_access
  - attack.t1649
```

---

#### ESC3 - Enrollment Agent Certificate Request
```yaml
title: ADCS ESC3 - Enrollment Agent Certificate Request
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: stable
description: Detects enrollment agent certificate requests from non-authorized users
author: ADCS Security Research
date: 2025/11/16
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4887
    CertificateTemplate|contains:
      - 'EnrollmentAgent'
      - 'Enrollment Agent'
  filter_authorized:
    SubjectUserName|contains:
      - 'HELPDESK'
      - 'CA-ADMIN'
      - 'PKI-'
  condition: selection and not filter_authorized
fields:
  - Requester
  - CertificateTemplate
  - Computer
falsepositives:
  - New helpdesk staff not in filter list
  - Legitimate enrollment agent usage
level: high
tags:
  - attack.privilege_escalation
  - attack.t1649
```

---

#### ESC4 - Certificate Template Modification
```yaml
title: ADCS ESC4 - Certificate Template Modification
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects modifications to certificate template objects
author: ADCS Security Research
date: 2025/11/16
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 5136
  selection_object:
    ObjectClass: 'pKICertificateTemplate'
  selection_attribute:
    AttributeLDAPDisplayName:
      - 'msPKI-Certificate-Name-Flag'
      - 'msPKI-Certificate-Application-Policy'
      - 'nTSecurityDescriptor'
      - 'msPKI-Enrollment-Flag'
  filter_admins:
    SubjectUserName|endswith:
      - 'Administrator'
      - '-PKI-Admin'
      - '-CA-Admin'
  condition: selection_event and selection_object and selection_attribute and not filter_admins
fields:
  - SubjectUserName
  - ObjectDN
  - AttributeLDAPDisplayName
  - AttributeValue
level: high
tags:
  - attack.privilege_escalation
  - attack.persistence
```

---

#### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Abuse
```yaml
title: ADCS ESC6 - User-Specified SAN in Certificate Request
id: 4d5e6f7g-8h9i-0j1k-2l3m-4n5o6p7q8r9s
status: experimental
description: Detects certificate requests with user-specified SAN when CA has ESC6 vulnerability
author: ADCS Security Research
date: 2025/11/16
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4886
  selection_attributes:
    RequestAttributes|contains:
      - 'san='
      - 'upn='
  condition: selection_event and selection_attributes
fields:
  - Requester
  - RequestAttributes
  - CertificateTemplate
  - Computer
falsepositives:
  - Templates legitimately configured with ENROLLEE_SUPPLIES_SUBJECT
  - Enrollment agent requests (ESC3)
level: medium
tags:
  - attack.credential_access
  - attack.t1649
```

---

## Behavioral Analytics

### Baseline Establishment

**Normal Certificate Enrollment Patterns:**
```
1. Time of Day: Business hours (8 AM - 6 PM)
2. Frequency: Periodic (new employees, cert renewals)
3. Templates: Standard templates (User, Computer, Workstation)
4. Requesters: Distributed across organization
5. Authentication: Standard NTLM/Kerberos, not PKINIT
```

### Anomaly Detection

**Suspicious Patterns:**
```
1. Certificate requests for privileged accounts
2. Unusual enrollment times (nights, weekends)
3. High-frequency requests from single account
4. PKINIT authentication spike
5. New/modified templates being used
6. Enrollment from unusual IP addresses
7. Certificate requests with long validity periods
```

---

### Machine Learning Detection

**Features for ML Model:**
```python
# Feature engineering for ADCS attack detection
features = {
    'hour_of_day': int,
    'day_of_week': int,
    'requester_frequency': float,  # Requests per hour
    'template_rarity': float,  # How rare is this template usage
    'san_mismatch': bool,  # Requester != SAN
    'privileged_target': bool,  # SAN contains privileged account
    'pkinit_auth': bool,  # Using certificate auth
    'unusual_ip': bool,  # IP not seen before
    'cert_validity_days': int,  # Certificate validity period
    'approval_required': bool,  # Template requires approval
}

# Anomaly score threshold
if anomaly_score > 0.85:
    alert("High confidence ADCS attack detected")
```

---

## Network Detection

### Network-Based Indicators

**Monitor for:**
```
1. HTTP/HTTPS traffic to /certsrv/ endpoints
2. RPC traffic to CA servers (Port 135, 445)
3. LDAP queries for certificate templates
4. Kerberos traffic with PKINIT (PA-DATA type 16)
```

**Wireshark Filters:**
```
# NTLM relay to ADCS web enrollment
http.request.uri contains "certsrv" and ntlmssp

# PKINIT authentication
kerberos.pa_data.type == 16

# Certificate enrollment traffic
dcerpc.cn_bind_to_uuid == 91ae6020-9e3c-11cf-8d7c-00aa00c091be
```

**Zeek/Bro Detection:**
```zeek
# Detect NTLM authentication to CA web enrollment
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    if (/certsrv/ in original_URI && c$http$authorization != "") {
        NOTICE([$note=ADCS_Web_Enrollment_Activity,
                $msg="ADCS web enrollment detected",
                $conn=c]);
    }
}
```

---

## Automated Hunting

### PowerShell Hunting Script

```powershell
# Hunt-ADCSAttacks.ps1
# Automated hunting for ADCS attack indicators

param(
    [int]$DaysBack = 7,
    [string]$OutputPath = ".\ADCSHuntingResults.csv"
)

$Results = @()

# Hunt for SAN mismatch certificates
$SANMismatch = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4887
    StartTime = (Get-Date).AddDays(-$DaysBack)
} | Where-Object {
    $Message = $_.Message
    $Message -match "upn=" -and
    # Additional parsing logic for mismatch detection
}

foreach ($Event in $SANMismatch) {
    $Results += [PSCustomObject]@{
        Finding = "SAN Mismatch"
        TimeCreated = $Event.TimeCreated
        Message = $Event.Message
        EventID = $Event.Id
    }
}

# Hunt for PKINIT authentication
$PKINITAuth = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4768
    StartTime = (Get-Date).AddDays(-$DaysBack)
} | Where-Object {
    $_.Message -match "Pre-Authentication Type:\s+16"
}

foreach ($Event in $PKINITAuth) {
    $Results += [PSCustomObject]@{
        Finding = "PKINIT Authentication"
        TimeCreated = $Event.TimeCreated
        Message = $Event.Message
        EventID = $Event.Id
    }
}

# Hunt for template modifications
$TemplateMods = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 5136
    StartTime = (Get-Date).AddDays(-$DaysBack)
} | Where-Object {
    $_.Message -match "pKICertificateTemplate"
}

foreach ($Event in $TemplateMods) {
    $Results += [PSCustomObject]@{
        Finding = "Template Modification"
        TimeCreated = $Event.TimeCreated
        Message = $Event.Message
        EventID = $Event.Id
    }
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "[+] Hunting complete. Results: $($Results.Count) findings"
Write-Host "[+] Output saved to: $OutputPath"
```

---

## Incident Response

### Response Playbook

#### Phase 1: Initial Detection
```
1. Alert triggered on suspicious certificate activity
2. Gather initial context:
   - Event ID, timestamp, affected accounts
   - Certificate template used
   - Requester information
   - CA server involved
```

#### Phase 2: Investigation
```
1. Query certificate database:
   certutil -view -restrict "SerialNumber=<serial>" -out "*"

2. Check certificate template configuration:
   Get-ADObject -Filter {name -eq "TemplateName"} -Properties *

3. Review CA audit logs:
   C:\Windows\System32\CertSrv\CertEnroll\<CAName>.log

4. Check for related authentication events:
   - Event 4768 (PKINIT auth)
   - Event 4624 (Logon events)

5. Identify scope:
   - How many certificates issued?
   - Which accounts compromised?
   - What access gained?
```

#### Phase 3: Containment
```
1. Revoke suspicious certificates:
   certutil -revoke <SerialNumber> 1  # KeyCompromise

2. Disable vulnerable templates:
   Set-ADObject -Identity $TemplateDN -Replace @{"flags"="130"}

3. Reset compromised account passwords

4. Disable compromised accounts temporarily

5. Block attacker IP addresses
```

#### Phase 4: Eradication
```
1. Fix vulnerable template configurations
2. Remove unauthorized enrollment permissions
3. Disable ESC6 flag if enabled:
   certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

4. Restore proper template ACLs
5. Patch known vulnerabilities
```

#### Phase 5: Recovery
```
1. Re-enable fixed templates
2. Re-enable legitimate accounts
3. Issue new certificates to affected users
4. Monitor for re-compromise attempts
```

#### Phase 6: Lessons Learned
```
1. Document attack TTPs
2. Update detection rules
3. Enhance monitoring
4. Security awareness training
5. Architecture improvements
```

---

## Monitoring Dashboard Metrics

### Key Performance Indicators

```yaml
Daily Metrics:
  - Total certificate requests
  - Certificates issued per template
  - Failed enrollment attempts
  - PKINIT authentications
  - Template modifications
  - Certificate revocations

Weekly Metrics:
  - Certificate enrollment trends
  - Template usage statistics
  - Enrollment agent activity
  - Privileged account cert requests

Monthly Metrics:
  - Certificate inventory
  - Template compliance score
  - Security baseline drift
  - Incident response metrics
```

---

## References

- [MITRE ATT&CK - T1649: Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [SpecterOps - Certified Pre-Owned Detection](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Microsoft - Security Monitoring for AD CS](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/security-monitoring)

---

**Author**: ADCS Security Research
**Last Updated**: November 2025
**Classification**: Defense & Detection Guidance
