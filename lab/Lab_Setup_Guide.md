# ADCS Vulnerable Lab Setup Guide

## Overview

This guide provides step-by-step instructions for setting up a vulnerable Active Directory Certificate Services (ADCS) environment for security research, penetration testing practice, and defensive training.

**WARNING**: This lab is intentionally vulnerable. NEVER deploy these configurations in production environments.

---

## Table of Contents

1. [Lab Architecture](#lab-architecture)
2. [Prerequisites](#prerequisites)
3. [Domain Controller Setup](#domain-controller-setup)
4. [Certificate Authority Setup](#certificate-authority-setup)
5. [Vulnerable Template Configuration](#vulnerable-template-configuration)
6. [Attack Workstation Setup](#attack-workstation-setup)
7. [Verification](#verification)
8. [Training Scenarios](#training-scenarios)

---

## Lab Architecture

### Recommended Setup

```
Network: 192.168.100.0/24

┌─────────────────────────────────────────────────────┐
│                  Lab Environment                     │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────┐         ┌──────────────┐         │
│  │   DC01       │         │  ATTACKER    │         │
│  │              │◄────────┤              │         │
│  │ - Domain     │         │ - Kali Linux │         │
│  │   Controller │         │ - Windows 10 │         │
│  │ - CA Server  │         │              │         │
│  │              │         │              │         │
│  │ 192.168.100.10        │ 192.168.100.50│         │
│  └──────────────┘         └──────────────┘         │
│                                                      │
│  ┌──────────────┐         ┌──────────────┐         │
│  │   CLIENT01   │         │  CLIENT02    │         │
│  │              │         │              │         │
│  │ - Domain     │         │ - Domain     │         │
│  │   Member     │         │   Member     │         │
│  │              │         │              │         │
│  │ 192.168.100.101       │ 192.168.100.102        │
│  └──────────────┘         └──────────────┘         │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### System Requirements

**Domain Controller (DC01):**
- Windows Server 2019 or 2022
- 4 GB RAM minimum
- 60 GB disk space
- Static IP: 192.168.100.10

**Attacker Machine:**
- Windows 10/11 (for Rubeus, Certify) OR
- Kali Linux (for Certipy, ntlmrelayx)
- 4 GB RAM
- 40 GB disk space
- Static IP: 192.168.100.50

**Client Machines (Optional):**
- Windows 10/11
- 2 GB RAM each
- 40 GB disk space each

---

## Prerequisites

### Required Software

**On Windows Server:**
- Windows Server 2019/2022 ISO
- Active Directory Domain Services role
- Active Directory Certificate Services role

**On Attacker Machine:**

Windows:
- Rubeus: https://github.com/GhostPack/Rubeus
- Certify: https://github.com/GhostPack/Certify
- Mimikatz: https://github.com/gentilkiwi/mimikatz
- PowerView: https://github.com/PowerShellMafia/PowerSploit

Linux:
- Certipy: `pip3 install certipy-ad`
- Impacket: `pip3 install impacket`
- Responder: `git clone https://github.com/lgandx/Responder`
- PetitPotam: `git clone https://github.com/topotam/PetitPotam`

---

## Domain Controller Setup

### Step 1: Install Windows Server

1. Install Windows Server 2019/2022
2. Set computer name: `DC01`
3. Configure static IP:
   ```powershell
   New-NetIPAddress -IPAddress 192.168.100.10 -PrefixLength 24 -DefaultGateway 192.168.100.1 -InterfaceAlias "Ethernet"
   Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.100.10
   ```

### Step 2: Install Active Directory Domain Services

```powershell
# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Import-Module ADDSDeployment

Install-ADDSForest `
    -DomainName "corp.local" `
    -DomainNetbiosName "CORP" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Force

# Server will reboot
```

### Step 3: Create Lab Users

After reboot:

```powershell
# Create OUs
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "LabComputers" -Path "DC=corp,DC=local"

# Create test users
$Users = @(
    @{Name="Alice"; Password="Password123!"; Groups=@("Domain Users")},
    @{Name="Bob"; Password="Password123!"; Groups=@("Domain Users")},
    @{Name="Charlie"; Password="Password123!"; Groups=@("Domain Admins")},
    @{Name="LowPrivUser"; Password="Password123!"; Groups=@("Domain Users")},
    @{Name="HelpDesk"; Password="Password123!"; Groups=@("Domain Users")}
)

foreach ($User in $Users) {
    New-ADUser `
        -Name $User.Name `
        -SamAccountName $User.Name `
        -UserPrincipalName "$($User.Name)@corp.local" `
        -Path "OU=LabUsers,DC=corp,DC=local" `
        -AccountPassword (ConvertTo-SecureString $User.Password -AsPlainText -Force) `
        -Enabled $true `
        -PasswordNeverExpires $true

    foreach ($Group in $User.Groups) {
        Add-ADGroupMember -Identity $Group -Members $User.Name
    }
}

Write-Host "[+] Lab users created successfully" -ForegroundColor Green
```

---

## Certificate Authority Setup

### Step 1: Install AD CS Role

```powershell
# Install Certificate Services
Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools

# Install Certificate Authority
Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCA `
    -CACommonName "CORP-DC01-CA" `
    -CADistinguishedNameSuffix "DC=corp,DC=local" `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 `
    -HashAlgorithmName SHA256 `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 10 `
    -Force

Write-Host "[+] Certificate Authority installed successfully" -ForegroundColor Green
```

### Step 2: Install Web Enrollment (ESC8 Vulnerability)

```powershell
# Install IIS and Web Enrollment
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name ADCS-Web-Enrollment

Install-AdcsWebEnrollment -Force

Write-Host "[+] Web Enrollment configured" -ForegroundColor Green
Write-Host "[!] Web enrollment available at: http://dc01.corp.local/certsrv" -ForegroundColor Yellow
```

### Step 3: Configure ESC6 Vulnerability

```powershell
# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart Certificate Services
Restart-Service CertSvc

Write-Host "[+] ESC6 vulnerability enabled (EDITF_ATTRIBUTESUBJECTALTNAME2)" -ForegroundColor Yellow
```

### Step 4: Disable Extended Protection (ESC8)

```powershell
# Disable Extended Protection for Authentication on web enrollment
Import-Module WebAdministration

Set-WebConfigurationProperty `
    -Filter "system.webServer/security/authentication/windowsAuthentication" `
    -Name "extendedProtection.tokenChecking" `
    -Value "None" `
    -PSPath "IIS:\Sites\Default Web Site\CertSrv"

Write-Host "[+] Extended Protection disabled (ESC8 vulnerable)" -ForegroundColor Yellow
```

---

## Vulnerable Template Configuration

### ESC1 - Vulnerable User Template

```powershell
# Duplicate User template to create vulnerable template
$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$TemplatesContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

# Get User template
$UserTemplate = Get-ADObject -SearchBase $TemplatesContainer -Filter {cn -eq "User"} -Properties *

# Create new template
$ESC1Template = New-ADObject `
    -Name "ESC1-Vulnerable" `
    -Type "pKICertificateTemplate" `
    -Path $TemplatesContainer `
    -OtherAttributes @{
        'displayName' = 'ESC1-Vulnerable'
        'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2'  # Client Authentication
        'msPKI-Certificate-Name-Flag' = 1  # ENROLLEE_SUPPLIES_SUBJECT
        'msPKI-Enrollment-Flag' = 0  # No manager approval
        'msPKI-RA-Signature' = 0  # No required signatures
        'pKIMaxIssuingDepth' = 0
        'pKICriticalExtensions' = '2.5.29.15'
        'pKIDefaultKeySpec' = 1
        'pKIMaxIssuingDepth' = 0
        'pKIExpirationPeriod' = $UserTemplate.'pKIExpirationPeriod'
        'pKIOverlapPeriod' = $UserTemplate.'pKIOverlapPeriod'
        'pKIExtendedKeyUsage' = '1.3.6.1.5.5.7.3.2'
        'revision' = 100
        'flags' = 66178  # Make template available
    } -PassThru

# Grant enrollment rights to Domain Users
$TemplateDN = "CN=ESC1-Vulnerable,$TemplatesContainer"
$ACL = Get-Acl -Path "AD:$TemplateDN"

$EnrollRight = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-5-11",  # Authenticated Users
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
)

$ACL.AddAccessRule($EnrollRight)
Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL

# Publish template to CA
certutil -SetCAtemplates +ESC1-Vulnerable

Write-Host "[+] ESC1 vulnerable template created and published" -ForegroundColor Yellow
```

### ESC2 - Any Purpose Template

```powershell
# Create template with Any Purpose EKU
$ESC2Template = @{
    'Name' = 'ESC2-AnyPurpose'
    'displayName' = 'ESC2-AnyPurpose'
    'msPKI-Certificate-Application-Policy' = '2.5.29.37.0'  # Any Purpose
    'msPKI-Enrollment-Flag' = 0
    'msPKI-RA-Signature' = 0
    'flags' = 66178
}

# Create using certutil or manual LDAP operations
# (Simplified - would need full LDAP object creation)

Write-Host "[+] ESC2 template configuration prepared" -ForegroundColor Yellow
```

### ESC3 - Enrollment Agent Template

```powershell
# Create Enrollment Agent template
$ESC3EnrollmentAgent = @{
    'Name' = 'ESC3-EnrollmentAgent'
    'displayName' = 'ESC3-EnrollmentAgent'
    'msPKI-Certificate-Application-Policy' = '1.3.6.1.4.1.311.20.2.1'  # Certificate Request Agent
    'msPKI-Enrollment-Flag' = 0
    'msPKI-RA-Signature' = 0
    'flags' = 66178
}

# Create target template that accepts enrollment agent
$ESC3TargetTemplate = @{
    'Name' = 'ESC3-UserAuth'
    'displayName' = 'ESC3-UserAuth'
    'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2'  # Client Auth
    'msPKI-RA-Application-Policies' = '1.3.6.1.4.1.311.20.2.1'  # Requires Certificate Request Agent
    'msPKI-Enrollment-Flag' = 0
    'msPKI-RA-Signature' = 1  # Requires 1 signature (from enrollment agent)
    'flags' = 66178
}

Write-Host "[+] ESC3 template configuration prepared" -ForegroundColor Yellow
```

### ESC4 - Weak ACL Template

```powershell
# Create template with weak ACLs
# Grant Domain Users GenericAll on template

$TemplateName = "ESC4-ModifiableTemplate"
# ... template creation code ...

$TemplateDN = "CN=$TemplateName,$TemplatesContainer"
$ACL = Get-Acl -Path "AD:$TemplateDN"

# Grant Domain Users full control (ESC4 vulnerability)
$FullControlACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-5-21-*-513",  # Domain Users SID
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$ACL.AddAccessRule($FullControlACE)
Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL

Write-Host "[+] ESC4 vulnerable template created (weak ACLs)" -ForegroundColor Yellow
```

---

## Attack Workstation Setup

### Windows Attacker Setup

```powershell
# Join to domain
Add-Computer -DomainName "corp.local" -Credential (Get-Credential) -Restart

# Download tools
$ToolsDir = "C:\Tools"
New-Item -ItemType Directory -Path $ToolsDir -Force

# Download Rubeus, Certify, etc.
# Place tools in C:\Tools\

# Login as low-privilege user
```

### Linux Attacker Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python tools
pip3 install certipy-ad impacket

# Clone attack tools
cd ~/tools
git clone https://github.com/lgandx/Responder
git clone https://github.com/topotam/PetitPotam

# Configure /etc/hosts
echo "192.168.100.10 dc01.corp.local dc01 corp.local" | sudo tee -a /etc/hosts

# Test connectivity
certipy find -u 'lowprivuser@corp.local' -p 'Password123!' -dc-ip 192.168.100.10
```

---

## Verification

### Verify Domain Functionality

```powershell
# On DC01
Get-ADDomain
Get-ADForest
Get-ADUser -Filter * | Select-Object Name, Enabled
```

### Verify CA Installation

```powershell
# Check CA status
certutil -ping

# List published templates
certutil -CATemplates

# Expected output should include:
# - ESC1-Vulnerable
# - ESC2-AnyPurpose
# - ESC3-EnrollmentAgent
# - ESC4-ModifiableTemplate
```

### Verify Web Enrollment

```powershell
# Test web enrollment access
Start-Process "http://dc01.corp.local/certsrv"

# Should prompt for credentials and display certificate request page
```

### Verify Vulnerabilities

```powershell
# On attacker machine - enumerate vulnerabilities
.\Certify.exe find /vulnerable

# Should detect:
# - ESC1: ESC1-Vulnerable template
# - ESC2: ESC2-AnyPurpose template
# - ESC3: ESC3-EnrollmentAgent template
# - ESC4: ESC4-ModifiableTemplate template
# - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
# - ESC8: Web enrollment without EPA
```

---

## Training Scenarios

### Scenario 1: ESC1 Privilege Escalation

**Objective**: Escalate from `lowprivuser` to `Administrator`

**Steps**:
1. Enumerate vulnerable templates
2. Request certificate with Administrator SAN
3. Authenticate using certificate
4. Verify Domain Admin access

**Expected Outcome**: Full domain compromise

---

### Scenario 2: ESC3 Enrollment Agent Abuse

**Objective**: Use enrollment agent to impersonate domain admin

**Steps**:
1. Request enrollment agent certificate
2. Use agent to request certificate for Charlie (Domain Admin)
3. Authenticate as Charlie
4. Perform DCSync attack

**Expected Outcome**: krbtgt hash extraction

---

### Scenario 3: ESC6 + ESC8 Combined Attack

**Objective**: NTLM relay to web enrollment with SAN specification

**Steps**:
1. Setup ntlmrelayx targeting web enrollment
2. Coerce authentication using PetitPotam
3. Relay authentication to request certificate
4. Authenticate with obtained certificate

**Expected Outcome**: Computer account compromise

---

### Scenario 4: ESC4 Template Modification

**Objective**: Modify template to create ESC1 vulnerability

**Steps**:
1. Identify template with write permissions
2. Modify template properties
3. Enable ENROLLEE_SUPPLIES_SUBJECT
4. Exploit modified template
5. Restore original configuration

**Expected Outcome**: Privilege escalation + stealth

---

## Reset Lab Environment

```powershell
# Reset script to restore lab to vulnerable state

# Revoke all certificates
certutil -view -restrict "Disposition=20" -out "SerialNumber" | ForEach-Object {
    certutil -revoke $_ 1
}

# Restore template configurations
# Re-enable ESC6 flag
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc

# Reset user passwords
$Users = @("Alice", "Bob", "Charlie", "LowPrivUser", "HelpDesk")
foreach ($User in $Users) {
    Set-ADAccountPassword -Identity $User -NewPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Reset
}

Write-Host "[+] Lab environment reset complete" -ForegroundColor Green
```

---

## Security Warnings

**⚠️ CRITICAL WARNINGS:**

1. **Isolation**: This lab MUST be isolated from production networks
2. **Firewall**: Use host-only or internal networking in hypervisor
3. **Snapshots**: Take snapshots before making changes
4. **Cleanup**: Destroy or properly secure the environment when finished
5. **No Internet**: Do not connect lab to internet

**These configurations are EXTREMELY DANGEROUS if deployed in production!**

---

## Troubleshooting

### Issue: Certificate request fails

**Solution:**
```powershell
# Check CA is running
Get-Service CertSvc

# Verify template is published
certutil -CATemplates

# Check enrollment permissions
```

### Issue: Cannot authenticate with certificate

**Solution:**
```powershell
# Verify certificate has correct EKUs
certutil -dump cert.cer

# Ensure domain controller trusts issuing CA
# Check KDC certificate in Enterprise NTAuth store
certutil -viewstore -enterprise NTAuth
```

### Issue: ESC6 not working

**Solution:**
```powershell
# Verify flag is set
certutil -getreg policy\EditFlags

# Should show EDITF_ATTRIBUTESUBJECTALTNAME2
# If not, re-apply and restart service
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc
```

---

## Additional Resources

- [SpecterOps ADCS Research](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certify Documentation](https://github.com/GhostPack/Certify)
- [Certipy Documentation](https://github.com/ly4k/Certipy)
- [Microsoft AD CS Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/)

---

**Author**: ADCS Lab Research Team
**Last Updated**: November 2025
**Purpose**: Security Research & Training Only
