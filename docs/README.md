# ADCS Attack Documentation

This directory contains comprehensive attack guides, detection strategies, and defensive playbooks for Active Directory Certificate Services (ADCS) exploitation.

## 📚 Attack Guides

Detailed exploitation guides for each ADCS escalation technique:

### [ESC1 - Misconfigured Certificate Templates](ESC1_Guide.md)
- **Attack Vector**: Templates allowing arbitrary Subject Alternative Name (SAN)
- **Impact**: Domain privilege escalation
- **Prerequisites**: Domain user access, vulnerable template with ENROLLEE_SUPPLIES_SUBJECT flag
- **Detection**: Event ID 4887 with SAN mismatches
- **Guide Sections**:
  - Enumeration with Certify, Certipy, PowerShell
  - Step-by-step exploitation
  - Certificate authentication with Rubeus
  - Detection strategies (Event logs, Splunk, KQL, Sigma rules)
  - Remediation and hardening

### [ESC2 - Misconfigured Certificate Templates (Any Purpose/SubCA)](ESC2_Guide.md)
- **Attack Vector**: Templates with Any Purpose EKU or Subordinate CA capabilities
- **Impact**: Certificate issuance for any purpose, potential rogue CA
- **Prerequisites**: Template with EKU 2.5.29.37.0 or SubCA permissions
- **Detection**: Event ID 4887 for Any Purpose/SubCA certificate issuance
- **Guide Sections**:
  - Three variants: Any Purpose, No EKU, Subordinate CA
  - ForgeCert exploitation for SubCA abuse
  - Multi-purpose certificate usage (code signing, authentication, etc.)
  - Detection and remediation strategies

### [ESC3 - Enrollment Agent Templates](ESC3_Guide.md)
- **Attack Vector**: Certificate Request Agent abuse for on-behalf-of enrollment
- **Impact**: Impersonation of any domain user including admins
- **Prerequisites**: Access to Enrollment Agent template + target template accepting agent
- **Detection**: Event ID 4887 with "on behalf of" indicators
- **Guide Sections**:
  - Two-step attack: Agent cert → Target cert
  - Enrollment agent restrictions bypass
  - Certificate chain validation
  - Comprehensive detection and policy hardening

### [ESC4 - Vulnerable Certificate Template Access Control](ESC4_Guide.md)
- **Attack Vector**: Write permissions on certificate template objects in AD
- **Impact**: Template modification to introduce ESC1/2/3 vulnerabilities
- **Prerequisites**: GenericAll, WriteDacl, WriteOwner, or WriteProperty on templates
- **Detection**: Event ID 5136 (AD object modification)
- **Guide Sections**:
  - ACL enumeration and exploitation
  - Template property modification techniques
  - Privilege escalation via WriteOwner/WriteDacl
  - ACL auditing and restoration

### [ESC6 & ESC8 - CA Configuration & NTLM Relay Attacks](ESC6_ESC8_Guide.md)

**ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2**
- **Attack Vector**: CA flag allowing user-specified SANs in any template
- **Impact**: Every enrollable template becomes ESC1-vulnerable
- **Prerequisites**: CA with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
- **Detection**: Certificate requests with SAN attributes on normally safe templates

**ESC8 - NTLM Relay to AD CS HTTP Endpoints**
- **Attack Vector**: NTLM relay to web enrollment (/certsrv/)
- **Impact**: Certificate issuance for relayed machine/user accounts
- **Prerequisites**: HTTP web enrollment OR HTTPS without EPA
- **Detection**: Unusual NTLM auth patterns to CA web endpoints
- **Guide Sections**:
  - CA configuration enumeration
  - NTLM relay setup with ntlmrelayx + PetitPotam
  - Extended Protection for Authentication (EPA) configuration
  - Network-based detection strategies

---

## 🛡️ Defense & Detection

### [Detection Playbook](Detection_Playbook.md)
Comprehensive detection and defensive strategies:

**Event Log Monitoring**:
- EventID 4886 - Certificate request indicators
- EventID 4887 - Certificate issuance anomalies
- EventID 4768 - PKINIT authentication detection
- EventID 5136 - Template modification tracking

**SIEM Queries**:
- **Splunk**: Ready-to-use SPL queries for each ESC technique
- **Microsoft Sentinel/Defender**: KQL queries for Azure environments
- **Sigma Rules**: Standardized detection rules for SIEM platforms

**Detection Categories**:
- SAN mismatch detection (ESC1/6)
- Enrollment agent abuse detection (ESC3)
- Template modification alerts (ESC4)
- PKINIT authentication anomalies
- NTLM relay patterns (ESC8)

**Behavioral Analytics**:
- Baseline establishment for certificate enrollment
- Anomaly detection patterns
- Machine learning feature engineering

**Incident Response**:
- Investigation procedures
- Containment strategies (certificate revocation, template disabling)
- Eradication and recovery steps
- Lessons learned framework

---

## 🧪 Lab Environment

### [Lab Setup Guide](../lab/Lab_Setup_Guide.md)
Complete vulnerable lab environment configuration:

**Infrastructure Setup**:
- Domain Controller (DC01) with AD CS
- Certificate Authority installation
- Web enrollment configuration
- Client machines and attacker workstation

**Vulnerable Configurations**:
- ESC1 templates (ENROLLEE_SUPPLIES_SUBJECT enabled)
- ESC2 templates (Any Purpose EKU)
- ESC3 Enrollment Agent setup
- ESC4 weak ACLs
- ESC6 flag enabled (EDITF_ATTRIBUTESUBJECTALTNAME2)
- ESC8 web enrollment without EPA

**Training Scenarios**:
- Privilege escalation exercises
- Detection rule testing
- Blue team training scenarios
- Lab reset procedures

---

## 📊 Quick Reference

### Attack Severity Matrix

| Technique | Severity | Prerequisites | Detection Difficulty | Remediation Priority |
|-----------|----------|---------------|---------------------|---------------------|
| ESC1 | Critical | User account | Medium | High |
| ESC2 | High | User account | Medium | High |
| ESC3 | Critical | User account | Medium-High | High |
| ESC4 | High | Write ACLs | Low | Critical |
| ESC6 | Critical | User account | Low | Critical |
| ESC8 | Critical | Network position | Medium | High |

### Common Tools by Technique

| Tool | ESC1 | ESC2 | ESC3 | ESC4 | ESC6 | ESC8 |
|------|------|------|------|------|------|------|
| Certify | ✓ | ✓ | ✓ | ✓ | ✓ | - |
| Certipy | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Rubeus | ✓ | ✓ | ✓ | ✓ | ✓ | - |
| ntlmrelayx | - | - | - | - | - | ✓ |
| ForgeCert | - | ✓ | - | - | - | - |

### Detection Event IDs by Technique

- **ESC1/ESC6**: 4886, 4887 (SAN mismatch)
- **ESC2**: 4887 (Any Purpose/SubCA issuance)
- **ESC3**: 4887 ("on behalf of" enrollment)
- **ESC4**: 5136 (template modification)
- **ESC8**: 4624 (NTLM auth) + IIS logs (web enrollment)
- **All**: 4768 (PKINIT authentication)

---

## 🎯 Usage Workflow

### 1. Reconnaissance
```powershell
# Enumerate all ADCS vulnerabilities
.\Certify.exe find /vulnerable
certipy find -u user@corp.local -p Password123 -dc-ip 10.10.10.10 -vulnerable
```

### 2. Exploitation
- Refer to specific ESC guides for detailed exploitation steps
- Use automation scripts in `../scripts/exploitation/`

### 3. Post-Exploitation
- Certificate-based authentication (Rubeus)
- Persistence mechanisms
- Lateral movement

### 4. Detection Testing
- Review Detection Playbook
- Test SIEM queries against lab environment
- Validate incident response procedures

---

## 📖 Additional Resources

**Original Research**:
- [SpecterOps - Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [SpecterOps - ESC9 & ESC10](https://posts.specterops.io/adcs-esc9-esc10-abuse-techniques-f9b9c648056b)

**Tool Documentation**:
- [Certify GitHub](https://github.com/GhostPack/Certify)
- [Certipy GitHub](https://github.com/ly4k/Certipy)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)

**Microsoft Documentation**:
- [AD CS Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/security-best-practices)
- [Certificate Template Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-security)

**MITRE ATT&CK**:
- [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)

---

## ⚠️ Legal and Ethical Use

All documentation and techniques are provided for:
- ✅ Authorized penetration testing engagements
- ✅ Red team operations with proper authorization
- ✅ Security research in controlled environments
- ✅ Defensive security training and blue team exercises
- ✅ CTF competitions and educational purposes

❌ **UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL**

Always obtain explicit written permission before testing any systems you do not own.

---

**Documentation Version**: 2.0
**Last Updated**: November 2025
**Maintained By**: ADCS Security Research Team
