<parameter name="content"># Enumerate-ADCS.ps1
# Comprehensive ADCS enumeration for vulnerability assessment
# Usage: .\Enumerate-ADCS.ps1 -Verbose -OutputFile report.html

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ADCS-Enumeration-Report.html",

    [Parameter(Mandatory=$false)]
    [switch]$CheckESC1,

    [Parameter(Mandatory=$false)]
    [switch]$CheckESC2,

    [Parameter(Mandatory=$false)]
    [switch]$CheckESC3,

    [Parameter(Mandatory=$false)]
    [switch]$CheckESC4,

    [Parameter(Mandatory=$false)]
    [switch]$CheckESC6,

    [Parameter(Mandatory=$false)]
    [switch]$AllChecks
)

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not available. Run on domain-joined system with RSAT."
    exit 1
}

# Global variables
$Script:Vulnerabilities = @()
$Script:ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$Script:TemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$Script:ConfigContext"
$Script:EnrollmentServicesPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$Script:ConfigContext"

#region Helper Functions

function Write-Finding {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$Template,
        [string]$Description,
        [hashtable]$Details
    )

    $Finding = [PSCustomObject]@{
        Type = $Type
        Severity = $Severity
        Template = $Template
        Description = $Description
        Details = $Details
        Timestamp = Get-Date
    }

    $Script:Vulnerabilities += $Finding

    $Color = switch($Severity) {
        "Critical" { "Red" }
        "High" { "DarkRed" }
        "Medium" { "Yellow" }
        "Low" { "Green" }
        default { "White" }
    }

    Write-Host "[$Severity] $Type - $Template" -ForegroundColor $Color
    Write-Host "  $Description" -ForegroundColor Gray
}

function Get-CurrentUserSIDs {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $SIDs = @($CurrentUser.User.Value)
    $SIDs += $CurrentUser.Groups | ForEach-Object { $_.Value }
    return $SIDs
}

function Test-EnrollmentRights {
    param($TemplateDN)

    $ACL = (Get-Acl -Path "AD:$TemplateDN").Access
    $UserSIDs = Get-CurrentUserSIDs

    foreach ($ACE in $ACL) {
        if ($ACE.ActiveDirectoryRights -match "ExtendedRight|GenericAll" -and
            $ACE.AccessControlType -eq "Allow") {

            $SID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

            if ($UserSIDs -contains $SID) {
                return $true
            }

            # Check for Authenticated Users / Domain Users
            if ($SID -eq "S-1-5-11" -or $SID -eq "S-1-5-21-*-513") {
                return $true
            }
        }
    }
    return $false
}

#endregion

#region ESC1 Check

function Test-ESC1 {
    Write-Host "`n[*] Checking for ESC1 vulnerabilities..." -ForegroundColor Cyan

    $Templates = Get-ADObject -SearchBase $Script:TemplatesPath -Filter * -Properties *

    foreach ($Template in $Templates) {
        $NameFlag = $Template.'msPKI-Certificate-Name-Flag'
        $EKUs = $Template.'msPKI-Certificate-Application-Policy'
        $EnrollmentFlag = $Template.'msPKI-Enrollment-Flag'
        $RASignature = $Template.'msPKI-RA-Signature'

        # Check for ENROLLEE_SUPPLIES_SUBJECT (0x1)
        if ($NameFlag -band 0x1) {
            # Check for Client Authentication EKU
            if ($EKUs -contains "1.3.6.1.5.5.7.3.2") {
                # Check manager approval not required
                if (-not ($EnrollmentFlag -band 0x2)) {
                    # Check no required signatures
                    if ($RASignature -eq 0 -or $null -eq $RASignature) {
                        # Check if we can enroll
                        if (Test-EnrollmentRights $Template.DistinguishedName) {
                            Write-Finding -Type "ESC1" -Severity "Critical" -Template $Template.Name `
                                -Description "Template allows arbitrary SAN with client authentication" `
                                -Details @{
                                    "msPKI-Certificate-Name-Flag" = $NameFlag
                                    "EKUs" = $EKUs -join ", "
                                    "EnrollmentRights" = "Current user can enroll"
                                }
                        }
                    }
                }
            }
        }
    }
}

#endregion

#region ESC2 Check

function Test-ESC2 {
    Write-Host "`n[*] Checking for ESC2 vulnerabilities..." -ForegroundColor Cyan

    $Templates = Get-ADObject -SearchBase $Script:TemplatesPath -Filter * -Properties *

    foreach ($Template in $Templates) {
        $EKUs = $Template.'msPKI-Certificate-Application-Policy'
        $EnrollmentFlag = $Template.'msPKI-Enrollment-Flag'
        $RASignature = $Template.'msPKI-RA-Signature'

        # Check for Any Purpose EKU (2.5.29.37.0) or no EKU
        $IsAnyPurpose = $EKUs -contains "2.5.29.37.0"
        $NoEKU = ($null -eq $EKUs -or $EKUs.Count -eq 0)

        if ($IsAnyPurpose -or $NoEKU) {
            # Check manager approval not required
            if (-not ($EnrollmentFlag -band 0x2)) {
                # Check no required signatures
                if ($RASignature -eq 0 -or $null -eq $RASignature) {
                    if (Test-EnrollmentRights $Template.DistinguishedName) {
                        $Type = if ($IsAnyPurpose) { "ESC2 - Any Purpose" } else { "ESC2 - No EKU" }

                        Write-Finding -Type $Type -Severity "High" -Template $Template.Name `
                            -Description "Template has any purpose or no EKU defined" `
                            -Details @{
                                "EKUs" = if ($NoEKU) { "None" } else { $EKUs -join ", " }
                                "EnrollmentRights" = "Current user can enroll"
                            }
                    }
                }
            }
        }
    }
}

#endregion

#region ESC3 Check

function Test-ESC3 {
    Write-Host "`n[*] Checking for ESC3 vulnerabilities..." -ForegroundColor Cyan

    $Templates = Get-ADObject -SearchBase $Script:TemplatesPath -Filter * -Properties *

    # Find enrollment agent templates
    $AgentTemplates = $Templates | Where-Object {
        $_.'msPKI-Certificate-Application-Policy' -contains "1.3.6.1.4.1.311.20.2.1"
    }

    foreach ($AgentTemplate in $AgentTemplates) {
        if (Test-EnrollmentRights $AgentTemplate.DistinguishedName) {
            # Find templates that accept this agent
            $ClientTemplates = $Templates | Where-Object {
                $_.'msPKI-RA-Application-Policies' -contains "1.3.6.1.4.1.311.20.2.1" -and
                $_.'msPKI-Certificate-Application-Policy' -contains "1.3.6.1.5.5.7.3.2"
            }

            foreach ($ClientTemplate in $ClientTemplates) {
                Write-Finding -Type "ESC3" -Severity "Critical" -Template $AgentTemplate.Name `
                    -Description "Enrollment agent template with client authentication target" `
                    -Details @{
                        "AgentTemplate" = $AgentTemplate.Name
                        "TargetTemplate" = $ClientTemplate.Name
                        "CanEnroll" = "Yes"
                    }
            }
        }
    }
}

#endregion

#region ESC4 Check

function Test-ESC4 {
    Write-Host "`n[*] Checking for ESC4 vulnerabilities..." -ForegroundColor Cyan

    $Templates = Get-ADObject -SearchBase $Script:TemplatesPath -Filter * -Properties nTSecurityDescriptor

    $UserSIDs = Get-CurrentUserSIDs

    foreach ($Template in $Templates) {
        $ACL = (Get-Acl -Path "AD:$($Template.DistinguishedName)").Access

        foreach ($ACE in $ACL) {
            $DangerousRights = $ACE.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl|WriteOwner|GenericWrite"

            if ($DangerousRights -and $ACE.AccessControlType -eq "Allow") {
                $SID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

                if ($UserSIDs -contains $SID) {
                    Write-Finding -Type "ESC4" -Severity "High" -Template $Template.Name `
                        -Description "Current user has write permissions on template" `
                        -Details @{
                            "Permission" = $ACE.ActiveDirectoryRights
                            "Identity" = $ACE.IdentityReference
                        }
                }
            }
        }
    }
}

#endregion

#region ESC6 Check

function Test-ESC6 {
    Write-Host "`n[*] Checking for ESC6 vulnerabilities..." -ForegroundColor Cyan

    # Get all CAs
    $CAs = Get-ADObject -SearchBase $Script:EnrollmentServicesPath -Filter * -Properties dNSHostName

    foreach ($CA in $CAs) {
        $CAServer = $CA.dNSHostName
        $CAName = $CA.Name

        Write-Verbose "Checking CA: $CAName on $CAServer"

        # Try to query CA configuration
        try {
            $EditFlags = certutil -config "$CAServer\$CAName" -getreg "policy\EditFlags" 2>&1

            if ($EditFlags -match "EDITF_ATTRIBUTESUBJECTALTNAME2") {
                Write-Finding -Type "ESC6" -Severity "Critical" -Template "N/A" `
                    -Description "CA allows user-specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)" `
                    -Details @{
                        "CA" = $CAName
                        "Server" = $CAServer
                        "Flag" = "EDITF_ATTRIBUTESUBJECTALTNAME2"
                    }
            }
        } catch {
            Write-Verbose "Could not query CA configuration for $CAName (may require CA admin rights)"
        }
    }
}

#endregion

#region Report Generation

function Generate-HTMLReport {
    $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>ADCS Vulnerability Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #d9534f; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vulnerability { background: white; padding: 15px; margin: 10px 0; border-left: 5px solid; border-radius: 3px; }
        .critical { border-color: #d9534f; }
        .high { border-color: #f0ad4e; }
        .medium { border-color: #5bc0de; }
        .low { border-color: #5cb85c; }
        .severity { font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }
        .sev-critical { background: #d9534f; }
        .sev-high { background: #f0ad4e; }
        .sev-medium { background: #5bc0de; }
        .sev-low { background: #5cb85c; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #333; color: white; }
        .details { font-size: 0.9em; color: #666; margin-top: 10px; }
        .timestamp { color: #999; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>ADCS Vulnerability Assessment Report</h1>
    <p class="timestamp">Generated: $(Get-Date -Format "yyyy-MM-DD HH:mm:ss")</p>

    <div class="summary">
        <h2>Executive Summary</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td><span class="severity sev-critical">Critical</span></td>
                <td>$($Script:Vulnerabilities | Where-Object {$_.Severity -eq "Critical"} | Measure-Object | Select-Object -ExpandProperty Count)</td>
            </tr>
            <tr>
                <td><span class="severity sev-high">High</span></td>
                <td>$($Script:Vulnerabilities | Where-Object {$_.Severity -eq "High"} | Measure-Object | Select-Object -ExpandProperty Count)</td>
            </tr>
            <tr>
                <td><span class="severity sev-medium">Medium</span></td>
                <td>$($Script:Vulnerabilities | Where-Object {$_.Severity -eq "Medium"} | Measure-Object | Select-Object -ExpandProperty Count)</td>
            </tr>
        </table>
    </div>

    <h2>Vulnerabilities Found</h2>
"@

    foreach ($Vuln in $Script:Vulnerabilities) {
        $SevClass = $Vuln.Severity.ToLower()
        $HTML += @"
    <div class="vulnerability $SevClass">
        <span class="severity sev-$SevClass">$($Vuln.Severity)</span>
        <strong>$($Vuln.Type)</strong> - Template: $($Vuln.Template)
        <p>$($Vuln.Description)</p>
        <div class="details">
"@
        foreach ($Key in $Vuln.Details.Keys) {
            $HTML += "            <strong>$Key:</strong> $($Vuln.Details[$Key])<br>`n"
        }
        $HTML += @"
        </div>
    </div>
"@
    }

    $HTML += @"
</body>
</html>
"@

    $HTML | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "`n[+] Report generated: $OutputFile" -ForegroundColor Green
}

#endregion

#region Main Execution

Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          ADCS Vulnerability Enumeration Tool             ║
║                    Version 1.0                            ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Determine which checks to run
$RunAll = $AllChecks -or (-not ($CheckESC1 -or $CheckESC2 -or $CheckESC3 -or $CheckESC4 -or $CheckESC6))

if ($RunAll -or $CheckESC1) { Test-ESC1 }
if ($RunAll -or $CheckESC2) { Test-ESC2 }
if ($RunAll -or $CheckESC3) { Test-ESC3 }
if ($RunAll -or $CheckESC4) { Test-ESC4 }
if ($RunAll -or $CheckESC6) { Test-ESC6 }

# Summary
Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    SCAN COMPLETE                          ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "`nTotal Vulnerabilities Found: $($Script:Vulnerabilities.Count)" -ForegroundColor Yellow

if ($Script:Vulnerabilities.Count -gt 0) {
    $Critical = ($Script:Vulnerabilities | Where-Object {$_.Severity -eq "Critical"}).Count
    $High = ($Script:Vulnerabilities | Where-Object {$_.Severity -eq "High"}).Count

    Write-Host "  Critical: $Critical" -ForegroundColor Red
    Write-Host "  High: $High" -ForegroundColor DarkRed

    Generate-HTMLReport
} else {
    Write-Host "`n[+] No vulnerabilities found!" -ForegroundColor Green
}

#endregion
