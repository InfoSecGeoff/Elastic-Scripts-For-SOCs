<#
.SYNOPSIS
Retrieves all Kibana security detection rules from Elastic Security.

.DESCRIPTION
This script connects to a Kibana instance and retrieves all security detection rules using the Detection Engine API.
It exports the rules to multiple formats (CSV, JSON, HTML) and provides detailed statistics about rule types,
severities, and MITRE ATT&CK coverage. The script supports filtering to show only enabled rules or all rules.

.PARAMETER KibanaUrl
The full URL of your Kibana instance (e.g., "https://your-kibana.kb.us-east-1.aws.found.io").
Do not include the API path - only the base URL.

.PARAMETER ApiKey
The Kibana API key for authentication. This should be a base64-encoded API key generated from Kibana.
Generate this in Kibana under Stack Management > API Keys.

.PARAMETER OnlyEnabledRules
Switch parameter. When specified, only retrieves enabled rules. When omitted, retrieves all rules (enabled and disabled).

.PARAMETER VerboseLogging
Switch parameter. When specified, displays detailed information about API calls being made.

.PARAMETER PerPage
Number of rules to retrieve per page. Default is 100. Maximum recommended is 500.
Lower values are safer for large rule sets but require more API calls.

.EXAMPLE
.\Get-KibanaSecurityRules.ps1 -KibanaUrl "https://my-kibana.kb.us-east-1.aws.found.io" -ApiKey "UkY4WWQ1VUIwOUhhc1M4VV9DRHk6VnJrV1FGdzBSSTJ3SGhEQm9JSmxpUQ=="

Retrieves all rules (enabled and disabled) from the specified Kibana instance.

.EXAMPLE
.\Get-KibanaSecurityRules.ps1 -KibanaUrl "https://my-kibana.kb.us-east-1.aws.found.io" -ApiKey "UkY4WWQ1VUIwOUhhc1M4VV9DRHk6VnJrV1FGdzBSSTJ3SGhEQm9JSmxpUQ==" -OnlyEnabledRules

Retrieves only enabled rules from the specified Kibana instance.

.EXAMPLE
.\Get-KibanaSecurityRules.ps1 -KibanaUrl "https://my-kibana.kb.us-east-1.aws.found.io" -ApiKey "UkY4WWQ1VUIwOUhhc1M4VV9DRHk6VnJrV1FGdzBSSTJ3SGhEQm9JSmxpUQ==" -OnlyEnabledRules -VerboseLogging

Retrieves only enabled rules with detailed logging of API calls.

.EXAMPLE
.\Get-KibanaSecurityRules.ps1 -KibanaUrl "https://my-kibana.kb.us-east-1.aws.found.io" -ApiKey "UkY4WWQ1VUIwOUhhc1M4VV9DRHk6VnJrV1FGdzBSSTJ3SGhEQm9JSmxpUQ==" -PerPage 50

Retrieves all rules using smaller page sizes (50 rules per page instead of default 100).

.OUTPUTS
The script generates three files in your Documents folder:
- CSV file: Tabular format suitable for Excel analysis
- JSON file: Full rule details in JSON format
- HTML file: Interactive web report with search functionality

.NOTES
Author: Geoff Tankersley
Version: 1.0
Requirements: PowerShell 5.1 or later
API Documentation: https://www.elastic.co/guide/en/security/current/rules-api-find.html
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the full Kibana URL (e.g., https://your-kibana.kb.us-east-1.aws.found.io)")]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory=$true, HelpMessage="Enter the Kibana API key for authentication")]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [switch]$OnlyEnabledRules,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseLogging,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 500)]
    [int]$PerPage = 100
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

function Invoke-KibanaApi {
    param (
        [string]$Endpoint,
        [string]$Method = "GET",
        [string]$Body = $null
    )
    
    $fullUrl = "$KibanaUrl$Endpoint"
    
    if ($VerboseLogging) {
        Write-Host "Calling $Method $fullUrl" -ForegroundColor Gray
    }
    
    try {
        if ($Body -and $Method -in @("POST", "PUT", "PATCH", "DELETE")) {
            $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -Body $Body -ErrorAction Stop
        } else {
            $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -ErrorAction Stop
        }
        return $response
    }
    catch {
        Write-Host "Error calling $fullUrl : $_" -ForegroundColor Red
        Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            Write-Host "API Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
        }
        return $null
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Kibana Security Detection Rules Exporter" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target: $KibanaUrl" -ForegroundColor Yellow
if ($OnlyEnabledRules) {
    Write-Host "Filter: Only enabled rules" -ForegroundColor Yellow
} else {
    Write-Host "Filter: All rules (enabled and disabled)" -ForegroundColor Yellow
}
Write-Host "Page Size: $PerPage rules per page" -ForegroundColor Yellow
Write-Host ""

$allRules = @()
$page = 1
$totalRetrieved = 0
$hasMore = $true

do {
    Write-Host "Fetching page $page..." -ForegroundColor Yellow
    
    $endpoint = "/api/detection_engine/rules/_find?page=$page&per_page=$PerPage&sort_field=enabled&sort_order=desc"
    
    $rulesResponse = Invoke-KibanaApi -Endpoint $endpoint -Method "GET"
    
    if (-not $rulesResponse) {
        Write-Host "Failed to retrieve rules on page $page" -ForegroundColor Red
        break
    }
    
    if ($rulesResponse.data) {
        if ($OnlyEnabledRules) {
            $filteredRules = $rulesResponse.data | Where-Object { $_.enabled -eq $true }
        } else {
            $filteredRules = $rulesResponse.data
        }
        
        $allRules += $filteredRules
        $totalRetrieved += $filteredRules.Count
        
        Write-Host "Retrieved $($filteredRules.Count) rules from page $page (Total so far: $totalRetrieved)" -ForegroundColor Green
        
        $hasMore = ($rulesResponse.data.Count -eq $PerPage)
        
        if ($rulesResponse.total -and $totalRetrieved -ge $rulesResponse.total) {
            $hasMore = $false
        }
    } else {
        Write-Host "No data returned on page $page" -ForegroundColor Yellow
        $hasMore = $false
    }
    
    $page++
    
    if ($page -gt 100) {
        Write-Host "Reached safety limit of 100 pages" -ForegroundColor Yellow
        $hasMore = $false
    }
    
} while ($hasMore)

Write-Host "`nTotal security detection rules retrieved: $($allRules.Count)" -ForegroundColor Green

if ($allRules.Count -eq 0) {
    Write-Host "No rules found. Check your API credentials and permissions." -ForegroundColor Red
    Write-Host "Verify that:" -ForegroundColor Yellow
    Write-Host "  1. The Kibana URL is correct and accessible" -ForegroundColor Yellow
    Write-Host "  2. The API key is valid and has appropriate permissions" -ForegroundColor Yellow
    Write-Host "  3. You have access to the Detection Engine" -ForegroundColor Yellow
    exit
}

Write-Host "Processing rule data..." -ForegroundColor Cyan
$formattedRules = $allRules | ForEach-Object {
    $mitreTactics = "N/A"
    $mitreTechniques = "N/A"
    
    if ($_.threat) {
        $tactics = $_.threat | Where-Object { $_.tactic.name } | ForEach-Object { $_.tactic.name } | Select-Object -Unique
        if ($tactics) { $mitreTactics = $tactics -join ", " }
        
        $techniques = $_.threat | Where-Object { $_.technique } | ForEach-Object { 
            $_.technique | ForEach-Object { $_.id } 
        } | Select-Object -Unique
        if ($techniques) { $mitreTechniques = $techniques -join ", " }
    }
    
    [PSCustomObject]@{
        RuleID = $_.id
        RuleUUID = $_.rule_id
        RuleName = $_.name
        RuleType = $_.type
        Enabled = $_.enabled
        Severity = $_.severity
        RiskScore = $_.risk_score
        Description = $_.description
        Author = if ($_.author) { $_.author -join ", " } else { "N/A" }
        Tags = if ($_.tags) { $_.tags -join ", " } else { "N/A" }
        MitreTactics = $mitreTactics
        MitreTechniques = $mitreTechniques
        CreatedAt = $_.created_at
        UpdatedAt = $_.updated_at
        CreatedBy = $_.created_by
        UpdatedBy = $_.updated_by
        Interval = $_.interval
        From = $_.from
        To = $_.to
        Index = if ($_.index) { $_.index -join ", " } else { "N/A" }
        Query = if ($_.query) { $_.query } else { "N/A" }
        Language = if ($_.language) { $_.language } else { "N/A" }
        MaxSignals = $_.max_signals
        Actions = if ($_.actions) { $_.actions.Count } else { 0 }
        Version = $_.version
        Immutable = if ($_.immutable) { $_.immutable } else { $false }
        RuleSource = if ($_.rule_source) { $_.rule_source.type } else { "N/A" }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RULE STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Rules Retrieved: $($allRules.Count)" -ForegroundColor White

$ruleTypes = $formattedRules | Group-Object -Property RuleType | Select-Object Name, Count | Sort-Object Count -Descending
Write-Host "`nRule Types Distribution:" -ForegroundColor Yellow
foreach ($type in $ruleTypes) {
    Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor White
}

$severities = $formattedRules | Group-Object -Property Severity | Select-Object Name, Count | Sort-Object Name
Write-Host "`nSeverity Distribution:" -ForegroundColor Yellow
foreach ($severity in $severities) {
    $color = switch ($severity.Name) {
        "critical" { "Red" }
        "high" { "DarkYellow" }
        "medium" { "Yellow" }
        "low" { "Green" }
        default { "White" }
    }
    Write-Host "  $($severity.Name): $($severity.Count)" -ForegroundColor $color
}

$enabledCount = ($formattedRules | Where-Object { $_.Enabled -eq $true }).Count
$disabledCount = ($formattedRules | Where-Object { $_.Enabled -eq $false }).Count
Write-Host "`nEnabled Status:" -ForegroundColor Yellow
Write-Host "  Enabled: $enabledCount" -ForegroundColor Green
Write-Host "  Disabled: $disabledCount" -ForegroundColor Gray

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "EXPORTING DATA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$filterSuffix = if ($OnlyEnabledRules) { "_EnabledOnly" } else { "_AllRules" }
$csvFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "Documents\KibanaSecurityRules$filterSuffix`_$timestamp.csv"
$formattedRules | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8

Write-Host "CSV Export: $csvFilePath" -ForegroundColor Green

$jsonFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "Documents\KibanaSecurityRules$filterSuffix`_$timestamp.json"
$allRules | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8

Write-Host "JSON Export: $jsonFilePath" -ForegroundColor Green

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Kibana Security Detection Rules - $(if ($OnlyEnabledRules) { "Enabled Only" } else { "All Rules" })</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #1f2937; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
        h2 { color: #374151; margin-top: 30px; border-left: 4px solid #3b82f6; padding-left: 15px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 0.9em; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #e5e7eb; word-wrap: break-word; }
        th { background-color: #f9fafb; font-weight: 600; color: #374151; position: sticky; top: 0; }
        tr:hover { background-color: #f9fafb; }
        .summary { background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-top: 15px; }
        .summary-item { text-align: center; }
        .summary-number { font-size: 2em; font-weight: bold; }
        .summary-label { font-size: 0.9em; opacity: 0.9; }
        .severity-critical { background-color: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        .severity-high { background-color: #fef3c7; color: #92400e; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        .severity-medium { background-color: #fef9c3; color: #854d0e; padding: 4px 8px; border-radius: 4px; }
        .severity-low { background-color: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 4px; }
        .enabled-badge { background-color: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
        .disabled-badge { background-color: #f3f4f6; color: #6b7280; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
        .rule-description { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.85em; }
        .filter-box { margin: 20px 0; padding: 10px; background-color: #f9fafb; border-radius: 4px; }
        .filter-box input { padding: 8px; width: 300px; border: 1px solid #d1d5db; border-radius: 4px; }
        .stats-table { background-color: #f9fafb; }
        .stats-table td { font-weight: 500; }
        .info-banner { background-color: #dbeafe; border-left: 4px solid #3b82f6; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .info-banner p { margin: 5px 0; color: #1e40af; }
    </style>
    <script>
        function filterTable() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('rulesTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        const textValue = cell.textContent || cell.innerText;
                        if (textValue.toLowerCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                row.style.display = found ? '' : 'none';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Kibana Security Detection Rules $(if ($OnlyEnabledRules) { "- Enabled Only" } else { "- All Rules" })</h1>
        
        <div class="info-banner">
            <p><strong>Kibana Instance:</strong> $KibanaUrl</p>
            <p><strong>Report Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Filter Applied:</strong> $(if ($OnlyEnabledRules) { "Enabled rules only" } else { "All rules (enabled and disabled)" })</p>
        </div>
        
        <div class="summary">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($allRules.Count)</div>
                    <div class="summary-label">Total Rules</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$enabledCount</div>
                    <div class="summary-label">Enabled</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$disabledCount</div>
                    <div class="summary-label">Disabled</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($ruleTypes.Count)</div>
                    <div class="summary-label">Rule Types</div>
                </div>
            </div>
        </div>

        <h2>Rule Type Distribution</h2>
        <table class="stats-table">
            <tr>
                <th>Rule Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            $(foreach ($type in $ruleTypes) {
                $percentage = [Math]::Round(($type.Count / $allRules.Count) * 100, 1)
                "<tr><td>$($type.Name)</td><td>$($type.Count)</td><td>$percentage%</td></tr>"
            })
        </table>

        <h2>Severity Distribution</h2>
        <table class="stats-table">
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            $(foreach ($severity in $severities) {
                $percentage = [Math]::Round(($severity.Count / $allRules.Count) * 100, 1)
                "<tr><td><span class=`"severity-$($severity.Name.ToLower())`">$($severity.Name.ToUpper())</span></td><td>$($severity.Count)</td><td>$percentage%</td></tr>"
            })
        </table>

        <h2>All Rules</h2>
        <div class="filter-box">
            <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search rules by name, type, severity, MITRE, etc...">
        </div>
        <table id="rulesTable">
            <tr>
                <th>Rule Name</th>
                <th>Status</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Description</th>
                <th>MITRE Tactics</th>
                <th>Updated</th>
            </tr>
            $(foreach ($rule in ($formattedRules | Sort-Object -Property @{Expression={$_.Enabled}; Descending=$true}, Severity, RuleName)) {
                $statusBadge = if ($rule.Enabled) { '<span class="enabled-badge">ENABLED</span>' } else { '<span class="disabled-badge">DISABLED</span>' }
                $escapedDesc = [System.Security.SecurityElement]::Escape($rule.Description)
                @"
                <tr>
                    <td><strong>$($rule.RuleName)</strong></td>
                    <td>$statusBadge</td>
                    <td>$($rule.RuleType)</td>
                    <td><span class="severity-$($rule.Severity.ToLower())">$($rule.Severity.ToUpper())</span></td>
                    <td>$($rule.RiskScore)</td>
                    <td class="rule-description" title="$escapedDesc">$escapedDesc</td>
                    <td style="font-size: 0.85em;">$($rule.MitreTactics)</td>
                    <td style="font-size: 0.85em;">$($rule.UpdatedAt)</td>
                </tr>
"@
            })
        </table>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 0.9em; color: #6b7280;">
            <p><strong>Script:</strong> Get-KibanaSecurityRules.ps1</p>
            <p><strong>API Endpoint:</strong> /api/detection_engine/rules/_find</p>
            <p><strong>Total rules retrieved:</strong> $($allRules.Count)</p>
        </div>
    </div>
</body>
</html>
"@

$htmlFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "Documents\KibanaSecurityRules$filterSuffix`_$timestamp.html"
$htmlReport | Out-File -FilePath $htmlFilePath -Encoding UTF8

Write-Host "HTML Report: $htmlFilePath" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TOP 10 RULES BY RISK SCORE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
$topRules = $formattedRules | Sort-Object -Property RiskScore -Descending | Select-Object -First 10
foreach ($rule in $topRules) {
    $statusIcon = if ($rule.Enabled) { "[ON]" } else { "[OFF]" }
    Write-Host "$statusIcon $($rule.RuleName) - Risk: $($rule.RiskScore) - Severity: $($rule.Severity)" -ForegroundColor White
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "OPENING REPORT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
try {
    Start-Process $htmlFilePath
    Write-Host "HTML report opened in default browser" -ForegroundColor Green
} catch {
    Write-Host "Could not automatically open report. File saved to: $htmlFilePath" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "EXPORT COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "All files exported successfully to your Documents folder!" -ForegroundColor Green
Write-Host ""
