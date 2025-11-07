<#
.SYNOPSIS
Lists all enabled building block detection rules in Kibana

.DESCRIPTION
Retrieves and exports all detection rules that are configured as building block rules.
Building block rules create alerts that are hidden from the UI by default and are
typically used as a foundation for correlation rules.

.PARAMETER KibanaUrl
The URL of your Kibana instance

.PARAMETER ApiKey
Kibana API key for authentication

.PARAMETER IncludeDisabled
Include information on  disabled building block rules in addition to enabled ones

.PARAMETER ExportCsv
Switch to export results as CSV in addition to JSON

.PARAMETER OutputPath
Output path for the report files

.EXAMPLE
.\Get-KibanaBuildingBlockRules.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key"

.EXAMPLE
.\Get-KibanaBuildingBlockRules.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -IncludeDisabled -ExportCsv -OutputPath "C:\Reports"

.NOTES
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or later

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ""
)

$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

# Set output directory
$scriptDirectory = if ([string]::IsNullOrEmpty($OutputPath)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Get-Location
    } else {
        $PSScriptRoot
    }
} else {
    $OutputPath
}

# Validate output directory exists
if (-not (Test-Path -Path $scriptDirectory -PathType Container)) {
    Write-Host "Creating output directory: $scriptDirectory" -ForegroundColor Yellow
    New-Item -Path $scriptDirectory -ItemType Directory -Force | Out-Null
}

function Invoke-KibanaApi {
    param (
        [string]$Endpoint,
        [string]$Method = "GET",
        [string]$Body
    )
    
    $fullUrl = "$KibanaUrl$Endpoint"
    
    Write-Host "Calling $Method $fullUrl" -ForegroundColor Gray
    
    try {
        $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -Body $Body -ContentType "application/json"
        return $response
    }
    catch {
        Write-Host "Error calling $fullUrl : $_" -ForegroundColor Red
        return $null
    }
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   KIBANA BUILDING BLOCK RULES EXTRACTOR                  ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Kibana URL: $KibanaUrl" -ForegroundColor White
Write-Host "  Include Disabled Rules: $IncludeDisabled" -ForegroundColor White
Write-Host "  Output Directory: $scriptDirectory" -ForegroundColor White
Write-Host "  Export CSV: $ExportCsv" -ForegroundColor White

Write-Host "`n=== RETRIEVING DETECTION RULES ===" -ForegroundColor Cyan

# Find all rules
$allRules = @()
$page = 1
$perPage = 100

do {
    Write-Host "Fetching page $page..." -ForegroundColor Yellow
    $rulesResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/rules/_find?page=$page&per_page=$perPage"
    
    if (-not $rulesResponse -or -not $rulesResponse.data) {
        Write-Host "No rules found or error occurred" -ForegroundColor Red
        break
    }
    
    $allRules += $rulesResponse.data
    $totalRules = $rulesResponse.total
    $page++
    
    Write-Host "Retrieved $($allRules.Count) of $totalRules rules" -ForegroundColor Green
    
} while ($allRules.Count -lt $rulesResponse.total)

Write-Host "`nTotal rules retrieved: $($allRules.Count)" -ForegroundColor Green

# Identify building block rules
Write-Host "`n=== FILTERING FOR BUILDING BLOCK RULES ===" -ForegroundColor Cyan

$buildingBlockRules = $allRules | Where-Object { 
    $_.building_block_type -eq "default" 
}

Write-Host "Total building block rules: $($buildingBlockRules.Count)" -ForegroundColor Green

# Filter by enabled status if requested
if (-not $IncludeDisabled) {
    $buildingBlockRules = $buildingBlockRules | Where-Object { $_.enabled -eq $true }
    Write-Host "Enabled building block rules: $($buildingBlockRules.Count)" -ForegroundColor Green
} else {
    $enabledCount = ($buildingBlockRules | Where-Object { $_.enabled -eq $true }).Count
    $disabledCount = ($buildingBlockRules | Where-Object { $_.enabled -eq $false }).Count
    Write-Host "  Enabled: $enabledCount" -ForegroundColor Green
    Write-Host "  Disabled: $disabledCount" -ForegroundColor Yellow
}

if ($buildingBlockRules.Count -eq 0) {
    Write-Host "`nNo building block rules found!" -ForegroundColor Yellow
    Write-Host "This means no rules in your Kibana instance are configured with building_block_type = 'default'" -ForegroundColor Yellow
    exit 0
}

# Convert to structured format
Write-Host "`n=== PROCESSING RULES ===" -ForegroundColor Cyan

$structuredRules = @()

foreach ($rule in $buildingBlockRules) {
    $structuredRule = [PSCustomObject]@{
        RuleName = $rule.name
        RuleId = $rule.rule_id
        Id = $rule.id
        Enabled = $rule.enabled
        Type = $rule.type
        Severity = $rule.severity
        RiskScore = $rule.risk_score
        Author = if ($rule.author) { ($rule.author -join ", ") } else { "" }
        Description = $rule.description
        CreatedAt = $rule.created_at
        UpdatedAt = $rule.updated_at
        Version = $rule.version
        Interval = $rule.interval
        From = $rule.from
        MaxSignals = $rule.max_signals
        Tags = if ($rule.tags) { ($rule.tags -join ", ") } else { "" }
        MitreTactics = if ($rule.threat) { 
            ($rule.threat | ForEach-Object { $_.tactic.name } | Select-Object -Unique) -join ", " 
        } else { "" }
        MitreTechniques = if ($rule.threat) { 
            ($rule.threat | ForEach-Object { $_.technique.id } | Select-Object -Unique) -join ", " 
        } else { "" }
        References = if ($rule.references) { ($rule.references -join "; ") } else { "" }
        FalsePositives = if ($rule.false_positives) { ($rule.false_positives -join "; ") } else { "" }
        Index = if ($rule.index) { ($rule.index -join ", ") } else { "" }
    }
    
    $structuredRules += $structuredRule
}

# Export to JSON
$reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$jsonFileName = "BuildingBlockRules_$reportDate.json"
$jsonFilePath = Join-Path -Path $scriptDirectory -ChildPath $jsonFileName

Write-Host "`nExporting to JSON: $jsonFilePath" -ForegroundColor Cyan

$exportData = @{
    GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    KibanaUrl = $KibanaUrl
    IncludeDisabled = $IncludeDisabled.IsPresent
    TotalRules = $structuredRules.Count
    Rules = $structuredRules
}

$exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8
Write-Host "✓ JSON export complete" -ForegroundColor Green

# Export to CSV if requested
if ($ExportCsv) {
    $csvFileName = "BuildingBlockRules_$reportDate.csv"
    $csvFilePath = Join-Path -Path $scriptDirectory -ChildPath $csvFileName
    
    Write-Host "`nExporting to CSV: $csvFilePath" -ForegroundColor Cyan
    $structuredRules | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
    Write-Host "✓ CSV export complete" -ForegroundColor Green
}

# Summary statistics
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   SUMMARY STATISTICS                                      ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nTotal Building Block Rules: $($structuredRules.Count)" -ForegroundColor White

# Enabled count
$enabledRules = $structuredRules | Where-Object { $_.Enabled -eq $true }
$disabledRules = $structuredRules | Where-Object { $_.Enabled -eq $false }
Write-Host "`nBy Status:" -ForegroundColor Cyan
Write-Host "  Enabled: $($enabledRules.Count)" -ForegroundColor Green
Write-Host "  Disabled: $($disabledRules.Count)" -ForegroundColor Yellow

# Rule type count
$ruleTypes = $structuredRules | Group-Object -Property Type | Sort-Object Count -Descending
if ($ruleTypes) {
    Write-Host "`nBy Rule Type:" -ForegroundColor Cyan
    foreach ($type in $ruleTypes) {
        Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor White
    }
}

# Severity count
$severityCounts = $structuredRules | Group-Object -Property Severity | Sort-Object Name -Descending
if ($severityCounts) {
    Write-Host "`nBy Severity:" -ForegroundColor Cyan
    foreach ($severity in $severityCounts) {
        $color = switch ($severity.Name) {
            "critical" { "Red" }
            "high" { "Red" }
            "medium" { "Yellow" }
            "low" { "White" }
            default { "Gray" }
        }
        Write-Host "  $($severity.Name): $($severity.Count)" -ForegroundColor $color
    }
}

# Top authors
$topAuthors = $structuredRules | Where-Object { $_.Author } | Group-Object -Property Author | Sort-Object Count -Descending | Select-Object -First 5
if ($topAuthors) {
    Write-Host "`nTop 5 Authors:" -ForegroundColor Cyan
    $rank = 1
    foreach ($author in $topAuthors) {
        Write-Host "  $rank. $($author.Name): $($author.Count) rules" -ForegroundColor White
        $rank++
    }
}

# Top 10 most common tags
$allTags = $structuredRules | Where-Object { $_.Tags } | ForEach-Object { $_.Tags.Split(",").Trim() } | Where-Object { $_ }
$topTags = $allTags | Group-Object | Sort-Object Count -Descending | Select-Object -First 10
if ($topTags) {
    Write-Host "`nTop 10 Tags:" -ForegroundColor Cyan
    $rank = 1
    foreach ($tag in $topTags) {
        Write-Host "  $rank. $($tag.Name): $($tag.Count) rules" -ForegroundColor White
        $rank++
    }
}

# Sample of rule names
Write-Host "`nSample Rule Names (first 10):" -ForegroundColor Cyan
$structuredRules | Select-Object -First 10 | ForEach-Object {
    $statusIcon = if ($_.Enabled) { "✓" } else { "✗" }
    $statusColor = if ($_.Enabled) { "Green" } else { "Gray" }
    Write-Host "  [$statusIcon] " -ForegroundColor $statusColor -NoNewline
    Write-Host "$($_.RuleName)" -ForegroundColor White
}

if ($structuredRules.Count -gt 10) {
    Write-Host "`n  ... and $($structuredRules.Count - 10) more rules" -ForegroundColor Gray
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   EXPORT COMPLETE                                         ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nFiles Generated:" -ForegroundColor Cyan
Write-Host "  JSON: $jsonFilePath" -ForegroundColor White
if ($ExportCsv) {
    Write-Host "  CSV: $csvFilePath" -ForegroundColor White
}

Write-Host "`nBuilding block rules create alerts that are hidden from the Kibana UI by default." -ForegroundColor Yellow
Write-Host "These rules are typically used as building blocks for more complex correlation rules." -ForegroundColor Yellow

# Generate HTML Report
Write-Host "`n=== GENERATING HTML REPORT ===" -ForegroundColor Cyan

$htmlFileName = "BuildingBlockRules_$reportDate.html"
$htmlFilePath = Join-Path -Path $scriptDirectory -ChildPath $htmlFileName

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Building Block Rules Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background-color: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #1f2937; 
            border-bottom: 3px solid #7c3aed; 
            padding-bottom: 10px; 
        }
        h2 { 
            color: #374151; 
            margin-top: 40px; 
            border-left: 4px solid #7c3aed; 
            padding-left: 15px; 
        }
        h3 { 
            color: #6b7280; 
            margin-top: 25px; 
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px; 
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #e5e7eb; 
        }
        th { 
            background-color: #f3f4f6; 
            font-weight: 600; 
            color: #374151; 
            position: sticky;
            top: 0;
        }
        tr:hover { 
            background-color: #f9fafb; 
        }
        .summary { 
            background: linear-gradient(135deg, #7c3aed, #5b21b6); 
            color: white; 
            padding: 30px; 
            border-radius: 8px; 
            margin-bottom: 30px; 
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-top: 20px; 
        }
        .summary-item { 
            text-align: center; 
            padding: 15px; 
            background: rgba(255,255,255,0.1); 
            border-radius: 8px; 
        }
        .summary-number { 
            font-size: 2.2em; 
            font-weight: bold; 
        }
        .summary-label { 
            font-size: 0.95em; 
            opacity: 0.95; 
            margin-top: 5px; 
        }
        .status-enabled { 
            color: #16a34a; 
            font-weight: bold; 
        }
        .status-disabled { 
            color: #dc2626; 
            font-weight: bold; 
        }
        .severity-critical { 
            background-color: #fee2e2; 
            color: #991b1b; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .severity-high { 
            background-color: #fef3c7; 
            color: #92400e; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .severity-medium { 
            background-color: #dbeafe; 
            color: #1e40af; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .severity-low { 
            background-color: #f3f4f6; 
            color: #374151; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .badge { 
            display: inline-block; 
            padding: 4px 10px; 
            border-radius: 12px; 
            font-size: 0.85em; 
            font-weight: 600; 
            margin: 2px; 
        }
        .badge-enabled { 
            background-color: #dcfce7; 
            color: #166534; 
        }
        .badge-disabled { 
            background-color: #fee2e2; 
            color: #991b1b; 
        }
        .rule-description { 
            font-size: 0.9em; 
            color: #6b7280; 
            max-width: 600px; 
        }
        .tags { 
            font-size: 0.85em; 
            color: #7c3aed; 
        }
        .stats-box { 
            background: #f9fafb; 
            border: 1px solid #e5e7eb; 
            border-radius: 8px; 
            padding: 20px; 
            margin: 20px 0; 
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 15px; 
        }
        .stat-item { 
            padding: 15px; 
            background: white; 
            border-radius: 6px; 
            border-left: 4px solid #7c3aed; 
        }
        .stat-label { 
            font-size: 0.9em; 
            color: #6b7280; 
            margin-bottom: 5px; 
        }
        .stat-value { 
            font-size: 1.5em; 
            font-weight: bold; 
            color: #1f2937; 
        }
        .filter-input { 
            width: 100%; 
            padding: 10px; 
            margin: 10px 0; 
            border: 1px solid #d1d5db; 
            border-radius: 6px; 
            font-size: 1em; 
        }
        .filter-container { 
            margin: 20px 0; 
            padding: 15px; 
            background: #f9fafb; 
            border-radius: 8px; 
        }
        .chart-container { 
            margin: 30px 0; 
            padding: 20px; 
            background-color: #f9fafb; 
            border-radius: 8px; 
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script>
        function filterTable() {
            const input = document.getElementById('ruleFilter');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('rulesTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        const text = cell.textContent || cell.innerText;
                        if (text.toLowerCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                rows[i].style.display = found ? '' : 'none';
            }
        }
        
        function sortTable(columnIndex) {
            const table = document.getElementById('rulesTable');
            let rows = Array.from(table.rows).slice(1);
            const header = table.rows[0].cells[columnIndex];
            const isAscending = header.classList.contains('sort-asc');
            
            rows.sort((a, b) => {
                const aVal = a.cells[columnIndex].textContent.trim();
                const bVal = b.cells[columnIndex].textContent.trim();
                
                if (isAscending) {
                    return bVal.localeCompare(aVal);
                } else {
                    return aVal.localeCompare(bVal);
                }
            });
            
            // Update sort indicators
            Array.from(table.rows[0].cells).forEach(cell => {
                cell.classList.remove('sort-asc', 'sort-desc');
            });
            
            if (isAscending) {
                header.classList.add('sort-desc');
            } else {
                header.classList.add('sort-asc');
            }
            
            rows.forEach(row => table.appendChild(row));
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🔧 Building Block Rules Report</h1>
        
        <div class="summary">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($structuredRules.Count)</div>
                    <div class="summary-label">Total Building Block Rules</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($enabledRules.Count)</div>
                    <div class="summary-label">Enabled Rules</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($disabledRules.Count)</div>
                    <div class="summary-label">Disabled Rules</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($ruleTypes.Count)</div>
                    <div class="summary-label">Rule Types</div>
                </div>
            </div>
        </div>

        <div class="stats-box">
            <h3>Distribution Statistics</h3>
            <div class="stats-grid">
"@

# Add rule type statistics
if ($ruleTypes) {
    foreach ($type in $ruleTypes | Select-Object -First 4) {
        $htmlReport += @"
                <div class="stat-item">
                    <div class="stat-label">$($type.Name) Rules</div>
                    <div class="stat-value">$($type.Count)</div>
                </div>
"@
    }
}

$htmlReport += @"
            </div>
        </div>

        <h2>Severity Distribution</h2>
        <div class="chart-container">
            <canvas id="severityChart" style="max-height: 300px;"></canvas>
        </div>

        <h2>All Building Block Rules</h2>
        
        <div class="filter-container">
            <label for="ruleFilter"><strong>Filter Rules:</strong></label>
            <input type="text" id="ruleFilter" class="filter-input" onkeyup="filterTable()" placeholder="Search by rule name, type, severity, tags...">
        </div>

        <table id="rulesTable">
            <tr>
                <th onclick="sortTable(0)" style="cursor: pointer;">Status</th>
                <th onclick="sortTable(1)" style="cursor: pointer;">Rule Name</th>
                <th onclick="sortTable(2)" style="cursor: pointer;">Type</th>
                <th onclick="sortTable(3)" style="cursor: pointer;">Severity</th>
                <th onclick="sortTable(4)" style="cursor: pointer;">Risk Score</th>
                <th>MITRE Tactics</th>
                <th>Tags</th>
            </tr>
"@

foreach ($rule in $structuredRules) {
    $statusClass = if ($rule.Enabled) { "status-enabled" } else { "status-disabled" }
    $statusText = if ($rule.Enabled) { "✓ Enabled" } else { "✗ Disabled" }
    $severityClass = "severity-$($rule.Severity.ToLower())"
    
    $htmlReport += @"
            <tr>
                <td><span class="$statusClass">$statusText</span></td>
                <td><strong>$($rule.RuleName)</strong><br/><span class="rule-description">$($rule.Description)</span></td>
                <td>$($rule.Type)</td>
                <td><span class="$severityClass">$($rule.Severity.ToUpper())</span></td>
                <td>$($rule.RiskScore)</td>
                <td>$($rule.MitreTactics)</td>
                <td class="tags">$($rule.Tags)</td>
            </tr>
"@
}

$htmlReport += @"
        </table>

        <h2>Detailed Statistics</h2>
        
        <h3>Rules by Type</h3>
        <table>
            <tr>
                <th>Rule Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"@

foreach ($type in $ruleTypes) {
    $percentage = [Math]::Round(($type.Count / $structuredRules.Count) * 100, 1)
    $htmlReport += "<tr><td>$($type.Name)</td><td>$($type.Count)</td><td>$percentage%</td></tr>`n"
}

$htmlReport += @"
        </table>

        <h3>Rules by Severity</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"@

foreach ($severity in $severityCounts) {
    $percentage = [Math]::Round(($severity.Count / $structuredRules.Count) * 100, 1)
    $severityClass = "severity-$($severity.Name.ToLower())"
    $htmlReport += "<tr><td><span class=`"$severityClass`">$($severity.Name.ToUpper())</span></td><td>$($severity.Count)</td><td>$percentage%</td></tr>`n"
}

$htmlReport += @"
        </table>
"@

if ($topAuthors) {
    $htmlReport += @"
        <h3>Top Authors</h3>
        <table>
            <tr>
                <th>Rank</th>
                <th>Author</th>
                <th>Rule Count</th>
            </tr>
"@
    $rank = 1
    foreach ($author in $topAuthors) {
        $htmlReport += "<tr><td>$rank</td><td>$($author.Name)</td><td>$($author.Count)</td></tr>`n"
        $rank++
    }
    $htmlReport += "</table>`n"
}

if ($topTags) {
    $htmlReport += @"
        <h3>Most Common Tags</h3>
        <table>
            <tr>
                <th>Rank</th>
                <th>Tag</th>
                <th>Usage Count</th>
            </tr>
"@
    $rank = 1
    foreach ($tag in $topTags | Select-Object -First 15) {
        $htmlReport += "<tr><td>$rank</td><td>$($tag.Name)</td><td>$($tag.Count)</td></tr>`n"
        $rank++
    }
    $htmlReport += "</table>`n"
}

# Generate severity chart data
$criticalCount = ($structuredRules | Where-Object { $_.Severity -eq "critical" }).Count
$highCount = ($structuredRules | Where-Object { $_.Severity -eq "high" }).Count
$mediumCount = ($structuredRules | Where-Object { $_.Severity -eq "medium" }).Count
$lowCount = ($structuredRules | Where-Object { $_.Severity -eq "low" }).Count

$htmlReport += @"
        <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #6b7280;">
            <h3 style="color: #374151;">Report Information</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Kibana Instance:</strong> $KibanaUrl</p>
            <p><strong>Include Disabled Rules:</strong> $($IncludeDisabled.IsPresent)</p>
            <p><strong>Total Rules in System:</strong> $($allRules.Count)</p>
            <p><strong>Building Block Rules:</strong> $($structuredRules.Count) ($([Math]::Round(($structuredRules.Count / $allRules.Count) * 100, 1))% of all rules)</p>
            
            <h4 style="color: #7c3aed; margin-top: 20px;">About Building Block Rules</h4>
            <p>Building block rules are detection rules configured to generate alerts that are <strong>hidden from the UI by default</strong>. These rules serve as foundational components for:</p>
            <ul>
                <li><strong>Correlation Rules:</strong> Higher-level rules that query building block alerts to detect complex attack patterns</li>
                <li><strong>Low-Noise Detection:</strong> Recording suspicious activity without cluttering the alerts dashboard</li>
                <li><strong>Signal Chaining:</strong> Creating intermediate signals that feed into more sophisticated detection logic</li>
            </ul>
            <p>Building block alerts can be viewed in Kibana by selecting "Additional filters → Include building block alerts" in the Alerts table.</p>
        </div>
    </div>
    
    <script>
        // Severity distribution chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Number of Rules',
                    data: [$criticalCount, $highCount, $mediumCount, $lowCount],
                    backgroundColor: [
                        'rgba(220, 38, 38, 0.7)',
                        'rgba(251, 191, 36, 0.7)',
                        'rgba(59, 130, 246, 0.7)',
                        'rgba(156, 163, 175, 0.7)'
                    ],
                    borderColor: [
                        'rgb(220, 38, 38)',
                        'rgb(251, 191, 36)',
                        'rgb(59, 130, 246)',
                        'rgb(156, 163, 175)'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Rules by Severity Level'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

$htmlReport | Out-File -FilePath $htmlFilePath -Encoding UTF8

Write-Host "✓ HTML report generated: $htmlFilePath" -ForegroundColor Green

# Open HTML report in browser
try {
    Start-Process $htmlFilePath
    Write-Host "✓ Opening HTML report in default browser..." -ForegroundColor Green
} catch {
    Write-Host "Could not automatically open HTML report. File saved to: $htmlFilePath" -ForegroundColor Yellow
}

Write-Host "`nAll files saved to: $scriptDirectory" -ForegroundColor Cyan
