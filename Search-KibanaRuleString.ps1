<#
.SYNOPSIS
Search Kibana detection rules for a specific string across all rule parameters

.DESCRIPTION
Searches through all detection rules in Kibana and returns rules where the search string
appears in ANY field including queries, descriptions, names, filters, exception lists, etc.
This is useful for finding all rules that reference specific IOCs, techniques, or patterns.

.PARAMETER KibanaUrl
The URL of your Kibana instance

.PARAMETER ApiKey
Kibana API key for authentication

.PARAMETER SearchString
The string to search for across all rule parameters (case-insensitive)

.PARAMETER SearchScope
Optional: Limit search to specific fields. Options: All, Query, Name, Description, Filters, Exceptions
Default: All

.PARAMETER IncludeDisabled
Include disabled rules in the search results

.PARAMETER ExportJson
Switch to export results as JSON file (optional)

.PARAMETER ExportHtml
Switch to export results as HTML report (optional)

.PARAMETER ExportCsv
Switch to export results as CSV file (optional)

.PARAMETER OutputPath
Output path for the report files (only used if exporting)

.EXAMPLE
.\Search-KibanaRuleString.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -SearchString "ZipArchive"
Searches for "ZipArchive" and prints results to console only

.EXAMPLE
.\Search-KibanaRuleString.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -SearchString "T1560" -SearchScope Query
Searches only in query fields for "T1560" and prints to console

.EXAMPLE
.\Search-KibanaRuleString.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -SearchString "malicious" -IncludeDisabled -ExportCsv -ExportHtml
Searches including disabled rules and exports CSV and HTML reports

.EXAMPLE
.\Search-KibanaRuleString.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -SearchString "cmd.exe" -ExportJson -ExportHtml
Searches and exports both JSON and HTML reports

.EXAMPLE
.\Search-KibanaRuleString.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -SearchString "ZipArchive" -SearchScope Query -ExportJson -ExportCsv -ExportHtml
Full export with all formats

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
    
    [Parameter(Mandatory = $true)]
    [string]$SearchString,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Query", "Name", "Description", "Filters", "Exceptions", "Tags")]
    [string]$SearchScope = "All",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportJson,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportHtml,
    
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

function Search-RuleForString {
    param (
        [Parameter(Mandatory = $true)]
        $Rule,
        
        [Parameter(Mandatory = $true)]
        [string]$SearchTerm,
        
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )
    
    $matches = @()
    
    # Helper function to search within an object recursively
    function Search-Object {
        param($obj, $path = "")
        
        if ($null -eq $obj) { return }
        
        if ($obj -is [string]) {
            if ($obj -match [regex]::Escape($SearchTerm)) {
                return @{
                    Field = $path
                    Value = $obj
                    MatchType = "Exact"
                }
            }
        }
        elseif ($obj -is [array]) {
            for ($i = 0; $i -lt $obj.Count; $i++) {
                Search-Object -obj $obj[$i] -path "$path[$i]"
            }
        }
        elseif ($obj -is [hashtable] -or $obj.GetType().Name -eq 'PSCustomObject') {
            $properties = if ($obj -is [hashtable]) { $obj.Keys } else { $obj.PSObject.Properties.Name }
            foreach ($prop in $properties) {
                $value = if ($obj -is [hashtable]) { $obj[$prop] } else { $obj.$prop }
                $newPath = if ([string]::IsNullOrEmpty($path)) { $prop } else { "$path.$prop" }
                Search-Object -obj $value -path $newPath
            }
        }
    }
    
    # Define search fields based on scope
    $searchFields = switch ($Scope) {
        "Query" { @("query", "language", "filters", "kql", "eql", "threshold") }
        "Name" { @("name") }
        "Description" { @("description", "note") }
        "Filters" { @("filters", "query_filter") }
        "Exceptions" { @("exceptions_list", "exception_items") }
        "Tags" { @("tags") }
        "All" { @() } # Empty means search everything
    }
    
    # If searching all, convert entire rule to JSON and search
    if ($Scope -eq "All") {
        $ruleJson = $Rule | ConvertTo-Json -Depth 20
        if ($ruleJson -match [regex]::Escape($SearchTerm)) {
            # Now find specific fields that matched
            $foundMatches = Search-Object -obj $Rule -path "rule"
            if ($foundMatches) {
                return , @($foundMatches)
            }
        }
    }
    else {
        # Search specific fields
        foreach ($field in $searchFields) {
            if ($Rule.PSObject.Properties.Name -contains $field) {
                $foundMatches = Search-Object -obj $Rule.$field -path $field
                if ($foundMatches) {
                    $matches += $foundMatches
                }
            }
        }
    }
    
    return , $matches
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   KIBANA DETECTION RULES SEARCH                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nSearch Configuration:" -ForegroundColor Yellow
Write-Host "  Kibana URL: $KibanaUrl" -ForegroundColor White
Write-Host "  Search String: '$SearchString'" -ForegroundColor White
Write-Host "  Search Scope: $SearchScope" -ForegroundColor White
Write-Host "  Include Disabled Rules: $IncludeDisabled" -ForegroundColor White
if ($ExportJson -or $ExportHtml -or $ExportCsv) {
    Write-Host "  Export Formats: $((@() + $(if($ExportJson){'JSON'}) + $(if($ExportHtml){'HTML'}) + $(if($ExportCsv){'CSV'})) -join ', ')" -ForegroundColor White
    Write-Host "  Output Directory: $scriptDirectory" -ForegroundColor White
} else {
    Write-Host "  Export: None (console output only)" -ForegroundColor Gray
}

Write-Host "`n=== RETRIEVING ALL DETECTION RULES ===" -ForegroundColor Cyan

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

# Filter by enabled status if requested
if (-not $IncludeDisabled) {
    $allRules = $allRules | Where-Object { $_.enabled -eq $true }
    Write-Host "Filtered to enabled rules: $($allRules.Count)" -ForegroundColor Green
}

# Search through rules
Write-Host "`n=== SEARCHING FOR '$SearchString' ===" -ForegroundColor Cyan

$matchedRules = @()
$ruleCount = 0

foreach ($rule in $allRules) {
    $ruleCount++
    
    if ($ruleCount % 50 -eq 0) {
        Write-Host "Processed $ruleCount of $($allRules.Count) rules..." -ForegroundColor Gray
    }
    
    $matches = Search-RuleForString -Rule $rule -SearchTerm $SearchString -Scope $SearchScope
    
    if ($matches -and $matches.Count -gt 0) {
        $matchedRules += [PSCustomObject]@{
            Rule = $rule
            Matches = $matches
        }
    }
}

Write-Host "`nSearch complete!" -ForegroundColor Green
Write-Host "Found $($matchedRules.Count) rules containing '$SearchString'" -ForegroundColor Green

if ($matchedRules.Count -eq 0) {
    Write-Host "`nNo rules found matching search criteria." -ForegroundColor Yellow
    exit 0
}

# Always print rule names to console
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   MATCHED RULE NAMES                                      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$index = 1
foreach ($matchedRule in $matchedRules) {
    $rule = $matchedRule.Rule
    $statusIndicator = if ($rule.enabled) { "[✓]" } else { "[✗]" }
    $statusColor = if ($rule.enabled) { "Green" } else { "Red" }
    $buildingBlockIndicator = if ($rule.building_block_type -eq "default") { " [BBR]" } else { "" }
    
    Write-Host "$index. " -NoNewline -ForegroundColor Gray
    Write-Host "$statusIndicator " -NoNewline -ForegroundColor $statusColor
    Write-Host "$($rule.name)" -NoNewline -ForegroundColor White
    Write-Host "$buildingBlockIndicator" -ForegroundColor Magenta
    
    $index++
}
Write-Host ""

# Convert to structured format with match details
Write-Host "`n=== PROCESSING MATCHED RULES ===" -ForegroundColor Cyan

$structuredResults = @()

foreach ($matchedRule in $matchedRules) {
    $rule = $matchedRule.Rule
    $matches = $matchedRule.Matches
    
    # Get the actual query text based on rule type
    $queryText = ""
    switch ($rule.type) {
        "query" { $queryText = $rule.query }
        "eql" { $queryText = $rule.query }
        "threshold" { $queryText = $rule.query }
        "threat_match" { $queryText = $rule.query }
        "machine_learning" { $queryText = "ML Job: $($rule.machine_learning_job_id)" }
        "new_terms" { $queryText = $rule.query }
        default { $queryText = "N/A for $($rule.type) type" }
    }
    
    # Collect all matched fields
    $matchedFields = if ($matches -is [array]) {
        ($matches | ForEach-Object { $_.Field } | Select-Object -Unique) -join "; "
    } else {
        $matches.Field
    }
    
    $structuredResult = [PSCustomObject]@{
        RuleName = $rule.name
        RuleId = $rule.rule_id
        Id = $rule.id
        Enabled = $rule.enabled
        Type = $rule.type
        Severity = $rule.severity
        RiskScore = $rule.risk_score
        BuildingBlock = ($rule.building_block_type -eq "default")
        Author = if ($rule.author) { ($rule.author -join ", ") } else { "" }
        Description = $rule.description
        Query = $queryText
        Language = $rule.language
        MatchedFields = $matchedFields
        CreatedAt = $rule.created_at
        UpdatedAt = $rule.updated_at
        Version = $rule.version
        Tags = if ($rule.tags) { ($rule.tags -join ", ") } else { "" }
        MitreTactics = if ($rule.threat) { 
            ($rule.threat | ForEach-Object { $_.tactic.name } | Select-Object -Unique) -join ", " 
        } else { "" }
        MitreTechniques = if ($rule.threat) { 
            ($rule.threat | ForEach-Object { 
                if ($_.technique) {
                    $_.technique | ForEach-Object { $_.id }
                }
            } | Select-Object -Unique) -join ", " 
        } else { "" }
        Index = if ($rule.index) { ($rule.index -join ", ") } else { "" }
        ExceptionsList = if ($rule.exceptions_list) { 
            ($rule.exceptions_list | ForEach-Object { $_.list_id } | Select-Object -Unique) -join ", " 
        } else { "" }
    }
    
    $structuredResults += $structuredResult
}

# Export to JSON if requested
if ($ExportJson) {
    $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $safeSearchString = $SearchString -replace '[\\/:*?"<>|]', '_'
    $jsonFileName = "RuleSearch_${safeSearchString}_$reportDate.json"
    $jsonFilePath = Join-Path -Path $scriptDirectory -ChildPath $jsonFileName
    
    Write-Host "`nExporting to JSON: $jsonFilePath" -ForegroundColor Cyan
    
    $exportData = @{
        GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        KibanaUrl = $KibanaUrl
        SearchString = $SearchString
        SearchScope = $SearchScope
        IncludeDisabled = $IncludeDisabled.IsPresent
        TotalRulesSearched = $allRules.Count
        MatchedRulesCount = $structuredResults.Count
        Results = $structuredResults
    }
    
    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8
    Write-Host "✓ JSON export complete" -ForegroundColor Green
}

# Export to CSV if requested
if ($ExportCsv) {
    if (-not $reportDate) {
        $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $safeSearchString = $SearchString -replace '[\\/:*?"<>|]', '_'
    }
    $csvFileName = "RuleSearch_${safeSearchString}_$reportDate.csv"
    $csvFilePath = Join-Path -Path $scriptDirectory -ChildPath $csvFileName
    
    Write-Host "`nExporting to CSV: $csvFilePath" -ForegroundColor Cyan
    $structuredResults | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
    Write-Host "✓ CSV export complete" -ForegroundColor Green
}

# Generate HTML Report if requested
if ($ExportHtml) {
    if (-not $reportDate) {
        $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $safeSearchString = $SearchString -replace '[\\/:*?"<>|]', '_'
    }
    Write-Host "`n=== GENERATING HTML REPORT ===" -ForegroundColor Cyan

$htmlFileName = "RuleSearch_${safeSearchString}_$reportDate.html"
$htmlFilePath = Join-Path -Path $scriptDirectory -ChildPath $htmlFileName

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rule Search Results: $SearchString - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1600px; 
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
        .search-header {
            background: linear-gradient(135deg, #7c3aed, #5b21b6);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .search-term {
            font-size: 1.8em;
            font-weight: bold;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 6px;
            display: inline-block;
            margin: 10px 0;
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
        .rule-query {
            font-family: 'Courier New', monospace;
            background-color: #f9fafb;
            padding: 10px;
            border-left: 3px solid #7c3aed;
            margin: 10px 0;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 200px;
            overflow-y: auto;
        }
        .highlight {
            background-color: #fef08a;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: 600;
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
        .building-block-badge {
            background-color: #e0e7ff;
            color: #4338ca;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .matched-fields {
            font-size: 0.85em;
            color: #7c3aed;
            background-color: #f3e8ff;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            margin: 2px;
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
        .rule-description { 
            font-size: 0.9em; 
            color: #6b7280; 
            margin-top: 5px;
        }
        .tags { 
            font-size: 0.85em; 
            color: #6b7280;
        }
    </style>
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
        
        function highlightSearchTerm() {
            const searchTerm = "$SearchString";
            const tables = document.getElementsByClassName('rule-query');
            
            for (let table of tables) {
                const text = table.innerHTML;
                const regex = new RegExp('(' + searchTerm.replace(/[.*+?^`${}()|[\]\\]/g, '\\`$&') + ')', 'gi');
                table.innerHTML = text.replace(regex, '<span class="highlight">`$1</span>');
            }
        }
        
        window.onload = highlightSearchTerm;
    </script>
</head>
<body>
    <div class="container">
        <h1>🔍 Detection Rules Search Results</h1>
        
        <div class="search-header">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">Search Query</h2>
            <div class="search-term">$SearchString</div>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($structuredResults.Count)</div>
                    <div class="summary-label">Rules Matched</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($allRules.Count)</div>
                    <div class="summary-label">Total Rules Searched</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$SearchScope</div>
                    <div class="summary-label">Search Scope</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$([Math]::Round(($structuredResults.Count / $allRules.Count) * 100, 1))%</div>
                    <div class="summary-label">Match Rate</div>
                </div>
            </div>
        </div>

        <h2>Matched Rules</h2>
        
        <div class="filter-container">
            <label for="ruleFilter"><strong>Filter Results:</strong></label>
            <input type="text" id="ruleFilter" class="filter-input" onkeyup="filterTable()" placeholder="Filter by rule name, type, severity, MITRE tactics...">
        </div>

        <table id="rulesTable">
            <tr>
                <th>Status</th>
                <th>Rule Name</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Matched Fields</th>
                <th>MITRE Tactics</th>
            </tr>
"@

foreach ($result in $structuredResults) {
    $statusClass = if ($result.Enabled) { "status-enabled" } else { "status-disabled" }
    $statusText = if ($result.Enabled) { "✓ Enabled" } else { "✗ Disabled" }
    $severityClass = "severity-$($result.Severity.ToLower())"
    $buildingBlockBadge = if ($result.BuildingBlock) { "<span class='building-block-badge'>BBR</span>" } else { "" }
    
    $htmlReport += @"
            <tr>
                <td><span class="$statusClass">$statusText</span></td>
                <td>
                    <strong>$($result.RuleName)</strong> $buildingBlockBadge<br/>
                    <span class="rule-description">$($result.Description)</span>
                    <div class="rule-query">$([System.Web.HttpUtility]::HtmlEncode($result.Query))</div>
                </td>
                <td>$($result.Type)</td>
                <td><span class="$severityClass">$($result.Severity.ToUpper())</span></td>
                <td>$($result.RiskScore)</td>
                <td><span class="matched-fields">$($result.MatchedFields)</span></td>
                <td>$($result.MitreTactics)</td>
            </tr>
"@
}

# Add statistics section (using variables calculated earlier)
$htmlReport += @"
        </table>

        <h2>Statistics</h2>
        
        <h3>Rule Status Distribution</h3>
        <table>
            <tr>
                <th>Status</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            <tr>
                <td><span class="status-enabled">Enabled</span></td>
                <td>$enabledCount</td>
                <td>$([Math]::Round(($enabledCount / $structuredResults.Count) * 100, 1))%</td>
            </tr>
            <tr>
                <td><span class="status-disabled">Disabled</span></td>
                <td>$disabledCount</td>
                <td>$([Math]::Round(($disabledCount / $structuredResults.Count) * 100, 1))%</td>
            </tr>
            <tr>
                <td><span class="building-block-badge">Building Block Rules</span></td>
                <td>$buildingBlockCount</td>
                <td>$([Math]::Round(($buildingBlockCount / $structuredResults.Count) * 100, 1))%</td>
            </tr>
        </table>

        <h3>Rules by Type</h3>
        <table>
            <tr>
                <th>Rule Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"@

foreach ($type in $ruleTypes) {
    $percentage = [Math]::Round(($type.Count / $structuredResults.Count) * 100, 1)
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
    $percentage = [Math]::Round(($severity.Count / $structuredResults.Count) * 100, 1)
    $severityClass = "severity-$($severity.Name.ToLower())"
    $htmlReport += "<tr><td><span class=`"$severityClass`">$($severity.Name.ToUpper())</span></td><td>$($severity.Count)</td><td>$percentage%</td></tr>`n"
}

$htmlReport += @"
        </table>

        <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #6b7280;">
            <h3 style="color: #374151;">Search Information</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Kibana Instance:</strong> $KibanaUrl</p>
            <p><strong>Search String:</strong> <code style="background: #f3f4f6; padding: 2px 6px; border-radius: 4px;">$SearchString</code></p>
            <p><strong>Search Scope:</strong> $SearchScope</p>
            <p><strong>Include Disabled Rules:</strong> $($IncludeDisabled.IsPresent)</p>
            <p><strong>Total Rules Searched:</strong> $($allRules.Count)</p>
            <p><strong>Rules Matched:</strong> $($structuredResults.Count) ($([Math]::Round(($structuredResults.Count / $allRules.Count) * 100, 1))%)</p>
        </div>
    </div>
</body>
</html>
"@

$htmlReport | Out-File -FilePath $htmlFilePath -Encoding UTF8

Write-Host "✓ HTML report generated: $htmlFilePath" -ForegroundColor Green
}

# Calculate statistics for summary (always shown)
$enabledCount = ($structuredResults | Where-Object { $_.Enabled -eq $true }).Count
$disabledCount = ($structuredResults | Where-Object { $_.Enabled -eq $false }).Count
$buildingBlockCount = ($structuredResults | Where-Object { $_.BuildingBlock -eq $true }).Count
$ruleTypes = $structuredResults | Group-Object -Property Type | Sort-Object Count -Descending
$severityCounts = $structuredResults | Group-Object -Property Severity | Sort-Object Name -Descending

# Summary statistics (always shown)
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   SEARCH SUMMARY                                          ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nSearch String: '$SearchString'" -ForegroundColor Cyan
Write-Host "Search Scope: $SearchScope" -ForegroundColor Cyan
Write-Host "Total Rules Searched: $($allRules.Count)" -ForegroundColor White
Write-Host "Rules Matched: $($structuredResults.Count)" -ForegroundColor Green
Write-Host "Match Rate: $([Math]::Round(($structuredResults.Count / $allRules.Count) * 100, 1))%" -ForegroundColor Yellow

Write-Host "`nMatched Rules by Status:" -ForegroundColor Cyan
Write-Host "  Enabled: $enabledCount" -ForegroundColor Green
Write-Host "  Disabled: $disabledCount" -ForegroundColor Yellow
Write-Host "  Building Block: $buildingBlockCount" -ForegroundColor Magenta

if ($ruleTypes) {
    Write-Host "`nMatched Rules by Type:" -ForegroundColor Cyan
    foreach ($type in $ruleTypes | Select-Object -First 5) {
        Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor White
    }
}

if ($severityCounts) {
    Write-Host "`nMatched Rules by Severity:" -ForegroundColor Cyan
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

# Show export summary only if files were generated
if ($ExportJson -or $ExportCsv -or $ExportHtml) {
    Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║   EXPORT COMPLETE                                         ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`nFiles Generated:" -ForegroundColor Cyan
    if ($ExportJson) {
        Write-Host "  JSON: $jsonFilePath" -ForegroundColor White
    }
    if ($ExportCsv) {
        Write-Host "  CSV: $csvFilePath" -ForegroundColor White
    }
    if ($ExportHtml) {
        Write-Host "  HTML: $htmlFilePath" -ForegroundColor White
    }
    
    Write-Host "`nAll files saved to: $scriptDirectory" -ForegroundColor Cyan
} else {
    Write-Host "`n(No files exported - use -ExportJson, -ExportHtml, or -ExportCsv to save results)" -ForegroundColor Gray
}
