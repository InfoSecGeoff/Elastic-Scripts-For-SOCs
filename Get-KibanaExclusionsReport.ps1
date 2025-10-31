<#
.SYNOPSIS
    Generates a comprehensive HTML report of Kibana detection rule exclusions.

.DESCRIPTION
    This script connects to a Kibana instance via API and analyzes all detection rules
    to identify exception lists and exclusions added within a specified time range.
    
    The script can generate either:
    - Global reports showing all rule exclusions across all clients
    - Client-specific reports filtered by customer name
    
    Output includes:
    - Executive summary with key statistics
    - Daily trend visualization
    - Top rules with most exclusions
    - Top people adding exclusions
    - Detailed exclusion listings with full context
    
    Both HTML and JSON formats are generated for further analysis.

.PARAMETER KibanaUrl
    The base URL of your Kibana instance (e.g., "https://kibana.example.com").
    This parameter is mandatory.

.PARAMETER ApiKey
    The API key for authenticating to Kibana. Must have permissions to read detection
    rules and exception lists. This parameter is mandatory.
    
    To create an API key in Kibana:
    1. Navigate to Stack Management > API Keys
    2. Create a new API key with appropriate privileges
    3. Copy the encoded key value

.PARAMETER TimeRange
    Specifies the time range for filtering exclusions by creation date.
    Uses Kibana's time range syntax (e.g., "now-30d/d" for last 30 days).
    
    Common examples:
    - "now-7d/d"  : Last 7 days
    - "now-30d/d" : Last 30 days (default)
    - "now-90d/d" : Last 90 days
    - "now-1y/d"  : Last year
    
    Default: "now-30d/d"

.PARAMETER GlobalReport
    Switch parameter. When specified, generates a global report including exclusions
    from all detection rules regardless of client association.
    
    Use this for organization-wide visibility into all rule modifications.

.PARAMETER ClientFilter
    Filters the report to show only exclusions related to a specific client or customer.
    The filter searches across multiple fields including:
    - Rule names
    - Rule descriptions
    - Exception names and descriptions
    - Exception entry values
    
    This parameter is ignored when -GlobalReport is specified.
    
    Example: -ClientFilter "Kentucky Society of CPA"

.EXAMPLE
    .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://kibana.example.com" -ApiKey "your-api-key-here" -GlobalReport
    
    Generates a global report showing all rule exclusions added in the last 30 days.

.EXAMPLE
    .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://kibana.example.com" -ApiKey "your-api-key-here" -ClientFilter "Acme Corp"
    
    Generates a client-specific report for "Acme Corp" showing exclusions from the last 30 days.

.EXAMPLE
    .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://kibana.example.com" -ApiKey "your-api-key-here" -TimeRange "now-7d/d" -GlobalReport
    
    Generates a global report showing exclusions added in the last 7 days.

.EXAMPLE
    .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://kibana.example.com" -ApiKey "your-api-key-here" -ClientFilter "Customer XYZ" -TimeRange "now-90d/d"
    
    Generates a client-specific report for "Customer XYZ" covering the last 90 days.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.String
    Generates two types of output files in the script directory:
    
    1. Standardized filenames (for automation):
       - KibanaExclusionsReport.html
       - KibanaExclusionsReport.json
    
    2. Timestamped backups:
       - KibanaExclusionsReport_[Client]_[TimeRange]_[Date].html
       - KibanaExclusionsReport_[Client]_[TimeRange]_[Date].json

.NOTES
    File Name      : Get-KibanaExclusionsReport.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or later
    
    API Permissions Required:
    - Read access to detection_engine rules
    - Read access to exception_lists
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the base URL of your Kibana instance")]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory = $true, HelpMessage = "Enter your Kibana API key")]
    [string]$ApiKey,
    
    [Parameter(Mandatory = $false, HelpMessage = "Time range in Kibana format (e.g., 'now-30d/d')")]
    [string]$TimeRange = "now-30d/d",
    
    [Parameter(Mandatory = $false, HelpMessage = "Generate a global report for all clients")]
    [switch]$GlobalReport,
    
    [Parameter(Mandatory = $false, HelpMessage = "Filter report by client/customer name")]
    [string]$ClientFilter = ""
)

#region Configuration
$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

$verboseLogging = $true

if ($GlobalReport) {
    $clientFilter = ""
    Write-Host "Running GLOBAL exclusions report for all clients" -ForegroundColor Green
} else {
    if ([string]::IsNullOrWhiteSpace($ClientFilter)) {
        Write-Warning "No ClientFilter specified and GlobalReport switch not used. Defaulting to global report."
        $clientFilter = ""
    } else {
        $clientFilter = $ClientFilter
        Write-Host "Running CLIENT-SPECIFIC exclusions report for: $clientFilter" -ForegroundColor Yellow
    }
}
#endregion

#region Helper Functions
function Invoke-KibanaApi {
    param (
        [string]$Endpoint,
        [string]$Method = "GET",
        [string]$Body
    )
    
    $fullUrl = "$KibanaUrl$Endpoint"
    
    if ($verboseLogging) {
        Write-Host "Calling $Method $fullUrl" -ForegroundColor Gray
    }
    
    try {
        $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -Body $Body -ContentType "application/json"
        return $response
    }
    catch {
        Write-Host "Error calling $fullUrl : $_" -ForegroundColor Red
        return $null
    }
}

function Get-TimeRangeDescription {
    param ([string]$TimeRange)
    
    if ($TimeRange -match "now-(\d+)([dwmy])/[dwmy]") {
        $number = $matches[1]
        $unit = $matches[2]
        $unitName = switch ($unit) {
            "d" { if ([int]$number -eq 1) { "Day" } else { "Days" } }
            "w" { if ([int]$number -eq 1) { "Week" } else { "Weeks" } }
            "m" { if ([int]$number -eq 1) { "Month" } else { "Months" } }
            "y" { if ([int]$number -eq 1) { "Year" } else { "Years" } }
        }
        return "Last $number $unitName"
    }
    return "Last 30 Days"
}

function Get-RuleExclusions {
    param (
        [string]$TimeRange = "now-30d/d",
        [string]$ClientFilter = $null
    )
    
    Write-Host "Fetching all detection rules..." -ForegroundColor Yellow
    
    $rulesResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/rules/_find?per_page=10000" -Method "GET"
    
    if (-not $rulesResponse -or -not $rulesResponse.data) {
        Write-Host "No rules found or error fetching rules" -ForegroundColor Red
        return @()
    }
    
    Write-Host "Found $($rulesResponse.data.Count) total rules, analyzing exceptions..." -ForegroundColor Green
    
    $exclusionsFound = @()
    $rulesWithExceptions = 0
    $totalExceptionLists = 0
    
    $timeRangeDate = Get-Date
    if ($TimeRange -match "now-(\d+)([dwmy])") {
        $number = [int]$matches[1]
        $unit = $matches[2]
        
        switch ($unit) {
            "d" { $timeRangeDate = $timeRangeDate.AddDays(-$number) }
            "w" { $timeRangeDate = $timeRangeDate.AddDays(-($number * 7)) }
            "m" { $timeRangeDate = $timeRangeDate.AddMonths(-$number) }
            "y" { $timeRangeDate = $timeRangeDate.AddYears(-$number) }
        }
    }
    
    Write-Host "Looking for rules with exceptions_list field..." -ForegroundColor Cyan
    
    foreach ($rule in $rulesResponse.data) {
        if ($rule.exceptions_list -and $rule.exceptions_list.Count -gt 0) {
            $rulesWithExceptions++
            Write-Host "Rule '$($rule.name)' has $($rule.exceptions_list.Count) exception list(s)" -ForegroundColor Gray
            
            foreach ($exceptionListRef in $rule.exceptions_list) {
                $totalExceptionLists++
                
                Write-Host "Fetching exception list items for list_id: $($exceptionListRef.list_id)" -ForegroundColor Yellow
                
                $exceptionItemsResponse = Invoke-KibanaApi -Endpoint "/api/exception_lists/items/_find?list_id=$($exceptionListRef.list_id)&per_page=1000" -Method "GET"
                
                if ($exceptionItemsResponse -and $exceptionItemsResponse.data) {
                    Write-Host "Found $($exceptionItemsResponse.data.Count) exception items in list '$($exceptionListRef.list_id)'" -ForegroundColor Green
                    
                    foreach ($item in $exceptionItemsResponse.data) {
                        $createdDate = $null
                        if ($item.created_at) {
                            try {
                                $createdDate = [DateTime]::Parse($item.created_at)
                            }
                            catch {
                                Write-Host "Could not parse date: $($item.created_at)" -ForegroundColor Red
                                continue
                            }
                        }
                        
                        if ($createdDate -and $createdDate -lt $timeRangeDate) {
                            continue
                        }
                        
                        if ($ClientFilter) {
                            $matchesClient = $false
                            
                            if ($rule.name -like "*$ClientFilter*" -or 
                                $rule.description -like "*$ClientFilter*" -or
                                $item.description -like "*$ClientFilter*" -or
                                $item.name -like "*$ClientFilter*") {
                                $matchesClient = $true
                            }
                            
                            if ($item.entries) {
                                foreach ($entry in $item.entries) {
                                    if ($entry.value -like "*$ClientFilter*") {
                                        $matchesClient = $true
                                        break
                                    }
                                }
                            }
                            
                            if (-not $matchesClient) {
                                continue
                            }
                        }
                        
                        $exclusionDetails = @()
                        if ($item.entries) {
                            foreach ($entry in $item.entries) {
                                $value = if ($entry.value -is [array]) { $entry.value -join ", " } else { $entry.value }
                                $exclusionDetails += "$($entry.field) $($entry.operator) $value"
                            }
                        }
                        
                        $exclusionObject = [PSCustomObject]@{
                            RuleName = $rule.name
                            RuleId = $rule.id
                            RuleType = $rule.type
                            ExceptionListId = $exceptionListRef.list_id
                            ExceptionListType = $exceptionListRef.type
                            ExceptionItemId = $item.id
                            ExceptionName = $item.name
                            ExceptionDescription = $item.description
                            ExceptionType = $item.type
                            CreatedAt = if ($createdDate) { $createdDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                            CreatedBy = $item.created_by
                            UpdatedAt = if ($item.updated_at) { ([DateTime]::Parse($item.updated_at)).ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                            UpdatedBy = $item.updated_by
                            ExclusionDetails = $exclusionDetails -join " AND "
                            Namespace = $item.namespace_type
                            Tags = if ($item.tags) { $item.tags -join ", " } else { "" }
                            RuleTags = if ($rule.tags) { $rule.tags -join ", " } else { "" }
                        }
                        
                        $exclusionsFound += $exclusionObject
                    }
                } else {
                    Write-Host "No exception items found for list '$($exceptionListRef.list_id)' or error fetching items" -ForegroundColor Red
                }
            }
        }
    }
    
    Write-Host "Found $totalExceptionLists total exception lists in $rulesWithExceptions rules" -ForegroundColor Green
    Write-Host "After filtering: $($exclusionsFound.Count) exception items match criteria" -ForegroundColor Cyan
    
    return $exclusionsFound
}

function Generate-ExclusionsChartScript {
    param (
        [array]$ExclusionsData,
        [string]$ChartId = "exclusionsTrendChart"
    )
    
    if (-not $ExclusionsData -or $ExclusionsData.Count -eq 0) {
        return ""
    }
    
    $dailyData = $ExclusionsData | 
        Where-Object { $_.CreatedAt -ne "Unknown" } |
        Group-Object { ([DateTime]::Parse($_.CreatedAt)).ToString("yyyy-MM-dd") } |
        ForEach-Object {
            [PSCustomObject]@{
                Date = $_.Name
                Count = $_.Count
            }
        } |
        Sort-Object Date
    
    if ($dailyData.Count -eq 0) {
        return ""
    }
    
    $labels = ($dailyData | ForEach-Object { "'$($_.Date)'" }) -join ","
    $data = ($dailyData | ForEach-Object { $_.Count }) -join ","
    
    return @"
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<script>
    const ctx = document.getElementById('$ChartId').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [$labels],
            datasets: [{
                label: 'Daily Exclusions Added',
                data: [$data],
                backgroundColor: 'rgba(239, 68, 68, 0.6)',
                borderColor: '#dc2626',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Daily Rule Exclusions Added'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Exclusions'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Date'
                    }
                }
            }
        }
    });
</script>
"@
}
#endregion

#region Main Report Collection
Write-Host "Generating Kibana Rule Exclusions Report..." -ForegroundColor Cyan
if ($clientFilter) {
    Write-Host "Filtering for customer: $clientFilter" -ForegroundColor Yellow
}

$timeRangeDescription = Get-TimeRangeDescription -TimeRange $TimeRange
Write-Host "Time range: $timeRangeDescription ($TimeRange)" -ForegroundColor Yellow

$exclusions = Get-RuleExclusions -TimeRange $TimeRange -ClientFilter $clientFilter

$stats = @{
    TotalExclusions = $exclusions.Count
    UniqueRules = ($exclusions | Group-Object RuleName).Count
    UniquePeople = ($exclusions | Where-Object { $_.CreatedBy } | Group-Object CreatedBy).Count
    ExclusionTypes = $exclusions | Group-Object ExceptionType | Select-Object Name, Count
    TopRules = $exclusions | Group-Object RuleName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        [PSCustomObject]@{
            RuleName = $_.Name
            ExclusionCount = $_.Count
        }
    }
    TopCreators = $exclusions | Where-Object { $_.CreatedBy } | Group-Object CreatedBy | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        [PSCustomObject]@{
            CreatedBy = $_.Name
            ExclusionCount = $_.Count
        }
    }
    RecentExclusions = $exclusions | Where-Object { $_.CreatedAt -ne "Unknown" } | Sort-Object { [DateTime]::Parse($_.CreatedAt) } -Descending | Select-Object -First 20
}
#endregion

#region Output Report
$reportDate = Get-Date -Format "yyyy-MM-dd"
$clientSuffix = if ($clientFilter) { "_$($clientFilter.Replace(' ', '_').Replace('&', 'and'))" } else { "" }
$reportTitle = if ($clientFilter) { 
    "Kibana Rule Exclusions Report - $clientFilter - $timeRangeDescription - $reportDate" 
} else { 
    "Kibana Rule Exclusions Report - All Rules - $timeRangeDescription - $reportDate" 
}

$chartScript = Generate-ExclusionsChartScript -ExclusionsData $exclusions

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>$reportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #1f2937; border-bottom: 3px solid #dc2626; padding-bottom: 10px; }
        h2 { color: #374151; margin-top: 30px; border-left: 4px solid #dc2626; padding-left: 15px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 0.9em; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        th { background-color: #fef2f2; font-weight: 600; color: #374151; }
        tr:hover { background-color: #fef2f2; }
        .summary { background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 15px; }
        .summary-item { text-align: center; }
        .summary-number { font-size: 2em; font-weight: bold; }
        .summary-label { font-size: 0.9em; opacity: 0.9; }
        .no-data { color: #6b7280; font-style: italic; text-align: center; padding: 20px; }
        .warning-badge { background-color: #fef3c7; color: #92400e; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; margin-bottom: 20px; }
        .filter-badge { background-color: #dbeafe; color: #1e40af; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; margin-bottom: 10px; }
        .chart-container { margin: 20px 0; padding: 20px; background-color: #f9fafb; border-radius: 8px; }
        .exclusion-details { max-width: 400px; word-wrap: break-word; font-size: 0.85em; }
        .rule-name { font-weight: 600; color: #1f2937; }
        .creator { color: #059669; font-weight: 500; }
        .date { color: #6b7280; font-size: 0.85em; }
        .exception-type { background-color: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>$reportTitle</h1>
"@

if ($clientFilter) {
    $htmlReport += "<div class=`"filter-badge`">🎯 Filtered for Customer: $clientFilter</div>`n"
}

$htmlReport += "<div class=`"warning-badge`">⚠️ This report shows rule exclusions that may reduce detection coverage</div>`n"

$summaryTitle = if ($clientFilter) { "Executive Summary - $timeRangeDescription - $clientFilter" } else { "Executive Summary - $timeRangeDescription - All Rules" }
$htmlReport += @"
        <div class="summary">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">$summaryTitle</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($stats.TotalExclusions)</div>
                    <div class="summary-label">Total Exclusions Added</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($stats.UniqueRules)</div>
                    <div class="summary-label">Rules Modified</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($stats.UniquePeople)</div>
                    <div class="summary-label">People Adding Exclusions</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($stats.ExclusionTypes.Count)</div>
                    <div class="summary-label">Exception Types</div>
                </div>
            </div>
        </div>

"@

$htmlReport += "<h2>Exception Types</h2>`n"
if ($stats.ExclusionTypes.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Exception Type</th><th>Count</th><th>Percentage</th></tr>`n"
    foreach ($type in $stats.ExclusionTypes) {
        $percentage = if ($stats.TotalExclusions -gt 0) { [Math]::Round(($type.Count / $stats.TotalExclusions) * 100, 1) } else { 0 }
        $htmlReport += "<tr><td><span class=`"exception-type`">$($type.Name)</span></td><td>$($type.Count)</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div class="no-data">No exception types found.</div>'
}

$htmlReport += "<h2>Rules with Most Exclusions Added</h2>`n"
if ($stats.TopRules.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>Rule Name</th><th>Exclusions Added</th></tr>`n"
    for ($i = 0; $i -lt $stats.TopRules.Count; $i++) {
        $rule = $stats.TopRules[$i]
        $htmlReport += "<tr><td>$($i + 1)</td><td class=`"rule-name`">$($rule.RuleName)</td><td>$($rule.ExclusionCount)</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div class="no-data">No rules with exclusions found.</div>'
}

$htmlReport += "<h2>Top People Adding Exclusions</h2>`n"
if ($stats.TopCreators.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>Created By</th><th>Exclusions Added</th></tr>`n"
    for ($i = 0; $i -lt $stats.TopCreators.Count; $i++) {
        $creator = $stats.TopCreators[$i]
        $htmlReport += "<tr><td>$($i + 1)</td><td class=`"creator`">$($creator.CreatedBy)</td><td>$($creator.ExclusionCount)</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div class="no-data">No creator information available.</div>'
}

if ($chartScript) {
    $htmlReport += "<h2>Daily Exclusions Trend</h2>`n"
    $htmlReport += '<div class="chart-container"><canvas id="exclusionsTrendChart"></canvas></div>`n'
}

$htmlReport += "<h2>Recent Exclusions Added (Last 20)</h2>`n"
if ($stats.RecentExclusions.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Date</th><th>Rule Name</th><th>Exception Name</th><th>Exception Details</th><th>Created By</th><th>Type</th></tr>`n"
    foreach ($exclusion in $stats.RecentExclusions) {
        $truncatedDetails = if ($exclusion.ExclusionDetails.Length -gt 100) { 
            $exclusion.ExclusionDetails.Substring(0, 100) + "..." 
        } else { 
            $exclusion.ExclusionDetails 
        }
        $htmlReport += "<tr>`n"
        $htmlReport += "<td class=`"date`">$($exclusion.CreatedAt)</td>`n"
        $htmlReport += "<td class=`"rule-name`">$($exclusion.RuleName)</td>`n"
        $htmlReport += "<td>$($exclusion.ExceptionName)</td>`n"
        $htmlReport += "<td class=`"exclusion-details`">$truncatedDetails</td>`n"
        $htmlReport += "<td class=`"creator`">$($exclusion.CreatedBy)</td>`n"
        $htmlReport += "<td><span class=`"exception-type`">$($exclusion.ExceptionType)</span></td>`n"
        $htmlReport += "</tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div class="no-data">No recent exclusions found.</div>'
}

$htmlReport += "<h2>All Exclusions Added ($($exclusions.Count) total)</h2>`n"
if ($exclusions.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Date</th><th>Rule Name</th><th>Exception Name</th><th>Description</th><th>Exclusion Details</th><th>Created By</th><th>Type</th></tr>`n"
    foreach ($exclusion in ($exclusions | Sort-Object { if ($_.CreatedAt -ne "Unknown") { [DateTime]::Parse($_.CreatedAt) } else { [DateTime]::MinValue } } -Descending)) {
        $truncatedDetails = if ($exclusion.ExclusionDetails.Length -gt 150) { 
            $exclusion.ExclusionDetails.Substring(0, 150) + "..." 
        } else { 
            $exclusion.ExclusionDetails 
        }
        $htmlReport += "<tr>`n"
        $htmlReport += "<td class=`"date`">$($exclusion.CreatedAt)</td>`n"
        $htmlReport += "<td class=`"rule-name`">$($exclusion.RuleName)</td>`n"
        $htmlReport += "<td>$($exclusion.ExceptionName)</td>`n"
        $htmlReport += "<td>$($exclusion.ExceptionDescription)</td>`n"
        $htmlReport += "<td class=`"exclusion-details`">$truncatedDetails</td>`n"
        $htmlReport += "<td class=`"creator`">$($exclusion.CreatedBy)</td>`n"
        $htmlReport += "<td><span class=`"exception-type`">$($exclusion.ExceptionType)</span></td>`n"
        $htmlReport += "</tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div class="no-data">No exclusions found for the specified criteria.</div>'
}

$customerFilterInfo = if ($clientFilter) { "<p>Customer filter: $clientFilter</p>" } else { "" }
$htmlReport += @"
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 0.9em; color: #6b7280;">
            <p>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p>Data source: $KibanaUrl</p>
            <p>Time range: $timeRangeDescription ($TimeRange)</p>
            $customerFilterInfo
            <p><strong>⚠️ SECURITY NOTE:</strong> Rule exclusions reduce detection coverage. Regular review is recommended.</p>
        </div>
    </div>
    
    $chartScript
</body>
</html>
"@

$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDirectory)) {
    $scriptDirectory = Get-Location
}

$reportFilePath = Join-Path -Path $scriptDirectory -ChildPath "KibanaExclusionsReport.html"
$jsonFilePath = Join-Path -Path $scriptDirectory -ChildPath "KibanaExclusionsReport.json"

$timestampedHtmlPath = Join-Path -Path $scriptDirectory -ChildPath "KibanaExclusionsReport$clientSuffix`_$($timeRangeDescription.Replace(' ', '_'))`_$reportDate.html"
$timestampedJsonPath = Join-Path -Path $scriptDirectory -ChildPath "KibanaExclusionsReport$clientSuffix`_$($timeRangeDescription.Replace(' ', '_'))`_$reportDate.json"

$htmlReport | Out-File -FilePath $reportFilePath -Encoding UTF8
$exclusions | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8

$htmlReport | Out-File -FilePath $timestampedHtmlPath -Encoding UTF8
$exclusions | ConvertTo-Json -Depth 10 | Out-File -FilePath $timestampedJsonPath -Encoding UTF8

Write-Host "Kibana Rule Exclusions Report generated successfully!" -ForegroundColor Green
if ($clientFilter) {
    Write-Host "Report filtered for customer: $clientFilter" -ForegroundColor Yellow
} else {
    Write-Host "Global exclusions report generated for all rules" -ForegroundColor Green
}
Write-Host "Time range: $timeRangeDescription" -ForegroundColor Yellow
Write-Host "Main HTML Report: $reportFilePath" -ForegroundColor Green
Write-Host "Main JSON Data: $jsonFilePath" -ForegroundColor Green
Write-Host "Timestamped HTML Backup: $timestampedHtmlPath" -ForegroundColor Yellow
Write-Host "Timestamped JSON Backup: $timestampedJsonPath" -ForegroundColor Yellow

Write-Host "`n=== EXCLUSIONS REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Time Range: $timeRangeDescription ($TimeRange)" -ForegroundColor White
if ($clientFilter) {
    Write-Host "Customer Filter: $clientFilter" -ForegroundColor Yellow
} else {
    Write-Host "Report Type: Global (All Rules)" -ForegroundColor Green
}
Write-Host "Total Exclusions Found: $($stats.TotalExclusions)" -ForegroundColor Red
Write-Host "Rules Modified: $($stats.UniqueRules)" -ForegroundColor Yellow
Write-Host "People Adding Exclusions: $($stats.UniquePeople)" -ForegroundColor White

if ($stats.TopRules.Count -gt 0) {
    Write-Host "`nTop 5 Rules with Most Exclusions:" -ForegroundColor Cyan
    for ($i = 0; $i -lt [Math]::Min(5, $stats.TopRules.Count); $i++) {
        $rule = $stats.TopRules[$i]
        Write-Host "  $($i + 1). $($rule.RuleName): $($rule.ExclusionCount) exclusions" -ForegroundColor White
    }
}

Write-Host "`n=== USAGE EXAMPLES ===" -ForegroundColor Cyan
Write-Host "View help:" -ForegroundColor Yellow
Write-Host '  Get-Help .\Get-KibanaExclusionsReport.ps1 -Full' -ForegroundColor White
Write-Host "`nGlobal exclusions report:" -ForegroundColor Yellow
Write-Host '  .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -GlobalReport' -ForegroundColor White
Write-Host "`nClient-specific exclusions report:" -ForegroundColor Yellow
Write-Host '  .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -ClientFilter "Kentucky Society of CPA"' -ForegroundColor White
Write-Host "`nCustom time range:" -ForegroundColor Yellow
Write-Host '  .\Get-KibanaExclusionsReport.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -TimeRange "now-7d/d" -GlobalReport' -ForegroundColor White

try {
    Start-Process $reportFilePath
} catch {
    Write-Host "Could not automatically open report. File saved to: $reportFilePath" -ForegroundColor Yellow
}
