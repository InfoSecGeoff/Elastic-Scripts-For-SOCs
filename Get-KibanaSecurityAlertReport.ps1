<#
.SYNOPSIS
Enhanced Kibana Security Detection Engine Report with Building Block Filtering

.DESCRIPTION
Generates comprehensive security detection reports with:
- Unique machines and users (instead of customers)
- Separate counts WITH and WITHOUT building block alerts
- Comparison metrics showing the impact of building blocks
- Client filtering support
- Dynamic time ranges

.PARAMETER KibanaUrl
The URL of your Kibana instance

.PARAMETER ApiKey
API key for authentication

.PARAMETER TimeRange
Time range in Elasticsearch date math format (default: now-30d/d)

.PARAMETER GlobalReport
Switch to generate a report for all clients

.PARAMETER ClientFilter
Filter for a specific client/customer name

.EXAMPLE
.\Get-KibanaSecurityAlertReport.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -GlobalReport

.EXAMPLE
.\Get-KibanaSecurityAlertReport.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory = $false)]
    [string]$TimeRange = "now-30d/d",
    
    [Parameter(Mandatory = $false)]
    [switch]$GlobalReport,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientFilter = ""
)

$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

$verboseLogging = $true

if ($GlobalReport) {
    $clientFilter = ""
    Write-Host "Running GLOBAL report for all clients" -ForegroundColor Green
} else {
    if ([string]::IsNullOrWhiteSpace($ClientFilter)) {
        Write-Warning "No ClientFilter specified and GlobalReport switch not used. Defaulting to global report."
        $clientFilter = ""
    } else {
        $clientFilter = $ClientFilter
        Write-Host "Running CLIENT-SPECIFIC report for: $clientFilter" -ForegroundColor Yellow
    }
}

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

function Build-CustomerFilter {
    param ([string]$CustomerName)
    
    if (-not $CustomerName) {
        return $null
    }
    
    Write-Host "Building customer filter for: $CustomerName" -ForegroundColor Cyan
    
    return @{
        "bool" = @{
            "should" = @(
                @{
                    "match_phrase" = @{
                        "ame.q360.customer_name" = $CustomerName
                    }
                },
                @{
                    "match_phrase" = @{
                        "ame.client" = $CustomerName
                    }
                },
                @{
                    "wildcard" = @{
                        "ame.q360.customer_name" = "*$CustomerName*"
                    }
                },
                @{
                    "wildcard" = @{
                        "ame.client" = "*$CustomerName*"
                    }
                }
            )
            "minimum_should_match" = 1
        }
    }
}

function Build-BaseQuery {
    param (
        [string]$TimeRange,
        [string]$CustomerFilter = $null,
        [bool]$ExcludeBuildingBlocks = $false
    )
    
    $mustClauses = @(
        @{
            "range" = @{
                "@timestamp" = @{
                    "gte" = $TimeRange
                }
            }
        }
    )
    
    if ($CustomerFilter) {
        $customerFilterClause = Build-CustomerFilter -CustomerName $CustomerFilter
        if ($customerFilterClause) {
            $mustClauses += $customerFilterClause
        }
    }
    
    $mustNotClauses = @()
    
    if ($ExcludeBuildingBlocks) {
        $mustNotClauses += @{
            "exists" = @{
                "field" = "kibana.alert.building_block_type"
            }
        }
    }
    
    $query = @{
        "bool" = @{
            "must" = $mustClauses
        }
    }
    
    if ($mustNotClauses.Count -gt 0) {
        $query.bool["must_not"] = $mustNotClauses
    }
    
    return $query
}

function Get-AlertCount {
    param (
        [string]$TimeRange = "now-30d/d",
        [string]$CustomerFilter = $null,
        [bool]$ExcludeBuildingBlocks = $false,
        [string]$CountLabel = "total"
    )
    
    Write-Host "Getting $CountLabel alert count..." -ForegroundColor Yellow
    
    $baseQuery = Build-BaseQuery -TimeRange $TimeRange -CustomerFilter $CustomerFilter -ExcludeBuildingBlocks $ExcludeBuildingBlocks
    
    $countQuery = @{
        "query" = $baseQuery
        "size" = 0
        "aggs" = @{
            "total_count" = @{
                "value_count" = @{
                    "field" = "@timestamp"
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    $countResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/signals/search" -Method "POST" -Body $countQuery
    
    if ($countResponse -and $countResponse.aggregations -and $countResponse.aggregations.total_count) {
        $totalCount = [int]$countResponse.aggregations.total_count.value
        Write-Host "$countLabel count: $($totalCount.ToString('N0'))" -ForegroundColor Green
        return $totalCount
    }
    
    Write-Host "Could not determine $CountLabel count" -ForegroundColor Red
    return 0
}

function Get-UniqueHostsAndUsers {
    param (
        [string]$TimeRange = "now-30d/d",
        [string]$CustomerFilter = $null,
        [bool]$ExcludeBuildingBlocks = $false
    )
    
    $label = if ($ExcludeBuildingBlocks) { "WITHOUT building blocks" } else { "WITH building blocks" }
    Write-Host "Getting unique hosts and users ($label)..." -ForegroundColor Yellow
    
    $baseQuery = Build-BaseQuery -TimeRange $TimeRange -CustomerFilter $CustomerFilter -ExcludeBuildingBlocks $ExcludeBuildingBlocks
    
    $uniqueQuery = @{
        "query" = $baseQuery
        "size" = 0
        "aggs" = @{
            "unique_hosts" = @{
                "cardinality" = @{
                    "field" = "host.name"
                }
            }
            "unique_users" = @{
                "cardinality" = @{
                    "field" = "user.name"
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    $response = Invoke-KibanaApi -Endpoint "/api/detection_engine/signals/search" -Method "POST" -Body $uniqueQuery
    
    if ($response -and $response.aggregations) {
        $uniqueHosts = [int]$response.aggregations.unique_hosts.value
        $uniqueUsers = [int]$response.aggregations.unique_users.value
        
        Write-Host "  Unique hosts: $($uniqueHosts.ToString('N0'))" -ForegroundColor Green
        Write-Host "  Unique users: $($uniqueUsers.ToString('N0'))" -ForegroundColor Green
        
        return @{
            UniqueHosts = $uniqueHosts
            UniqueUsers = $uniqueUsers
        }
    }
    
    Write-Host "Could not determine unique hosts and users" -ForegroundColor Red
    return @{
        UniqueHosts = 0
        UniqueUsers = 0
    }
}

function Get-ComprehensiveAggregations {
    param (
        [string]$TimeRange = "now-30d/d",
        [string]$CustomerFilter = $null,
        [bool]$ExcludeBuildingBlocks = $false
    )
    
    $label = if ($ExcludeBuildingBlocks) { "WITHOUT building blocks" } else { "WITH building blocks" }
    Write-Host "Fetching comprehensive alert aggregations ($label)..." -ForegroundColor Yellow
    
    $baseQuery = Build-BaseQuery -TimeRange $TimeRange -CustomerFilter $CustomerFilter -ExcludeBuildingBlocks $ExcludeBuildingBlocks
    
    $comprehensiveQuery = @{
        "query" = $baseQuery
        "size" = 0
        "aggs" = @{
            "alert_status" = @{
                "terms" = @{
                    "field" = "kibana.alert.workflow_status"
                    "size" = 10
                }
            }
            "alert_rules_by_name" = @{
                "terms" = @{
                    "field" = "kibana.alert.rule.name"
                    "size" = 25
                }
            }
            "alert_rules_by_keyword" = @{
                "terms" = @{
                    "field" = "kibana.alert.rule.name.keyword"
                    "size" = 25
                }
            }
            "alert_hosts" = @{
                "terms" = @{
                    "field" = "host.name"
                    "size" = 50
                }
            }
            "alert_users" = @{
                "terms" = @{
                    "field" = "user.name"
                    "size" = 50
                }
            }
            "source_ips" = @{
                "terms" = @{
                    "field" = "source.ip"
                    "size" = 50
                }
            }
            "destination_ips" = @{
                "terms" = @{
                    "field" = "destination.ip"
                    "size" = 50
                }
            }
            "alerts_by_day" = @{
                "date_histogram" = @{
                    "field" = "@timestamp"
                    "calendar_interval" = "1d"
                }
            }
            "mitre_techniques" = @{
                "terms" = @{
                    "field" = "kibana.alert.rule.threat.technique.id"
                    "size" = 20
                }
            }
            "mitre_tactics" = @{
                "terms" = @{
                    "field" = "kibana.alert.rule.threat.tactic.name"
                    "size" = 15
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    $aggregationResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/signals/search" -Method "POST" -Body $comprehensiveQuery
    
    return $aggregationResponse
}

function Get-HighSeverityCount {
    param (
        [string]$TimeRange = "now-30d/d",
        [string]$CustomerFilter = $null,
        [bool]$ExcludeBuildingBlocks = $false
    )
    
    $label = if ($ExcludeBuildingBlocks) { "WITHOUT building blocks" } else { "WITH building blocks" }
    Write-Host "Fetching high-severity alerts ($label)..." -ForegroundColor Yellow
    
    $severityFields = @("kibana.alert.rule.severity", "kibana.alert.severity", "signal.rule.severity")
    $highSeverityCount = 0

    foreach ($severityField in $severityFields) {
        $severityBaseQuery = Build-BaseQuery -TimeRange $TimeRange -CustomerFilter $CustomerFilter -ExcludeBuildingBlocks $ExcludeBuildingBlocks
        $severityBaseQuery.bool.must += @{
            "terms" = @{
                $severityField = @("high", "critical")
            }
        }
        
        $highSeverityQuery = @{
            "query" = $severityBaseQuery
            "size" = 0
            "aggs" = @{
                "severity_count" = @{
                    "value_count" = @{
                        "field" = "@timestamp"
                    }
                }
            }
        } | ConvertTo-Json -Depth 10

        $highSeverityResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/signals/search" -Method "POST" -Body $highSeverityQuery

        if ($highSeverityResponse -and $highSeverityResponse.aggregations.severity_count) {
            $severityCount = [int]$highSeverityResponse.aggregations.severity_count.value
            if ($severityCount -gt $highSeverityCount) {
                $highSeverityCount = $severityCount
                Write-Host "Found $($severityCount.ToString('N0')) high-severity alerts using field: $severityField" -ForegroundColor Green
                break
            }
        }
    }
    
    return $highSeverityCount
}

function Generate-ChartScript {
    param (
        [array]$DailyData,
        [array]$DailyDataNoBB,
        [string]$ChartId = "alertTrendChart"
    )
    
    if (-not $DailyData -or $DailyData.Count -eq 0) {
        return ""
    }
    
    $labels = ($DailyData | Sort-Object Date | ForEach-Object { "'$($_.Date)'" }) -join ","
    $dataWithBB = ($DailyData | Sort-Object Date | ForEach-Object { $_.AlertCount }) -join ","
    $dataNoBB = ($DailyDataNoBB | Sort-Object Date | ForEach-Object { $_.AlertCount }) -join ","
    
    return @"
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<script>
    const ctx = document.getElementById('$ChartId').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [$labels],
            datasets: [
                {
                    label: 'All Alerts (With Building Blocks)',
                    data: [$dataWithBB],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Alerts (Without Building Blocks)',
                    data: [$dataNoBB],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Daily Alert Trend Comparison'
                },
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Alert Count'
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

Write-Host "`n=== ENHANCED SECURITY DETECTION ENGINE REPORT ===" -ForegroundColor Cyan
Write-Host "Features: Unique Machines/Users + Building Block Filtering" -ForegroundColor Cyan

if ($clientFilter) {
    Write-Host "Filtering for customer: $clientFilter" -ForegroundColor Yellow
}

$timeRangeDescription = Get-TimeRangeDescription -TimeRange $TimeRange
Write-Host "Time range: $timeRangeDescription ($TimeRange)" -ForegroundColor Yellow

$report = [ordered]@{}

Write-Host "`n--- Detection Rules Summary ---" -ForegroundColor Cyan
$rulesResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/rules/_find?per_page=10000" -Method "GET"

if ($rulesResponse) {
    $report.TotalRules = $rulesResponse.total ?? 0
    
    $enabledCount = 0
    $disabledCount = 0
    $buildingBlockCount = 0
    
    if ($rulesResponse.data) {
        foreach ($rule in $rulesResponse.data) {
            if ($rule.enabled -eq $true) {
                $enabledCount++
            } else {
                $disabledCount++
            }
            
            if ($rule.building_block_type -eq "default") {
                $buildingBlockCount++
            }
        }
    }
    
    $report.EnabledRules = $enabledCount
    $report.DisabledRules = $disabledCount
    $report.BuildingBlockRules = $buildingBlockCount
    
    if ($rulesResponse.data) {
        $ruleTypes = $rulesResponse.data | Group-Object -Property type | Select-Object Name, Count
        $report.RuleTypeDistribution = $ruleTypes | ForEach-Object {
            [PSCustomObject]@{
                Type = $_.Name
                Count = $_.Count
            }
        }
    } else {
        $report.RuleTypeDistribution = @()
    }
} else {
    $report.TotalRules = 0
    $report.EnabledRules = 0
    $report.DisabledRules = 0
    $report.BuildingBlockRules = 0
    $report.RuleTypeDistribution = @()
}

Write-Host "Building Block Rules Detected: $buildingBlockCount" -ForegroundColor Magenta

Write-Host "`n--- Metrics WITH Building Blocks ---" -ForegroundColor Cyan
$report.TotalAlerts_WithBB = Get-AlertCount -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $false -CountLabel "total (with BB)"
$report.HighSeverityAlerts_WithBB = Get-HighSeverityCount -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $false
$uniqueStats_WithBB = Get-UniqueHostsAndUsers -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $false
$report.UniqueHosts_WithBB = $uniqueStats_WithBB.UniqueHosts
$report.UniqueUsers_WithBB = $uniqueStats_WithBB.UniqueUsers

Write-Host "`n--- Metrics WITHOUT Building Blocks ---" -ForegroundColor Cyan
$report.TotalAlerts_NoBB = Get-AlertCount -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $true -CountLabel "total (without BB)"
$report.HighSeverityAlerts_NoBB = Get-HighSeverityCount -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $true
$uniqueStats_NoBB = Get-UniqueHostsAndUsers -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $true
$report.UniqueHosts_NoBB = $uniqueStats_NoBB.UniqueHosts
$report.UniqueUsers_NoBB = $uniqueStats_NoBB.UniqueUsers

Write-Host "`n--- Calculating Impact of Building Blocks ---" -ForegroundColor Cyan
$report.BuildingBlockAlerts = $report.TotalAlerts_WithBB - $report.TotalAlerts_NoBB
$report.BuildingBlockSeverityAlerts = $report.HighSeverityAlerts_WithBB - $report.HighSeverityAlerts_NoBB
$report.BuildingBlockPercentage = if ($report.TotalAlerts_WithBB -gt 0) { 
    [Math]::Round(($report.BuildingBlockAlerts / $report.TotalAlerts_WithBB) * 100, 2) 
} else { 0 }

Write-Host "Building Block alerts: $($report.BuildingBlockAlerts.ToString('N0')) ($($report.BuildingBlockPercentage)%)" -ForegroundColor Magenta

Write-Host "`n--- Comprehensive Aggregations (WITH BB) ---" -ForegroundColor Cyan
$aggregationResponse_WithBB = Get-ComprehensiveAggregations -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $false

Write-Host "`n--- Comprehensive Aggregations (WITHOUT BB) ---" -ForegroundColor Cyan
$aggregationResponse_NoBB = Get-ComprehensiveAggregations -TimeRange $TimeRange -CustomerFilter $clientFilter -ExcludeBuildingBlocks $true

if ($aggregationResponse_WithBB -and $aggregationResponse_WithBB.aggregations) {
    $aggs = $aggregationResponse_WithBB.aggregations
    
    if ($aggs.alert_status.buckets) {
        $report.AlertsByStatus_WithBB = $aggs.alert_status.buckets | ForEach-Object {
            [PSCustomObject]@{
                Status = $_.key
                Count = $_.doc_count
                Percentage = if ($report.TotalAlerts_WithBB -gt 0) { [Math]::Round(($_.doc_count / $report.TotalAlerts_WithBB) * 100, 2) } else { 0 }
            }
        }
    } else {
        $report.AlertsByStatus_WithBB = @()
    }
    
    $rulesData = $null
    if ($aggs.alert_rules_by_keyword.buckets -and $aggs.alert_rules_by_keyword.buckets.Count -gt 0) {
        $rulesData = $aggs.alert_rules_by_keyword.buckets
    } elseif ($aggs.alert_rules_by_name.buckets -and $aggs.alert_rules_by_name.buckets.Count -gt 0) {
        $rulesData = $aggs.alert_rules_by_name.buckets
    }
    
    if ($rulesData) {
        $report.TopAlertRules_WithBB = $rulesData | ForEach-Object {
            [PSCustomObject]@{
                RuleName = $_.key
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.TopAlertRules_WithBB = @()
    }
    
    if ($aggs.alert_hosts.buckets) {
        $report.TopAffectedHosts_WithBB = $aggs.alert_hosts.buckets | 
            Where-Object { $_.key -ne $null -and $_.key -ne "" } |
            ForEach-Object {
                [PSCustomObject]@{
                    HostName = $_.key
                    AlertCount = $_.doc_count
                }
            }
    } else {
        $report.TopAffectedHosts_WithBB = @()
    }
    
    if ($aggs.alert_users.buckets) {
        $report.TopAffectedUsers_WithBB = $aggs.alert_users.buckets | 
            Where-Object { $_.key -ne $null -and $_.key -ne "" } |
            ForEach-Object {
                [PSCustomObject]@{
                    UserName = $_.key
                    AlertCount = $_.doc_count
                }
            }
    } else {
        $report.TopAffectedUsers_WithBB = @()
    }
    
    if ($aggs.alerts_by_day.buckets) {
        $report.DailyAlertTrend_WithBB = $aggs.alerts_by_day.buckets | ForEach-Object {
            [PSCustomObject]@{
                Date = (Get-Date $_.key_as_string).ToString("yyyy-MM-dd")
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.DailyAlertTrend_WithBB = @()
    }
    
    if ($aggs.mitre_techniques.buckets) {
        $report.TopMitreTechniques_WithBB = $aggs.mitre_techniques.buckets | ForEach-Object {
            [PSCustomObject]@{
                TechniqueID = $_.key
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.TopMitreTechniques_WithBB = @()
    }
    
    if ($aggs.mitre_tactics.buckets) {
        $report.TopMitreTactics_WithBB = $aggs.mitre_tactics.buckets | ForEach-Object {
            [PSCustomObject]@{
                TacticName = $_.key
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.TopMitreTactics_WithBB = @()
    }
}

if ($aggregationResponse_NoBB -and $aggregationResponse_NoBB.aggregations) {
    $aggs = $aggregationResponse_NoBB.aggregations
    
    if ($aggs.alert_status.buckets) {
        $report.AlertsByStatus_NoBB = $aggs.alert_status.buckets | ForEach-Object {
            [PSCustomObject]@{
                Status = $_.key
                Count = $_.doc_count
                Percentage = if ($report.TotalAlerts_NoBB -gt 0) { [Math]::Round(($_.doc_count / $report.TotalAlerts_NoBB) * 100, 2) } else { 0 }
            }
        }
    } else {
        $report.AlertsByStatus_NoBB = @()
    }
    
    $rulesData = $null
    if ($aggs.alert_rules_by_keyword.buckets -and $aggs.alert_rules_by_keyword.buckets.Count -gt 0) {
        $rulesData = $aggs.alert_rules_by_keyword.buckets
    } elseif ($aggs.alert_rules_by_name.buckets -and $aggs.alert_rules_by_name.buckets.Count -gt 0) {
        $rulesData = $aggs.alert_rules_by_name.buckets
    }
    
    if ($rulesData) {
        $report.TopAlertRules_NoBB = $rulesData | ForEach-Object {
            [PSCustomObject]@{
                RuleName = $_.key
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.TopAlertRules_NoBB = @()
    }
    
    if ($aggs.alert_hosts.buckets) {
        $report.TopAffectedHosts_NoBB = $aggs.alert_hosts.buckets | 
            Where-Object { $_.key -ne $null -and $_.key -ne "" } |
            ForEach-Object {
                [PSCustomObject]@{
                    HostName = $_.key
                    AlertCount = $_.doc_count
                }
            }
    } else {
        $report.TopAffectedHosts_NoBB = @()
    }
    
    if ($aggs.alert_users.buckets) {
        $report.TopAffectedUsers_NoBB = $aggs.alert_users.buckets | 
            Where-Object { $_.key -ne $null -and $_.key -ne "" } |
            ForEach-Object {
                [PSCustomObject]@{
                    UserName = $_.key
                    AlertCount = $_.doc_count
                }
            }
    } else {
        $report.TopAffectedUsers_NoBB = @()
    }
    
    if ($aggs.alerts_by_day.buckets) {
        $report.DailyAlertTrend_NoBB = $aggs.alerts_by_day.buckets | ForEach-Object {
            [PSCustomObject]@{
                Date = (Get-Date $_.key_as_string).ToString("yyyy-MM-dd")
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.DailyAlertTrend_NoBB = @()
    }
    
    if ($aggs.mitre_techniques.buckets) {
        $report.TopMitreTechniques_NoBB = $aggs.mitre_techniques.buckets | ForEach-Object {
            [PSCustomObject]@{
                TechniqueID = $_.key
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.TopMitreTechniques_NoBB = @()
    }
    
    if ($aggs.mitre_tactics.buckets) {
        $report.TopMitreTactics_NoBB = $aggs.mitre_tactics.buckets | ForEach-Object {
            [PSCustomObject]@{
                TacticName = $_.key
                AlertCount = $_.doc_count
            }
        }
    } else {
        $report.TopMitreTactics_NoBB = @()
    }
}

$reportDate = Get-Date -Format "yyyy-MM-dd"
$clientSuffix = if ($clientFilter) { "_$($clientFilter.Replace(' ', '_').Replace('&', 'and'))" } else { "" }
$reportTitle = if ($clientFilter) { 
    "Enhanced Security Detection Report - $clientFilter - $timeRangeDescription - $reportDate" 
} else { 
    "Enhanced Security Detection Report - All Clients - $timeRangeDescription - $reportDate" 
}

$chartScript = Generate-ChartScript -DailyData $report.DailyAlertTrend_WithBB -DailyDataNoBB $report.DailyAlertTrend_NoBB

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>$reportTitle</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { color: #1f2937; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
        h2 { color: #374151; margin-top: 40px; border-left: 4px solid #3b82f6; padding-left: 15px; }
        h3 { color: #6b7280; margin-top: 25px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        th { background-color: #f9fafb; font-weight: 600; color: #374151; }
        tr:hover { background-color: #f9fafb; }
        .summary { background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .summary-item { text-align: center; padding: 15px; background: rgba(255,255,255,0.1); border-radius: 8px; }
        .summary-number { font-size: 2.2em; font-weight: bold; }
        .summary-label { font-size: 0.95em; opacity: 0.95; margin-top: 5px; }
        .comparison-box { background: #f0f9ff; border: 2px solid #3b82f6; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .comparison-title { font-size: 1.3em; font-weight: bold; color: #1e40af; margin-bottom: 15px; }
        .comparison-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
        .comparison-item { text-align: center; padding: 15px; background: white; border-radius: 6px; border: 1px solid #bfdbfe; }
        .comparison-value { font-size: 1.8em; font-weight: bold; color: #1e40af; }
        .comparison-label { font-size: 0.9em; color: #6b7280; margin-top: 5px; }
        .impact-badge { display: inline-block; padding: 6px 12px; border-radius: 4px; font-weight: 600; font-size: 0.9em; }
        .impact-high { background-color: #fee2e2; color: #991b1b; }
        .impact-medium { background-color: #fef3c7; color: #92400e; }
        .impact-low { background-color: #dcfce7; color: #166534; }
        .with-bb { color: #3b82f6; }
        .without-bb { color: #10b981; }
        .status-open { color: #dc2626; font-weight: bold; }
        .status-acknowledged { color: #f59e0b; font-weight: bold; }
        .status-closed { color: #16a34a; font-weight: bold; }
        .filter-badge { background-color: #dbeafe; color: #1e40af; padding: 8px 16px; border-radius: 4px; font-size: 0.95em; margin: 15px 0; display: inline-block; }
        .chart-container { margin: 30px 0; padding: 20px; background-color: #f9fafb; border-radius: 8px; }
        #alertTrendChart { max-height: 400px; }
        .tabs { display: flex; margin: 30px 0 20px 0; border-bottom: 2px solid #e5e7eb; }
        .tab { padding: 12px 24px; cursor: pointer; border: none; background: none; font-size: 1em; color: #6b7280; border-bottom: 3px solid transparent; transition: all 0.3s; }
        .tab:hover { color: #3b82f6; }
        .tab.active { color: #3b82f6; border-bottom: 3px solid #3b82f6; font-weight: 600; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .comparison-table { width: 100%; margin: 20px 0; }
        .comparison-table th { background-color: #eff6ff; }
        .diff-positive { color: #dc2626; font-weight: bold; }
        .diff-neutral { color: #6b7280; }
    </style>
    <script>
        function switchTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName + '-content').classList.add('active');
            
            // Add active class to selected tab
            event.target.classList.add('active');
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>$reportTitle</h1>
"@

if ($clientFilter) {
    $htmlReport += "<div class=`"filter-badge`">🎯 Filtered for Customer: $clientFilter</div>`n"
}

$summaryTitle = if ($clientFilter) { "Executive Summary - $timeRangeDescription - $clientFilter" } else { "Executive Summary - $timeRangeDescription - All Clients" }
$htmlReport += @"
        <div class="summary">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">$summaryTitle</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($report.TotalAlerts_NoBB.ToString('N0'))</div>
                    <div class="summary-label">Total Alerts<br/>(Without Building Blocks)</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($report.HighSeverityAlerts_NoBB.ToString('N0'))</div>
                    <div class="summary-label">High/Critical Severity<br/>(Without Building Blocks)</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($report.UniqueHosts_NoBB)</div>
                    <div class="summary-label">Unique Machines</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($report.UniqueUsers_NoBB)</div>
                    <div class="summary-label">Unique Users</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($report.EnabledRules)</div>
                    <div class="summary-label">Active Rules</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($report.BuildingBlockRules)</div>
                    <div class="summary-label">Building Block Rules</div>
                </div>
            </div>
        </div>

"@

$impactClass = if ($report.BuildingBlockPercentage -gt 50) { "impact-high" } elseif ($report.BuildingBlockPercentage -gt 25) { "impact-medium" } else { "impact-low" }
$htmlReport += @"
        <div class="comparison-box">
            <div class="comparison-title">🔍 Building Block Alert Impact Analysis</div>
            <div class="comparison-grid">
                <div class="comparison-item">
                    <div class="comparison-value with-bb">$($report.TotalAlerts_WithBB.ToString('N0'))</div>
                    <div class="comparison-label">Total Alerts<br/>WITH Building Blocks</div>
                </div>
                <div class="comparison-item">
                    <div class="comparison-value without-bb">$($report.TotalAlerts_NoBB.ToString('N0'))</div>
                    <div class="comparison-label">Total Alerts<br/>WITHOUT Building Blocks</div>
                </div>
                <div class="comparison-item">
                    <div class="comparison-value" style="color: #dc2626;">$($report.BuildingBlockAlerts.ToString('N0'))</div>
                    <div class="comparison-label">Building Block Alerts<br/><span class="impact-badge $impactClass">$($report.BuildingBlockPercentage)% of Total</span></div>
                </div>
            </div>
            <table class="comparison-table" style="margin-top: 25px;">
                <tr>
                    <th>Metric</th>
                    <th>With Building Blocks</th>
                    <th>Without Building Blocks</th>
                    <th>Difference</th>
                </tr>
                <tr>
                    <td><strong>Total Alerts</strong></td>
                    <td class="with-bb">$($report.TotalAlerts_WithBB.ToString('N0'))</td>
                    <td class="without-bb">$($report.TotalAlerts_NoBB.ToString('N0'))</td>
                    <td class="diff-positive">$($report.BuildingBlockAlerts.ToString('N0'))</td>
                </tr>
                <tr>
                    <td><strong>High/Critical Severity</strong></td>
                    <td class="with-bb">$($report.HighSeverityAlerts_WithBB.ToString('N0'))</td>
                    <td class="without-bb">$($report.HighSeverityAlerts_NoBB.ToString('N0'))</td>
                    <td class="diff-positive">$($report.BuildingBlockSeverityAlerts.ToString('N0'))</td>
                </tr>
                <tr>
                    <td><strong>Unique Hosts</strong></td>
                    <td class="with-bb">$($report.UniqueHosts_WithBB)</td>
                    <td class="without-bb">$($report.UniqueHosts_NoBB)</td>
                    <td class="diff-neutral">$($report.UniqueHosts_WithBB - $report.UniqueHosts_NoBB)</td>
                </tr>
                <tr>
                    <td><strong>Unique Users</strong></td>
                    <td class="with-bb">$($report.UniqueUsers_WithBB)</td>
                    <td class="without-bb">$($report.UniqueUsers_NoBB)</td>
                    <td class="diff-neutral">$($report.UniqueUsers_WithBB - $report.UniqueUsers_NoBB)</td>
                </tr>
            </table>
        </div>

"@

$htmlReport += @"
        <h2>Daily Alert Trend Comparison</h2>
        <div class="chart-container">
            <canvas id="alertTrendChart"></canvas>
        </div>

"@

$htmlReport += @"
        <div class="tabs">
            <button class="tab active" onclick="switchTab('without-bb')">📊 Without Building Blocks (Primary View)</button>
            <button class="tab" onclick="switchTab('with-bb')">📈 With Building Blocks (Full Data)</button>
        </div>

"@

$htmlReport += '<div id="without-bb-content" class="tab-content active">'

$htmlReport += "<h2>Alert Status Distribution (Without Building Blocks)</h2>`n"
if ($report.AlertsByStatus_NoBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Status</th><th>Count</th><th>Percentage</th></tr>`n"
    foreach ($status in $report.AlertsByStatus_NoBB) {
        $statusClass = switch ($status.Status) {
            "open" { "status-open" }
            "acknowledged" { "status-acknowledged" }
            "closed" { "status-closed" }
            default { "" }
        }
        $htmlReport += "<tr><td class=`"$statusClass`">$($status.Status)</td><td>$($status.Count.ToString('N0'))</td><td>$($status.Percentage)%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top 25 Alert Rules (Without Building Blocks)</h2>`n"
if ($report.TopAlertRules_NoBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>Rule Name</th><th>Alert Count</th><th>% of Total</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(25, $report.TopAlertRules_NoBB.Count); $i++) {
        $rule = $report.TopAlertRules_NoBB[$i]
        $percentage = if ($report.TotalAlerts_NoBB -gt 0) { [Math]::Round(($rule.AlertCount / $report.TotalAlerts_NoBB) * 100, 2) } else { 0 }
        $htmlReport += "<tr><td>$($i + 1)</td><td>$($rule.RuleName)</td><td>$($rule.AlertCount.ToString('N0'))</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top 25 Affected Machines (Without Building Blocks)</h2>`n"
if ($report.TopAffectedHosts_NoBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>Host Name</th><th>Alert Count</th><th>% of Total</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(25, $report.TopAffectedHosts_NoBB.Count); $i++) {
        $host = $report.TopAffectedHosts_NoBB[$i]
        $percentage = if ($report.TotalAlerts_NoBB -gt 0) { [Math]::Round(($host.AlertCount / $report.TotalAlerts_NoBB) * 100, 2) } else { 0 }
        $htmlReport += "<tr><td>$($i + 1)</td><td>$($host.HostName)</td><td>$($host.AlertCount.ToString('N0'))</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top 25 Affected Users (Without Building Blocks)</h2>`n"
if ($report.TopAffectedUsers_NoBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>User Name</th><th>Alert Count</th><th>% of Total</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(25, $report.TopAffectedUsers_NoBB.Count); $i++) {
        $user = $report.TopAffectedUsers_NoBB[$i]
        $percentage = if ($report.TotalAlerts_NoBB -gt 0) { [Math]::Round(($user.AlertCount / $report.TotalAlerts_NoBB) * 100, 2) } else { 0 }
        $htmlReport += "<tr><td>$($i + 1)</td><td>$($user.UserName)</td><td>$($user.AlertCount.ToString('N0'))</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top MITRE ATT&CK Techniques (Without Building Blocks)</h2>`n"
if ($report.TopMitreTechniques_NoBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Technique ID</th><th>Alert Count</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(10, $report.TopMitreTechniques_NoBB.Count); $i++) {
        $technique = $report.TopMitreTechniques_NoBB[$i]
        $htmlReport += "<tr><td>$($technique.TechniqueID)</td><td>$($technique.AlertCount.ToString('N0'))</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top MITRE ATT&CK Tactics (Without Building Blocks)</h2>`n"
if ($report.TopMitreTactics_NoBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Tactic Name</th><th>Alert Count</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(10, $report.TopMitreTactics_NoBB.Count); $i++) {
        $tactic = $report.TopMitreTactics_NoBB[$i]
        $htmlReport += "<tr><td>$($tactic.TacticName)</td><td>$($tactic.AlertCount.ToString('N0'))</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += '</div>'

$htmlReport += '<div id="with-bb-content" class="tab-content">'

$htmlReport += "<h2>Alert Status Distribution (With Building Blocks)</h2>`n"
if ($report.AlertsByStatus_WithBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Status</th><th>Count</th><th>Percentage</th></tr>`n"
    foreach ($status in $report.AlertsByStatus_WithBB) {
        $statusClass = switch ($status.Status) {
            "open" { "status-open" }
            "acknowledged" { "status-acknowledged" }
            "closed" { "status-closed" }
            default { "" }
        }
        $htmlReport += "<tr><td class=`"$statusClass`">$($status.Status)</td><td>$($status.Count.ToString('N0'))</td><td>$($status.Percentage)%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top 25 Alert Rules (With Building Blocks)</h2>`n"
if ($report.TopAlertRules_WithBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>Rule Name</th><th>Alert Count</th><th>% of Total</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(25, $report.TopAlertRules_WithBB.Count); $i++) {
        $rule = $report.TopAlertRules_WithBB[$i]
        $percentage = if ($report.TotalAlerts_WithBB -gt 0) { [Math]::Round(($rule.AlertCount / $report.TotalAlerts_WithBB) * 100, 2) } else { 0 }
        $htmlReport += "<tr><td>$($i + 1)</td><td>$($rule.RuleName)</td><td>$($rule.AlertCount.ToString('N0'))</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top 25 Affected Machines (With Building Blocks)</h2>`n"
if ($report.TopAffectedHosts_WithBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>Host Name</th><th>Alert Count</th><th>% of Total</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(25, $report.TopAffectedHosts_WithBB.Count); $i++) {
        $host = $report.TopAffectedHosts_WithBB[$i]
        $percentage = if ($report.TotalAlerts_WithBB -gt 0) { [Math]::Round(($host.AlertCount / $report.TotalAlerts_WithBB) * 100, 2) } else { 0 }
        $htmlReport += "<tr><td>$($i + 1)</td><td>$($host.HostName)</td><td>$($host.AlertCount.ToString('N0'))</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top 25 Affected Users (With Building Blocks)</h2>`n"
if ($report.TopAffectedUsers_WithBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Rank</th><th>User Name</th><th>Alert Count</th><th>% of Total</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(25, $report.TopAffectedUsers_WithBB.Count); $i++) {
        $user = $report.TopAffectedUsers_WithBB[$i]
        $percentage = if ($report.TotalAlerts_WithBB -gt 0) { [Math]::Round(($user.AlertCount / $report.TotalAlerts_WithBB) * 100, 2) } else { 0 }
        $htmlReport += "<tr><td>$($i + 1)</td><td>$($user.UserName)</td><td>$($user.AlertCount.ToString('N0'))</td><td>$percentage%</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top MITRE ATT&CK Techniques (With Building Blocks)</h2>`n"
if ($report.TopMitreTechniques_WithBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Technique ID</th><th>Alert Count</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(10, $report.TopMitreTechniques_WithBB.Count); $i++) {
        $technique = $report.TopMitreTechniques_WithBB[$i]
        $htmlReport += "<tr><td>$($technique.TechniqueID)</td><td>$($technique.AlertCount.ToString('N0'))</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += "<h2>Top MITRE ATT&CK Tactics (With Building Blocks)</h2>`n"
if ($report.TopMitreTactics_WithBB.Count -gt 0) {
    $htmlReport += "<table>`n<tr><th>Tactic Name</th><th>Alert Count</th></tr>`n"
    for ($i = 0; $i -lt [Math]::Min(10, $report.TopMitreTactics_WithBB.Count); $i++) {
        $tactic = $report.TopMitreTactics_WithBB[$i]
        $htmlReport += "<tr><td>$($tactic.TacticName)</td><td>$($tactic.AlertCount.ToString('N0'))</td></tr>`n"
    }
    $htmlReport += "</table>`n"
} else {
    $htmlReport += '<div style="color: #6b7280; font-style: italic; padding: 20px;">No data available</div>'
}

$htmlReport += '</div>'

$htmlReport += @"
        <h2>Detection Rules Summary</h2>
        <table>
            <tr><th>Metric</th><th>Count</th></tr>
            <tr><td>Total Rules</td><td>$($report.TotalRules)</td></tr>
            <tr><td>Enabled Rules</td><td>$($report.EnabledRules)</td></tr>
            <tr><td>Disabled Rules</td><td>$($report.DisabledRules)</td></tr>
            <tr><td style="color: #7c3aed; font-weight: bold;">Building Block Rules</td><td style="color: #7c3aed; font-weight: bold;">$($report.BuildingBlockRules)</td></tr>
        </table>

"@

if ($report.RuleTypeDistribution.Count -gt 0) {
    $htmlReport += "<h3>Rule Type Distribution</h3>`n<table>`n<tr><th>Rule Type</th><th>Count</th></tr>`n"
    foreach ($type in $report.RuleTypeDistribution) {
        $htmlReport += "<tr><td>$($type.Type)</td><td>$($type.Count)</td></tr>`n"
    }
    $htmlReport += "</table>`n"
}

$customerFilterInfo = if ($clientFilter) { "<p>Customer filter: <strong>$clientFilter</strong></p>" } else { "" }
$htmlReport += @"
        <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #6b7280;">
            <h3 style="color: #374151;">Report Information</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Data Source:</strong> $KibanaUrl</p>
            <p><strong>Time Range:</strong> $timeRangeDescription ($TimeRange)</p>
            $customerFilterInfo
            <h4 style="color: #1e40af; margin-top: 20px;">✨ Enhanced Features</h4>
            <ul>
                <li>✅ <strong>Unique Machine & User Tracking:</strong> Replaced customer counts with host.name and user.name cardinality</li>
                <li>✅ <strong>Building Block Filtering:</strong> Separate metrics WITH and WITHOUT building block alerts</li>
                <li>✅ <strong>Impact Analysis:</strong> Detailed comparison showing the effect of building block rules</li>
                <li>✅ <strong>Tabbed Interface:</strong> Easy switching between filtered and unfiltered views</li>
                <li>✅ <strong>Visual Comparison Chart:</strong> Dual-line chart showing alert trends with/without building blocks</li>
                <li>✅ <strong>Building Block Rule Count:</strong> Tracks how many rules are configured as building blocks</li>
            </ul>
            <p style="margin-top: 20px;"><strong>Building Block Note:</strong> <span class="impact-badge impact-medium">Building block alerts are hidden from the UI by default</span> and typically serve as input for correlation rules. This report helps you understand their impact on your overall alert volume.</p>
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

$reportFilePath = Join-Path -Path $scriptDirectory -ChildPath "EnhancedKibanaSecurityReport.html"
$jsonFilePath = Join-Path -Path $scriptDirectory -ChildPath "EnhancedKibanaSecurityReport.json"
$timestampedHtmlPath = Join-Path -Path $scriptDirectory -ChildPath "EnhancedSecurityReport$clientSuffix`_$($timeRangeDescription.Replace(' ', '_'))`_$reportDate.html"
$timestampedJsonPath = Join-Path -Path $scriptDirectory -ChildPath "EnhancedSecurityReport$clientSuffix`_$($timeRangeDescription.Replace(' ', '_'))`_$reportDate.json"

$htmlReport | Out-File -FilePath $reportFilePath -Encoding UTF8
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8
$htmlReport | Out-File -FilePath $timestampedHtmlPath -Encoding UTF8
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $timestampedJsonPath -Encoding UTF8

Write-Host "`n=== ENHANCED REPORT GENERATED SUCCESSFULLY ===" -ForegroundColor Green
Write-Host "Main HTML Report: $reportFilePath" -ForegroundColor Green
Write-Host "Main JSON Data: $jsonFilePath" -ForegroundColor Green
Write-Host "Timestamped HTML Backup: $timestampedHtmlPath" -ForegroundColor Yellow
Write-Host "Timestamped JSON Backup: $timestampedJsonPath" -ForegroundColor Yellow

Write-Host "`n=== COMPREHENSIVE SUMMARY ===" -ForegroundColor Cyan
Write-Host "Time Range: $timeRangeDescription ($TimeRange)" -ForegroundColor White
if ($clientFilter) {
    Write-Host "Customer Filter: $clientFilter" -ForegroundColor Yellow
} else {
    Write-Host "Report Type: Global (All Clients)" -ForegroundColor Green
}

Write-Host "`n--- WITH Building Blocks ---" -ForegroundColor Cyan
Write-Host "Total Alerts: $($report.TotalAlerts_WithBB.ToString('N0'))" -ForegroundColor White
Write-Host "High/Critical Severity: $($report.HighSeverityAlerts_WithBB.ToString('N0'))" -ForegroundColor Red
Write-Host "Unique Machines: $($report.UniqueHosts_WithBB)" -ForegroundColor White
Write-Host "Unique Users: $($report.UniqueUsers_WithBB)" -ForegroundColor White

Write-Host "`n--- WITHOUT Building Blocks ---" -ForegroundColor Cyan
Write-Host "Total Alerts: $($report.TotalAlerts_NoBB.ToString('N0'))" -ForegroundColor White
Write-Host "High/Critical Severity: $($report.HighSeverityAlerts_NoBB.ToString('N0'))" -ForegroundColor Red
Write-Host "Unique Machines: $($report.UniqueHosts_NoBB)" -ForegroundColor White
Write-Host "Unique Users: $($report.UniqueUsers_NoBB)" -ForegroundColor White

Write-Host "`n--- Building Block Impact ---" -ForegroundColor Magenta
Write-Host "Building Block Alerts: $($report.BuildingBlockAlerts.ToString('N0')) ($($report.BuildingBlockPercentage)% of total)" -ForegroundColor Magenta
Write-Host "Building Block Rules: $($report.BuildingBlockRules)" -ForegroundColor Magenta
Write-Host "BB High/Critical Alerts: $($report.BuildingBlockSeverityAlerts.ToString('N0'))" -ForegroundColor Magenta

Write-Host "`n--- Detection Rules ---" -ForegroundColor Cyan
Write-Host "Total Rules: $($report.TotalRules)" -ForegroundColor White
Write-Host "Enabled Rules: $($report.EnabledRules)" -ForegroundColor Green
Write-Host "Building Block Rules: $($report.BuildingBlockRules)" -ForegroundColor Magenta

try {
    Start-Process $reportFilePath
} catch {
    Write-Host "`nCould not automatically open report. File saved to: $reportFilePath" -ForegroundColor Yellow
}
